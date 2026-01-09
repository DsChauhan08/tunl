/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tunl TUI - Terminal User Interface
 *
 * ncurses-based dashboard for monitoring and control.
 * Like htop, but for your tunnels.
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <termios.h>

#ifdef HAVE_NCURSES
#include <ncurses.h>
#else
/* Fallback: simple ANSI terminal UI */
#define ANSI_CLEAR      "\033[2J\033[H"
#define ANSI_BOLD       "\033[1m"
#define ANSI_GREEN      "\033[32m"
#define ANSI_RED        "\033[31m"
#define ANSI_YELLOW     "\033[33m"
#define ANSI_CYAN       "\033[36m"
#define ANSI_RESET      "\033[0m"
#define ANSI_HIDE_CUR   "\033[?25l"
#define ANSI_SHOW_CUR   "\033[?25h"
#endif

#define TUI_REFRESH_MS  1000
#define TUI_MAX_SESSIONS 100

struct tui_state {
	int running;
	int selected;
	int scroll;
	int width;
	int height;
	time_t start_time;
	
	/* Cached stats */
	uint64_t bytes_in;
	uint64_t bytes_out;
	int active_sessions;
	int total_sessions;
	double cpu_pct;
	uint64_t mem_total;
	uint64_t mem_used;
};

static struct tui_state g_tui;
static volatile sig_atomic_t tui_resize = 0;

/* Minimal system metrics (btop-lite) */
struct cpu_sample {
	uint64_t user, nice, system, idle, iowait, irq, softirq, steal;
};

static int read_cpu_sample(struct cpu_sample *s)
{
	if (!s)
		return -1;
	FILE *f = fopen("/proc/stat", "r");
	if (!f)
		return -1;
	int n = fscanf(f, "cpu %lu %lu %lu %lu %lu %lu %lu %lu",
			&s->user, &s->nice, &s->system, &s->idle,
			&s->iowait, &s->irq, &s->softirq, &s->steal);
	fclose(f);
	return (n >= 4) ? 0 : -1;
}

static double cpu_usage_pct(struct cpu_sample *prev, struct cpu_sample *cur)
{
	uint64_t p_idle = prev->idle + prev->iowait;
	uint64_t c_idle = cur->idle + cur->iowait;
	uint64_t p_non = prev->user + prev->nice + prev->system + prev->irq + prev->softirq + prev->steal;
	uint64_t c_non = cur->user + cur->nice + cur->system + cur->irq + cur->softirq + cur->steal;
	uint64_t p_total = p_idle + p_non;
	uint64_t c_total = c_idle + c_non;
	uint64_t d_total = c_total - p_total;
	uint64_t d_idle = c_idle - p_idle;
	if (d_total == 0)
		return 0.0;
	return ((double)(d_total - d_idle) / (double)d_total) * 100.0;
}

static int read_mem(uint64_t *total, uint64_t *used)
{
	FILE *f = fopen("/proc/meminfo", "r");
	if (!f)
		return -1;
	char key[32];
	uint64_t val;
	uint64_t mt = 0, ma = 0;
	while (fscanf(f, "%31s %lu kB", key, &val) == 2) {
		if (strcmp(key, "MemTotal:") == 0)
			mt = val * 1024ULL;
		else if (strcmp(key, "MemAvailable:") == 0)
			ma = val * 1024ULL;
		if (mt && ma)
			break;
	}
	fclose(f);
	if (mt == 0 || ma == 0)
		return -1;
	if (total)
		*total = mt;
	if (used)
		*used = mt > ma ? mt - ma : 0;
	return 0;
}

/*
 * Signal handler for terminal resize
 */
static void tui_handle_resize(int sig)
{
	(void)sig;
	tui_resize = 1;
}

/*
 * Get terminal size
 */
static void tui_get_size(void)
{
	struct winsize ws;
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
		g_tui.width = ws.ws_col;
		g_tui.height = ws.ws_row;
	} else {
		g_tui.width = 80;
		g_tui.height = 24;
	}
}

/*
 * Format bytes to human readable
 */
static void tui_format_bytes(uint64_t bytes, char *buf, size_t len)
{
	if (bytes >= 1073741824ULL)
		snprintf(buf, len, "%.1f GB", (double)bytes / 1073741824.0);
	else if (bytes >= 1048576ULL)
		snprintf(buf, len, "%.1f MB", (double)bytes / 1048576.0);
	else if (bytes >= 1024ULL)
		snprintf(buf, len, "%.1f KB", (double)bytes / 1024.0);
	else
		snprintf(buf, len, "%lu B", (unsigned long)bytes);
}

static void tui_format_pct(double pct, char *buf, size_t len)
{
	if (pct < 0)
		pct = 0;
	if (pct > 100)
		pct = 100;
	snprintf(buf, len, "%5.1f%%", pct);
}

static void tui_update_system(struct cpu_sample *prev)
{
	struct cpu_sample cur;
	static int have_prev;

	if (prev) {
		if (!have_prev) {
			if (read_cpu_sample(prev) == 0)
				have_prev = 1;
		} else if (read_cpu_sample(&cur) == 0) {
			g_tui.cpu_pct = cpu_usage_pct(prev, &cur);
			*prev = cur;
		}
	}
	if (read_mem(&g_tui.mem_total, &g_tui.mem_used) != 0) {
		g_tui.mem_total = 0;
		g_tui.mem_used = 0;
	}
}

/*
 * Format uptime
 */
static void tui_format_uptime(time_t start, char *buf, size_t len)
{
	time_t now = time(NULL);
	time_t diff = now - start;
	int days = (int)(diff / 86400);
	int hours = (int)((diff % 86400) / 3600);
	int mins = (int)((diff % 3600) / 60);
	int secs = (int)(diff % 60);

	if (days > 0)
		snprintf(buf, len, "%dd %02d:%02d:%02d", days, hours, mins, secs);
	else
		snprintf(buf, len, "%02d:%02d:%02d", hours, mins, secs);
}

#ifndef HAVE_NCURSES

/*
 * Simple ANSI-based TUI (no ncurses dependency)
 */
static void tui_draw_ansi(void)
{
	char uptime[32];
	char bytes_in[16], bytes_out[16];
	char cpu[16], mem[32];
	int row = 0;

	tui_format_uptime(g_tui.start_time, uptime, sizeof(uptime));
	tui_format_bytes(g_tui.bytes_in, bytes_in, sizeof(bytes_in));
	tui_format_bytes(g_tui.bytes_out, bytes_out, sizeof(bytes_out));
	tui_format_pct(g_tui.cpu_pct, cpu, sizeof(cpu));
	if (g_tui.mem_total)
		snprintf(mem, sizeof(mem), "%.1f/%.1f GB", (double)g_tui.mem_used/1e9, (double)g_tui.mem_total/1e9);
	else
		strncpy(mem, "n/a", sizeof(mem));

	printf(ANSI_CLEAR);
	printf(ANSI_BOLD ANSI_CYAN);
	printf("╔══════════════════════════════════════════════════════════════════════╗\n");
	printf("║                            tunl dashboard                             ║\n");
	printf("╠══════════════════════════════════════════════════════════════════════╣\n");
	printf(ANSI_RESET);
	row = 3;

	/* Stats row */
	printf("║ Uptime: %-12s │ Sessions: %-6d │ In: %-10s Out: %-10s║\n",
	       uptime, g_tui.active_sessions, bytes_in, bytes_out);
	row++;
	printf("║ CPU: %-7s │ Mem: %-16s │ Active rules: %-3u                         ║\n",
	       cpu, mem, g_state.rule_count);
	row++;

	printf("╠══════════════════════════════════════════════════════════════════════╣\n");
	row++;

	/* Rules */
	printf(ANSI_BOLD "║ Active Rules:                                                         ║\n" ANSI_RESET);
	row++;

	pthread_mutex_lock(&g_state.lock);
	for (uint32_t i = 0; i < g_state.rule_count && row < g_tui.height - 5; i++) {
		struct tunl_rule *r = &g_state.rules[i];
		const char *status;
		
		if (r->backends[0].healthy)
			status = ANSI_GREEN "●" ANSI_RESET;
		else
			status = ANSI_RED "●" ANSI_RESET;

		printf("║  %s :%d → %s:%d %-43s║\n",
		       status,
		       r->listen_port,
		       r->backends[0].host,
		       r->backends[0].port,
		       r->tls ? "[TLS]" : "");
		row++;
	}
	pthread_mutex_unlock(&g_state.lock);

	/* Fill remaining space */
	while (row < g_tui.height - 3) {
		printf("║                                                                        ║\n");
		row++;
	}

	printf("╠══════════════════════════════════════════════════════════════════════╣\n");
	printf("║ " ANSI_BOLD "q" ANSI_RESET ":quit  " 
	       ANSI_BOLD "r" ANSI_RESET ":reload  "
	       ANSI_BOLD "s" ANSI_RESET ":stats  "
	       ANSI_BOLD "h" ANSI_RESET ":help                                      ║\n");
	printf("╚══════════════════════════════════════════════════════════════════════╝\n");
	
	fflush(stdout);
}

/*
 * ANSI TUI input handler
 */
static int tui_handle_input_ansi(void)
{
	fd_set fds;
	struct timeval tv;
	char c;

	FD_ZERO(&fds);
	FD_SET(STDIN_FILENO, &fds);
	tv.tv_sec = 1;
	tv.tv_usec = 0;

	if (select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) > 0) {
		if (read(STDIN_FILENO, &c, 1) == 1) {
			switch (c) {
			case 'q':
			case 'Q':
				return -1;
			case 'r':
			case 'R':
				/* TODO: reload config */
				break;
			case 's':
			case 'S':
				/* Show detailed stats */
				break;
			}
		}
	}

	return 0;
}

/*
 * Run ANSI TUI main loop
 */
static void tui_run_ansi(void)
{
	struct termios old_term, new_term;
	struct cpu_sample prev = {0};
	
	/* Set terminal to raw mode */
	tcgetattr(STDIN_FILENO, &old_term);
	new_term = old_term;
	new_term.c_lflag &= (tcflag_t)~(ICANON | ECHO);
	new_term.c_cc[VMIN] = 0;
	new_term.c_cc[VTIME] = 0;
	tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

	printf(ANSI_HIDE_CUR);

	while (g_tui.running) {
		if (tui_resize) {
			tui_get_size();
			tui_resize = 0;
		}

		/* Update stats from global state */
		pthread_mutex_lock(&g_state.lock);
		g_tui.active_sessions = (int)g_state.session_count;
		g_tui.bytes_in = g_state.bytes_in;
		g_tui.bytes_out = g_state.bytes_out;
		pthread_mutex_unlock(&g_state.lock);

		tui_update_system(&prev);

		tui_draw_ansi();

		if (tui_handle_input_ansi() < 0)
			break;
	}

	printf(ANSI_SHOW_CUR ANSI_CLEAR);
	tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
}

#else /* HAVE_NCURSES */

/*
 * ncurses-based TUI
 */
static WINDOW *win_header;
static WINDOW *win_rules;
static WINDOW *win_sessions;
static WINDOW *win_status;

static void tui_init_ncurses(void)
{
	initscr();
	cbreak();
	noecho();
	keypad(stdscr, TRUE);
	curs_set(0);
	timeout(TUI_REFRESH_MS);

	if (has_colors()) {
		start_color();
		init_pair(1, COLOR_GREEN, COLOR_BLACK);
		init_pair(2, COLOR_RED, COLOR_BLACK);
		init_pair(3, COLOR_YELLOW, COLOR_BLACK);
		init_pair(4, COLOR_CYAN, COLOR_BLACK);
	}

	/* Create windows */
	win_header = newwin(3, COLS, 0, 0);
	win_rules = newwin(LINES - 6, COLS, 3, 0);
	win_status = newwin(3, COLS, LINES - 3, 0);
}

static void tui_draw_ncurses(void)
{
	char uptime[32];
	char bytes_in[16], bytes_out[16];
	char cpu[16], mem[32];

	tui_format_uptime(g_tui.start_time, uptime, sizeof(uptime));
	tui_format_bytes(g_tui.bytes_in, bytes_in, sizeof(bytes_in));
	tui_format_bytes(g_tui.bytes_out, bytes_out, sizeof(bytes_out));
	tui_format_pct(g_tui.cpu_pct, cpu, sizeof(cpu));
	if (g_tui.mem_total)
		snprintf(mem, sizeof(mem), "%.1f/%.1f GB", (double)g_tui.mem_used/1e9, (double)g_tui.mem_total/1e9);
	else
		strncpy(mem, "n/a", sizeof(mem));

	/* Header */
	werase(win_header);
	box(win_header, 0, 0);
	wattron(win_header, A_BOLD | COLOR_PAIR(4));
	mvwprintw(win_header, 1, (COLS - 14) / 2, "tunl dashboard");
	wattroff(win_header, A_BOLD | COLOR_PAIR(4));
	wrefresh(win_header);

	/* Rules */
	werase(win_rules);
	box(win_rules, 0, 0);
	wattron(win_rules, A_BOLD);
	mvwprintw(win_rules, 0, 2, " Rules ");
	wattroff(win_rules, A_BOLD);

	pthread_mutex_lock(&g_state.lock);
	for (int i = 0; i < g_state.rule_count && i < LINES - 8; i++) {
		struct tunl_rule *r = &g_state.rules[i];
		
		if (i == g_tui.selected)
			wattron(win_rules, A_REVERSE);

		if (r->backends[0].healthy)
			wattron(win_rules, COLOR_PAIR(1));
		else
			wattron(win_rules, COLOR_PAIR(2));

		mvwprintw(win_rules, i + 1, 2, "● :%d → %s:%d %s",
			  r->listen_port,
			  r->backends[0].host,
			  r->backends[0].port,
			  r->tls ? "[TLS]" : "");

		wattroff(win_rules, COLOR_PAIR(1) | COLOR_PAIR(2) | A_REVERSE);
	}
	pthread_mutex_unlock(&g_state.lock);

	wrefresh(win_rules);

	/* Status bar */
	werase(win_status);
	box(win_status, 0, 0);
	mvwprintw(win_status, 1, 2, 
		  "Up: %s | CPU: %s | Mem: %s | Sessions: %d | In: %s | Out: %s",
		  uptime, cpu, mem, g_tui.active_sessions, bytes_in, bytes_out);
	mvwprintw(win_status, 1, COLS - 30, "q:quit r:reload h:help");
	wrefresh(win_status);
}

static void tui_run_ncurses(void)
{
	int ch;
	struct cpu_sample prev = {0};

	tui_init_ncurses();

	while (g_tui.running) {
		/* Update stats */
		pthread_mutex_lock(&g_state.lock);
		g_tui.active_sessions = g_state.session_count;
		g_tui.bytes_in = g_state.bytes_in;
		g_tui.bytes_out = g_state.bytes_out;
		pthread_mutex_unlock(&g_state.lock);

		tui_update_system(&prev);

		tui_draw_ncurses();

		ch = getch();
		switch (ch) {
		case 'q':
		case 'Q':
			g_tui.running = 0;
			break;
		case KEY_UP:
			if (g_tui.selected > 0)
				g_tui.selected--;
			break;
		case KEY_DOWN:
			if (g_tui.selected < g_state.rule_count - 1)
				g_tui.selected++;
			break;
		case 'r':
		case 'R':
			/* TODO: reload */
			break;
		case KEY_RESIZE:
			/* Handle terminal resize */
			endwin();
			refresh();
			tui_init_ncurses();
			break;
		}
	}

	delwin(win_header);
	delwin(win_rules);
	delwin(win_status);
	endwin();
}

#endif /* HAVE_NCURSES */

/*
 * Start TUI
 */
int tui_run(void)
{
	signal(SIGWINCH, tui_handle_resize);

	memset(&g_tui, 0, sizeof(g_tui));
	g_tui.running = 1;
	g_tui.start_time = time(NULL);
	tui_get_size();

	tunl_log(TUNL_LOG_INFO, "Starting TUI (%dx%d)", g_tui.width, g_tui.height);

#ifdef HAVE_NCURSES
	tui_run_ncurses();
#else
	tui_run_ansi();
#endif

	return 0;
}

/*
 * Standalone TUI (connect to running instance via control socket)
 */
int tui_standalone(const char *ctrl_path)
{
	/* For standalone mode, we connect to the control socket
	 * and display status from there */
	(void)ctrl_path;
	
	printf("Connecting to tunl control socket...\n");
	
	/* TODO: implement control socket client */
	
	return tui_run();
}
