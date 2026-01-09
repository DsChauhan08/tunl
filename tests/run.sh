#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bin/tunl"
LOG_DIR="$ROOT/tests/logs"
mkdir -p "$LOG_DIR"

cleanup_pids=()
cleanup() {
	for pid in "${cleanup_pids[@]:-}"; do
		if kill -0 "$pid" 2>/dev/null; then
			kill "$pid" 2>/dev/null || true
			wait "$pid" 2>/dev/null || true
		fi
	done
}
trap cleanup EXIT

need_bin() {
	if [ ! -x "$BIN" ]; then
		echo "Building tunl..." >&2
		make -s -C "$ROOT"
	fi
}

start_http_backend() {
	local port=$1
	python - <<'PY' "$port" >/dev/null 2>&1 &
import http.server, socketserver, socket, sys
port = int(sys.argv[1])

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
		body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, fmt, *args):
        return

class HTTPServerV6(http.server.HTTPServer):
    address_family = socket.AF_INET6

httpd = HTTPServerV6(("::1", port), Handler)
httpd.serve_forever()
PY
	cleanup_pids+=($!)
}

wait_for_port() {
	local host=$1 port=$2
	python - <<'PY' "$host" "$port"
import socket, sys, time
host, port = sys.argv[1], int(sys.argv[2])
for _ in range(50):
    try:
        s = socket.create_connection((host, port), 0.1)
        s.close()
        sys.exit(0)
    except OSError:
        time.sleep(0.1)
sys.exit(1)
PY
}

start_tunl_forward() {
	local listen=$1 target=$2
	"$BIN" -f "$listen:$target" >"$LOG_DIR/forward.log" 2>&1 &
	cleanup_pids+=($!)
}

start_tunl_serve() {
	local conf=$1
	"$BIN" serve -C "$conf" >"$LOG_DIR/serve.log" 2>&1 &
	cleanup_pids+=($!)
}

http_request() {
	local url=$1
	curl -s --max-time 5 "$url"
}

assert_eq() {
	local got=$1 expected=$2 label=$3
	if [ "$got" != "$expected" ]; then
		echo "[FAIL] $label: expected '$expected', got '$got'" >&2
		exit 1
	fi
	echo "[OK] $label"
}

quick_forward_test() {
	echo "Running quick forward test"
	start_http_backend 3000
	start_tunl_forward 8080 "localhost:3000"
	wait_for_port ::1 8080
	resp=$(http_request "http://[::1]:8080/")
	assert_eq "$resp" "ok" "IPv6 forward"
	resp4=$(http_request "http://127.0.0.1:8080/")
	assert_eq "$resp4" "ok" "IPv4 forward"
}

config_serve_test() {
	echo "Running config serve test"
	start_http_backend 3001
	start_tunl_serve "$ROOT/tests/fixtures/basic.conf"
	wait_for_port ::1 8082
	resp=$(http_request "http://[::1]:8082/")
	assert_eq "$resp" "ok" "Config-based forward"
}

main() {
	need_bin
	quick_forward_test
	config_serve_test
	echo "All tests passed"
}

main "$@"
