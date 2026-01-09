# Test Suite

This folder contains a lightweight smoke suite to exercise the tunl binary locally without extra dependencies.

## Prerequisites
- IPv6 loopback available (`::1`)
- Python 3 and curl installed
- Optional: `make` to build `bin/tunl` if not already present

## What is covered
- Quick forward mode (`tunl -f`) forwarding IPv6/IPv4 to a local backend
- Config-driven serve mode (`tunl serve -C ...`) with a simple rule

## Running

```bash
./tests/run.sh
```

The runner will:
1. Build `bin/tunl` if missing.
2. Start temporary IPv6 HTTP backends on `::1:3000` and `::1:3001`.
3. Forward via `tunl -f 8080:localhost:3000` and hit it over IPv6 and IPv4.
4. Launch `tunl serve -C tests/fixtures/basic.conf` and hit the configured listener on `::1:8082`.
5. Clean up all background processes.

Logs are written to `tests/logs/` for inspection.

## Extending
- Add more fixtures under `tests/fixtures/` and new test functions in `tests/run.sh`.
- Keep tests self-contained: start any helper services inside the script and clean them up via the shared trap.
