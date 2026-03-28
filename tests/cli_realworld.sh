#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPF_BIN="$ROOT/bin/spf"
BACKEND_PY="$ROOT/fast_backend.py"
CFG_FILE="$(mktemp /tmp/spf-cli-config.XXXXXX.conf)"
GUARD_CFG_FILE="$(mktemp /tmp/spf-cli-guard-config.XXXXXX.conf)"

BACK_PID=""
SPF_PID=""

cleanup() {
  if [[ -n "$SPF_PID" ]]; then
    kill "$SPF_PID" 2>/dev/null || true
    wait "$SPF_PID" 2>/dev/null || true
  fi
  if [[ -n "$BACK_PID" ]]; then
    kill "$BACK_PID" 2>/dev/null || true
    wait "$BACK_PID" 2>/dev/null || true
  fi
  rm -f "$CFG_FILE"
  rm -f "$GUARD_CFG_FILE"
}
trap cleanup EXIT

cat >"$CFG_FILE" <<'EOF'
[admin]
bind = 127.0.0.1
port = 18081
tls = false
mtls = false
allowlist = 127.0.0.1

[metrics]
enabled = false
port = 19100
EOF

cat >"$GUARD_CFG_FILE" <<'EOF'
[admin]
bind = 127.0.0.1
port = 18081
tls = false
mtls = false
allowlist = 127.0.0.1

[metrics]
enabled = false
port = 19100
EOF

echo "[cli] starting backend"
python3 "$BACKEND_PY" >/tmp/spf-cli-backend.log 2>&1 &
BACK_PID=$!

echo "[cli] starting SPF"
"$SPF_BIN" --config "$CFG_FILE" --token secret --admin-port 18081 --admin-bind 127.0.0.1 --admin-allow 127.0.0.1 >/tmp/spf-cli.log 2>&1 &
SPF_PID=$!
sleep 1

echo "[cli] creating rule"
ADMIN_OUT=$( {
  printf 'AUTH secret\n'; sleep 0.2
  printf 'ADD 18080 127.0.0.1:9000 rr\n'; sleep 0.2
  printf 'RULES\n'; sleep 0.2
  printf 'QUIT\n'
} | nc 127.0.0.1 18081 )

echo "$ADMIN_OUT"
RULE_ID=$(printf '%s\n' "$ADMIN_OUT" | rg -o 'ID:[0-9]+' | sed 's/ID://g' | head -n 1)
if [[ -z "$RULE_ID" ]]; then
  echo "[cli] failed to parse rule id"
  exit 1
fi

echo "[cli] validating data path"
CURL_OUT=$(curl -sS -m 3 http://127.0.0.1:18080)
[[ "$CURL_OUT" == *"Hello"* ]]

echo "[cli] running month-2/3 control checks"
CTRL_OUT=$( {
  printf 'AUTH secret\n'; sleep 0.2
  printf 'SETWEIGHT %s 0 3\n' "$RULE_ID"; sleep 0.2
  printf 'SETSTATE %s 0 DOWN\n' "$RULE_ID"; sleep 0.2
  printf 'SETSTATE %s 0 UP\n' "$RULE_ID"; sleep 0.2
  printf 'PAUSE %s\n' "$RULE_ID"; sleep 0.2
  printf 'RESUME %s\n' "$RULE_ID"; sleep 0.2
  printf 'DRAIN %s 0 1\n' "$RULE_ID"; sleep 0.2
  printf 'HEALTH %s\n' "$RULE_ID"; sleep 0.2
  printf 'ADMINALLOW 127.0.0.2\n'; sleep 0.2
  printf 'ADMINDENY 127.0.0.2\n'; sleep 0.2
  printf 'ADMINSET 127.0.0.1\n'; sleep 0.2
  printf 'SAVE\n'; sleep 0.2
  printf 'METRICS\n'; sleep 0.2
  printf 'QUIT\n'
} | nc 127.0.0.1 18081 )

echo "$CTRL_OUT"

printf '%s\n' "$CTRL_OUT" | rg -q 'OK weight set'
printf '%s\n' "$CTRL_OUT" | rg -q 'OK state set'
printf '%s\n' "$CTRL_OUT" | rg -q 'OK paused'
printf '%s\n' "$CTRL_OUT" | rg -q 'OK resumed'
printf '%s\n' "$CTRL_OUT" | rg -q 'OK config saved'
printf '%s\n' "$CTRL_OUT" | rg -q 'spf_connections_total'

echo "[cli] validating startup guardrails"
set +e
"$SPF_BIN" --config "$GUARD_CFG_FILE" --admin-bind 0.0.0.0 >/tmp/spf-cli-guard.log 2>&1
RC=$?
set -e
if [[ "$RC" -eq 0 ]]; then
  echo "[cli] expected guardrail failure did not happen"
  exit 1
fi
rg -q 'Refusing to expose admin control on non-loopback without --token' /tmp/spf-cli-guard.log

echo "[cli] real-world CLI checks passed"
