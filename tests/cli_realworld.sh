#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPF_BIN="${SPF_BIN:-$ROOT/bin/spf}"
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
readonly = false
readonly_token = readonly-secret
max_cmds_per_min = 240
auth_fail_threshold = 3
auth_lockout_sec = 3
idle_timeout_sec = 120
service_token_max_ttl_sec = 30
temp_grant_max_ttl_sec = 30
audit_log = /tmp/spf-cli-audit.log
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
readonly = false
readonly_token = readonly-secret
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
sleep 5

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
  printf 'SETRATE %s 2097152\n' "$RULE_ID"; sleep 0.2
  printf 'SETMAXCONNS %s 2\n' "$RULE_ID"; sleep 0.2
  printf 'SETGLOBALMAXCONNS 1024\n'; sleep 0.2
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
printf '%s\n' "$CTRL_OUT" | rg -q 'OK rate set'
printf '%s\n' "$CTRL_OUT" | rg -q 'OK max conns set'
printf '%s\n' "$CTRL_OUT" | rg -q 'OK global max conns'
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

echo "[cli] validating readonly token behavior"
RO_OUT=$( {
  printf 'AUTH readonly-secret\n'; sleep 0.2
  printf 'STATUS\n'; sleep 0.2
  printf 'ADD 19080 127.0.0.1:9000 rr\n'; sleep 0.2
  printf 'QUIT\n'
} | nc 127.0.0.1 18081 )

echo "$RO_OUT"
printf '%s\n' "$RO_OUT" | rg -q 'OK authenticated readonly'
printf '%s\n' "$RO_OUT" | rg -q 'ERR readonly session'

echo "[cli] validating auth lockout behavior"
LOCK_OUT=$( {
  printf 'AUTH bad1\n'; sleep 0.2
  printf 'AUTH bad2\n'; sleep 0.2
  printf 'AUTH bad3\n'; sleep 0.2
  printf 'AUTH secret\n'; sleep 0.2
  printf 'QUIT\n'
} | nc 127.0.0.1 18081 )

echo "$LOCK_OUT"
printf '%s\n' "$LOCK_OUT" | rg -q 'locked'

sleep 5

echo "[cli] validating TLS info command"
TLS_OUT=$( {
  printf 'AUTH readonly-secret\n'; sleep 0.2
  printf 'TLSINFO\n'; sleep 0.2
  printf 'QUIT\n'
} | nc 127.0.0.1 18081 )

echo "$TLS_OUT"
printf '%s\n' "$TLS_OUT" | rg -q 'max_cmds_per_min='
printf '%s\n' "$TLS_OUT" | rg -q 'auth_fail_threshold='
printf '%s\n' "$TLS_OUT" | rg -q 'audit_log='

echo "[cli] validating staged apply + rollback"
DUAL_OUT=$( {
  printf 'AUTH secret\n'; sleep 0.2
  printf 'STAGE max_cmds_per_min 123\n'; sleep 0.2
  printf 'STAGE readonly true\n'; sleep 0.2
  printf 'APPLY\n'; sleep 0.2
  printf 'TLSINFO\n'; sleep 0.2
  printf 'ROLLBACK\n'; sleep 0.2
  printf 'TLSINFO\n'; sleep 0.2
  printf 'QUIT\n'
} | nc 127.0.0.1 18081 )

echo "$DUAL_OUT"
printf '%s\n' "$DUAL_OUT" | rg -q 'OK staged max_cmds_per_min'
printf '%s\n' "$DUAL_OUT" | rg -q 'OK staged readonly'
printf '%s\n' "$DUAL_OUT" | rg -q 'OK applied staged config'
printf '%s\n' "$DUAL_OUT" | rg -q 'max_cmds_per_min=123'
printf '%s\n' "$DUAL_OUT" | rg -q 'OK rolled back'
printf '%s\n' "$DUAL_OUT" | rg -q 'max_cmds_per_min=240'

echo "[cli] validating service token auth and temp access grants"
TOK_OUT=$( {
  printf 'AUTH secret\n'; sleep 0.2
  printf 'TOKENADD ci rw 15 2 svc-ci-token\n'; sleep 0.2
  printf 'TOKENLIST\n'; sleep 0.2
  printf 'ACCESSGRANT 127.0.0.2 10\n'; sleep 0.2
  printf 'ACCESSGRANTS\n'; sleep 0.2
  printf 'QUIT\n'
} | nc 127.0.0.1 18081 )

echo "$TOK_OUT"
printf '%s\n' "$TOK_OUT" | rg -q 'OK token id='
printf '%s\n' "$TOK_OUT" | rg -q -- '--- SERVICE TOKENS ---'
printf '%s\n' "$TOK_OUT" | rg -q 'OK temp access granted 127.0.0.2'
printf '%s\n' "$TOK_OUT" | rg -q -- '--- TEMP ACCESS GRANTS ---'

SVC_TOKEN="svc-ci-token"

SVC_AUTH_OUT=$( {
  printf 'AUTH %s\n' "$SVC_TOKEN"; sleep 0.2
  printf 'STATUS\n'; sleep 0.2
  printf 'QUIT\n'
} | nc 127.0.0.1 18081 )

echo "$SVC_AUTH_OUT"
printf '%s\n' "$SVC_AUTH_OUT" | rg -q 'OK authenticated service token'

TOK_DEL_OUT=$( {
  printf 'AUTH secret\n'; sleep 0.2
  printf 'TOKENLIST\n'; sleep 0.2
  printf 'TOKENDEL 1\n'; sleep 0.2
  printf 'ACCESSREVOKE 127.0.0.2\n'; sleep 0.2
  printf 'QUIT\n'
} | nc 127.0.0.1 18081 )

echo "$TOK_DEL_OUT"
printf '%s\n' "$TOK_DEL_OUT" | rg -q 'token deleted|token not found'
printf '%s\n' "$TOK_DEL_OUT" | rg -q 'temp access revoked 127.0.0.2'

echo "[cli] validating token metrics surfacing"
TOK_METRICS=$( {
  printf 'AUTH secret\n'; sleep 0.2
  printf 'EMERGENCY ON\n'; sleep 0.2
  printf 'EMERGENCY OFF\n'; sleep 0.2
  printf 'METRICS\n'; sleep 0.2
  printf 'AUDITVERIFY\n'; sleep 0.2
  printf 'QUIT\n'
} | nc 127.0.0.1 18081 )

echo "$TOK_METRICS"
printf '%s\n' "$TOK_METRICS" | rg -q 'spf_admin_service_token_auth_success_total'
printf '%s\n' "$TOK_METRICS" | rg -q 'spf_admin_temp_grants_created_total'
printf '%s\n' "$TOK_METRICS" | rg -q 'spf_admin_failed_commands_total'
printf '%s\n' "$TOK_METRICS" | rg -q 'spf_emergency_mode'
printf '%s\n' "$TOK_METRICS" | rg -q 'OK audit chain verified entries='

echo "[cli] validating audit log entries"
[[ -f /tmp/spf-cli-audit.log ]]
rg -q '"prev_hash"' /tmp/spf-cli-audit.log
rg -q '"hash"' /tmp/spf-cli-audit.log
! rg -q 'svc-ci-token' /tmp/spf-cli-audit.log

echo "[cli] real-world CLI checks passed"
