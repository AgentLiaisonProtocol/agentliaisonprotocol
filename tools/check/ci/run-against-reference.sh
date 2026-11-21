#!/usr/bin/env bash
# Runs alp-check against the reference broker on one machine, with federation on, and judges the report.
# The "check" job in .github/workflows/ci.yml runs it; it works the same on any Linux machine with Node 22.18 or
# later, python3, curl, setsid and timeout, after `npm ci` in reference/ and in tools/check/.
#
#   tools/check/ci/run-against-reference.sh
#
# ALP_CHECK_WORK names a new or empty folder for the configuration, the broker's data, the logs and the report
# (default: a new temporary folder). The JSON report is written to $ALP_CHECK_WORK/report/alp-check-report.json.
#
# Steps:
#   1. write a configuration from reference/deploy/config.example.json with "federation": true and
#      reference/deploy/policy.eval.json;
#   2. start the reference broker (npm start) on 127.0.0.1, with sign-in secrets made here and never printed;
#   3. wait for its /readyz;
#   4. build example.org's domain document from the broker's own key set (ci/domain-document.mjs) and serve it
#      from a second port with python3's static file server;
#   5. run alp-check against example.org with a development host map that sends https://example.org and
#      https://broker.example.org to those two ports;
#   6. print the report and judge it (ci/judge.mjs);
#   7. stop every process it started, whatever happens.
#
# The broker listens on plain HTTP on loopback, so alp-check skips its TLS and DNS checks.
# Licensed under Apache-2.0.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
DOMAIN="example.org"
BROKER_ID="https://broker.example.org"
BROKER_PORT=47210
WEB_PORT=47211
DOC_PORT=47212

WORK="${ALP_CHECK_WORK:-$(mktemp -d)}"
mkdir -p "$WORK"
if [ -n "$(ls -A "$WORK")" ]; then
  echo "$WORK is not empty" >&2
  exit 2
fi
mkdir -p "$WORK/eval" "$WORK/data" "$WORK/site/.well-known" "$WORK/report"
BROKER_LOG="$WORK/broker.log"
DOC_LOG="$WORK/doc-server.log"

# Each process starts in its own process group, so stopping the group stops npm, its shell and node together.
PIDS=()
stop_all() {
  local pid i
  for pid in "${PIDS[@]}"; do kill -TERM -- "-$pid" 2>/dev/null || true; done
  for pid in "${PIDS[@]}"; do
    for i in $(seq 1 20); do
      kill -0 -- "-$pid" 2>/dev/null || break
      sleep 0.5
    done
    kill -KILL -- "-$pid" 2>/dev/null || true
  done
  PIDS=()
}
SECRET_ANA=""
SECRET_LEE=""
print_broker_log() {
  [ -f "$BROKER_LOG" ] || return 0
  echo "::group::reference broker log"
  # The secrets go to the search through its environment, not its arguments.
  if [ -n "$SECRET_ANA" ] && ALP_CHECK_S1="$SECRET_ANA" ALP_CHECK_S2="$SECRET_LEE" node -e '
    const t = require("node:fs").readFileSync(process.argv[1], "utf8");
    process.exit(t.includes(process.env.ALP_CHECK_S1) || t.includes(process.env.ALP_CHECK_S2) ? 0 : 1);
  ' "$BROKER_LOG"; then
    echo "(not printed: the log holds a sign-in secret)"
  else
    cat "$BROKER_LOG"
  fi
  echo "::endgroup::"
}
on_exit() {
  local status=$?
  stop_all
  print_broker_log
  exit "$status"
}
trap on_exit EXIT
trap 'exit 130' INT TERM

# 1. The configuration.
cp "$ROOT/reference/deploy/policy.eval.json" "$WORK/eval/"
node -e '
  const fs = require("node:fs");
  const [from, to] = process.argv.slice(1);
  const c = JSON.parse(fs.readFileSync(from, "utf8"));
  c.policies = ["policy.eval.json"];
  c.federation = true;
  fs.writeFileSync(to, JSON.stringify(c, null, 2));
' "$ROOT/reference/deploy/config.example.json" "$WORK/eval/config.json"

# 2. The broker. One sign-in secret per test identity of config.example.json, made here. Shell tracing is switched
# off first, so that `bash -x` or SHELLOPTS=xtrace cannot print them; they reach the broker through its environment
# only, never through a command's arguments; and on GitHub Actions the runner is told to mask them.
{ set +x; } 2>/dev/null
SECRET_ANA="$(node -e 'process.stdout.write(require("node:crypto").randomBytes(18).toString("base64url"))')"
SECRET_LEE="$(node -e 'process.stdout.write(require("node:crypto").randomBytes(18).toString("base64url"))')"
if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
  echo "::add-mask::$SECRET_ANA"
  echo "::add-mask::$SECRET_LEE"
fi
(
  cd "$ROOT/reference"
  export ALP_CONFIG="$WORK/eval/config.json"
  export ALP_DATA_DIR="$WORK/data"
  export ALP_DEV_LOGIN_SECRETS="{\"ana\":\"$SECRET_ANA\",\"lee\":\"$SECRET_LEE\"}"
  export HOST=127.0.0.1 PORT="$BROKER_PORT" WEB_HOST=127.0.0.1 WEB_PORT="$WEB_PORT"
  exec setsid npm start
) >"$BROKER_LOG" 2>&1 &
BROKER_PID=$!
PIDS+=("$BROKER_PID")

# 3. Ready within 90 seconds.
deadline=$((SECONDS + 90))
until curl -fsS --max-time 5 -o /dev/null "http://127.0.0.1:$BROKER_PORT/readyz" 2>/dev/null; do
  if ! kill -0 "$BROKER_PID" 2>/dev/null; then
    echo "the reference broker stopped before it was ready" >&2
    exit 1
  fi
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "the reference broker was not ready within 90 seconds" >&2
    exit 1
  fi
  sleep 1
done
echo "reference broker ready on 127.0.0.1:$BROKER_PORT (id $BROKER_ID, federation on)"

# 4. The domain document, from the broker's own key set, served from a second port.
curl -fsS --max-time 10 -o "$WORK/jwks.json" "http://127.0.0.1:$BROKER_PORT/.well-known/jwks.json"
node "$HERE/domain-document.mjs" "$WORK/jwks.json" "$BROKER_ID" "$DOMAIN" >"$WORK/site/.well-known/alp.json"
echo "::group::domain document served for $DOMAIN"
cat "$WORK/site/.well-known/alp.json"
echo "::endgroup::"
setsid python3 -m http.server "$DOC_PORT" --bind 127.0.0.1 --directory "$WORK/site" >"$DOC_LOG" 2>&1 &
PIDS+=("$!")
deadline=$((SECONDS + 30))
until curl -fsS --max-time 5 -o /dev/null "http://127.0.0.1:$DOC_PORT/.well-known/alp.json" 2>/dev/null; do
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "the domain document was not served within 30 seconds" >&2
    cat "$DOC_LOG" >&2
    exit 1
  fi
  sleep 1
done

# 5. alp-check, at most 5 minutes.
MAP="{\"https://$DOMAIN\":\"http://127.0.0.1:$DOC_PORT\",\"$BROKER_ID\":\"http://127.0.0.1:$BROKER_PORT\"}"
REPORT="$WORK/report/alp-check-report.json"
set +e
timeout 300 node "$ROOT/tools/check/check.mjs" "$DOMAIN" --dev-map "$MAP" --json >"$REPORT"
code=$?
set -e
echo "alp-check exited $code"

# 6. The report and the judgement.
node "$HERE/judge.mjs" "$REPORT" "$code"
