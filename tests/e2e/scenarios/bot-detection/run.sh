#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=bot-detection
PROJECT="e2e-${SCENARIO}"
COMPOSE_FILE="$HERE/docker-compose.yml"
LOG_FILE="/tmp/e2e-${SCENARIO}.log"

cleanup() {
  local rc=$?
  if (( rc != 0 )); then
    dump_diagnostics "$PROJECT" "$COMPOSE_FILE" > "$LOG_FILE" 2>&1 || true
    echo "Scenario failed. Logs written to $LOG_FILE"
  fi
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
  exit $rc
}
trap cleanup EXIT

assert_body_contains() {
  local body="$1" expected="$2"
  if ! grep -qF "$expected" <<<"$body"; then
    echo "Expected response body to contain \"$expected\", got:" >&2
    head -c 500 <<<"$body" >&2
    exit 1
  fi
}

assert_not_backend() {
  if grep -q '^Hostname:' <<<"$1"; then
    echo "Expected the request not to reach the backend, got the whoami response" >&2
    exit 1
  fi
}

echo "[$SCENARIO] starting stack (AppSec collections download — may take ~30s on first boot)..."
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d --wait

echo "[$SCENARIO] waiting for crowdsec readiness..."
wait_crowdsec_ready crowdsec 180

echo "[$SCENARIO] waiting for traefik readiness..."
wait_for_status http://localhost:8000/foo 200 60

echo "[$SCENARIO] a request gets the AppSec challenge page instead of the backend"
assert_status http://localhost:8000/foo 200 -H "X-Forwarded-For: 1.2.3.4"
body=$(curl -s http://localhost:8000/foo -H "X-Forwarded-For: 1.2.3.4")
assert_not_backend "$body"
assert_body_contains "$body" "CrowdSec Challenge"
assert_body_contains "$body" "/crowdsec-internal/challenge/fpscanner.js"

echo "[$SCENARIO] the challenge carries the AppSec Content-Security-Policy"
csp=$(curl -s -D - -o /dev/null http://localhost:8000/foo -H "X-Forwarded-For: 1.2.3.4" | tr -d '\r' \
  | awk -F': ' 'tolower($1) == "content-security-policy" { print $2; exit }')
assert_body_contains "$csp" "worker-src 'self' blob:"

echo "[$SCENARIO] the fingerprint script is served by AppSec, not the backend"
assert_header http://localhost:8000/crowdsec-internal/challenge/fpscanner.js Content-Type application/javascript -H "X-Forwarded-For: 1.2.3.4"
assert_not_backend "$(curl -s http://localhost:8000/crowdsec-internal/challenge/fpscanner.js -H "X-Forwarded-For: 1.2.3.4")"

echo "[$SCENARIO] a challenge path AppSec does not serve is answered 404, never by the backend"
assert_status http://localhost:8000/crowdsec-internal/challenge/custom.js 404 -H "X-Forwarded-For: 1.2.3.4"
assert_not_backend "$(curl -s http://localhost:8000/crowdsec-internal/challenge/custom.js -H "X-Forwarded-For: 1.2.3.4")"

echo "[$SCENARIO] an invalid proof is forwarded with its body to AppSec and rejected"
body=$(curl -s -X POST -d 'garbage=1' http://localhost:8000/crowdsec-internal/challenge/submit -H "X-Forwarded-For: 1.2.3.4")
assert_body_contains "$body" '{"status":"failed"}'

echo "[$SCENARIO] OK"
