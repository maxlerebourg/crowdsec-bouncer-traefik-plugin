#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=captcha
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

echo "[$SCENARIO] starting stack..."
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d --wait

echo "[$SCENARIO] waiting for crowdsec readiness..."
wait_crowdsec_ready

echo "[$SCENARIO] waiting for traefik readiness..."
wait_for_status http://localhost:8000/foo 200 30

echo "[$SCENARIO] adding captcha decision for 1.2.3.4"
docker exec crowdsec cscli decisions add --ip 1.2.3.4 --type captcha --duration 5m

echo "[$SCENARIO] waiting one stream tick + buffer..."
sleep 6

echo "[$SCENARIO] captcha response must be HTTP 200 (the captcha page itself, not a 403)"
assert_status http://localhost:8000/foo 200 -H "X-Forwarded-For: 1.2.3.4"

echo "[$SCENARIO] captcha response body must contain the captcha template marker"
body=$(curl -s http://localhost:8000/foo -H "X-Forwarded-For: 1.2.3.4")
if ! grep -q "E2E_CAPTCHA_PAGE_MARKER" <<<"$body"; then
  echo "Expected response body to contain E2E_CAPTCHA_PAGE_MARKER, got:" >&2
  echo "$body" >&2
  exit 1
fi

echo "[$SCENARIO] non-flagged IP must still pass through to the backend"
assert_status http://localhost:8000/foo 200 -H "X-Forwarded-For: 5.6.7.8"

echo "[$SCENARIO] OK"
