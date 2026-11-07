#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=custom-ban-page
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

echo "[$SCENARIO] adding ban decision"
docker exec crowdsec cscli decisions add --ip 1.2.3.4 --type ban --duration 5m

echo "[$SCENARIO] waiting one stream tick + buffer..."
sleep 6

echo "[$SCENARIO] banned response status is 403"
assert_status http://localhost:8000/foo 403 -H "X-Forwarded-For: 1.2.3.4"

echo "[$SCENARIO] banned response Content-Type is HTML"
assert_header http://localhost:8000/foo Content-Type "text/html; charset=utf-8" -H "X-Forwarded-For: 1.2.3.4"

echo "[$SCENARIO] banned response body contains the custom marker"
body=$(curl -s http://localhost:8000/foo -H "X-Forwarded-For: 1.2.3.4")
if ! grep -q "E2E_CUSTOM_BAN_PAGE_MARKER" <<<"$body"; then
  echo "Expected response body to contain E2E_CUSTOM_BAN_PAGE_MARKER, got:" >&2
  echo "$body" >&2
  exit 1
fi

echo "[$SCENARIO] OK"
