#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=appsec
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

echo "[$SCENARIO] starting stack (AppSec collections download — may take ~30s on first boot)..."
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d --wait

echo "[$SCENARIO] waiting for crowdsec readiness..."
wait_crowdsec_ready crowdsec 180

echo "[$SCENARIO] waiting for traefik readiness..."
wait_for_status http://localhost:8000/foo 200 30

echo "[$SCENARIO] benign request must pass"
assert_status http://localhost:8000/foo 200

echo "[$SCENARIO] SQL-injection-like query string must be blocked by AppSec virtual patching"
# CRS-style SQLi probe — caught by crowdsecurity/appsec-generic-rules.
assert_status "http://localhost:8000/foo?id=1%27%20UNION%20SELECT%201%2C2%2C3--" 403

echo "[$SCENARIO] OK"
