#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=stream-mode
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

echo "[$SCENARIO] no decision yet -> request allowed"
assert_status http://localhost:8000/foo 200 -H "X-Forwarded-For: 1.2.3.4"

echo "[$SCENARIO] adding ban decision for 1.2.3.4"
docker exec crowdsec cscli decisions add --ip 1.2.3.4 --type ban --duration 5m

echo "[$SCENARIO] waiting one stream tick + buffer..."
sleep 6

echo "[$SCENARIO] banned IP must be blocked (HTTP 403)"
assert_status http://localhost:8000/foo 403 -H "X-Forwarded-For: 1.2.3.4"

echo "[$SCENARIO] non-banned IP must still pass (HTTP 200)"
assert_status http://localhost:8000/foo 200 -H "X-Forwarded-For: 5.6.7.8"

echo "[$SCENARIO] deleting ban decision"
docker exec crowdsec cscli decisions delete --ip 1.2.3.4

echo "[$SCENARIO] waiting one stream tick + buffer..."
sleep 6

echo "[$SCENARIO] previously banned IP must pass again"
assert_status http://localhost:8000/foo 200 -H "X-Forwarded-For: 1.2.3.4"

echo "[$SCENARIO] OK"
