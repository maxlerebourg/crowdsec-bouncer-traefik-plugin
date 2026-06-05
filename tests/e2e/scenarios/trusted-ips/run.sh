#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=trusted-ips
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

echo "[$SCENARIO] banning the trusted IP 1.2.3.4 and an untrusted IP 5.6.7.8"
docker exec crowdsec cscli decisions add --ip 1.2.3.4 --type ban --duration 5m
docker exec crowdsec cscli decisions add --ip 5.6.7.8 --type ban --duration 5m

echo "[$SCENARIO] waiting one stream tick + buffer..."
sleep 6

echo "[$SCENARIO] trusted IP must bypass the bouncer even though it is banned"
assert_status http://localhost:8000/foo 200 -H "X-Forwarded-For: 1.2.3.4"

echo "[$SCENARIO] untrusted banned IP must be blocked (control: proves the bouncer is active)"
assert_status http://localhost:8000/foo 403 -H "X-Forwarded-For: 5.6.7.8"

echo "[$SCENARIO] OK"
