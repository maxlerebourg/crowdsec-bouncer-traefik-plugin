#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=stream-mode

body() {
  echo "[$SCENARIO] no decision yet -> request allowed"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] adding ban decision for 1.2.3.4"
  lapi_add_decision 1.2.3.4 ban 5m

  echo "[$SCENARIO] waiting one stream tick + buffer..."
  sleep 4

  echo "[$SCENARIO] banned IP must be blocked (HTTP 403)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 403 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] non-banned IP must still pass (HTTP 200)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 5.6.7.8"

  echo "[$SCENARIO] deleting ban decision"
  lapi_delete_decision 1.2.3.4

  echo "[$SCENARIO] waiting one stream tick + buffer..."
  sleep 4

  echo "[$SCENARIO] previously banned IP must pass again"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4"
}

run_scenario "$SCENARIO" "$HERE" body
