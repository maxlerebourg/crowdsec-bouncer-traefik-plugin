#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=live-mode

body() {
  echo "[$SCENARIO] no decision -> first hit queries LAPI, returns 200, caches 'allowed' for 2s"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] adding ban decision for 1.2.3.4"
  lapi_add_decision 1.2.3.4 ban 5m

  # Stays 200 until the cached 'allowed' (defaultDecisionSeconds) expires, then
  # the re-query sees the ban — poll instead of guessing the cache TTL.
  echo "[$SCENARIO] hit must turn 403 once the cached 'allowed' expires and LAPI is re-queried"
  wait_for_status "http://127.0.0.1:${WEB_PORT}/foo" 403 15 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] another non-banned IP must still pass"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 5.6.7.8"
}

run_scenario "$SCENARIO" "$HERE" body
