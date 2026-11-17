#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=none-mode

body() {
  echo "[$SCENARIO] no decision -> request passes (LAPI queried per request)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] adding ban decision for 1.2.3.4"
  lapi_add_decision 1.2.3.4 ban 5m

  echo "[$SCENARIO] none mode has no cache -> next request must be blocked immediately"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 429 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] the ban must carry the seconds left on its decision as Retry-After"
  assert_header_between "http://127.0.0.1:${WEB_PORT}/foo" Retry-After 299 300 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] deleting decision"
  lapi_delete_decision 1.2.3.4

  echo "[$SCENARIO] previously banned IP must pass again immediately"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4"
}

run_scenario "$SCENARIO" "$HERE" body
