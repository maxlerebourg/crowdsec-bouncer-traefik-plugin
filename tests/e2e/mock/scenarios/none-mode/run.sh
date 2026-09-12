#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=none-mode

body() {
  echo "[$SCENARIO] no decision -> request passes (LAPI queried per request)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] adding ban decision for 1.2.3.4 and 2001:db8::1"
  lapi_add_decision 1.2.3.4 ban 5m
  lapi_add_decision "2001:db8::1" ban 5m

  echo "[$SCENARIO] IP banned must be blocked (HTTP 403)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 403 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] IPv6 banned must be blocked (HTTP 403)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 403 -H "X-Forwarded-For: 2001:db8::1"

  echo "[$SCENARIO] deleting decision"
  lapi_delete_decision 1.2.3.4
  lapi_delete_decision "2001:db8::1"

  echo "[$SCENARIO] previously banned IP must pass again"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] previously banned IPv6 must pass again"
  wait_for_status "http://127.0.0.1:${WEB_PORT}/foo" 200 15 -H "X-Forwarded-For: 2001:db8::1"
}

run_scenario "$SCENARIO" "$HERE" body
