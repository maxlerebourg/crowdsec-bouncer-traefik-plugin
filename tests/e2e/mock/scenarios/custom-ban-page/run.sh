#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=custom-ban-page

body() {
  echo "[$SCENARIO] adding ban decision"
  lapi_add_decision 1.2.3.4 ban 5m

  echo "[$SCENARIO] waiting one stream tick + buffer..."
  sleep 4

  echo "[$SCENARIO] banned response status is 403"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 403 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] banned response Content-Type is HTML"
  assert_header "http://127.0.0.1:${WEB_PORT}/foo" Content-Type "text/html; charset=utf-8" -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] banned response body contains the custom marker"
  assert_body_contains "http://127.0.0.1:${WEB_PORT}/foo" "E2E_CUSTOM_BAN_PAGE_MARKER" -H "X-Forwarded-For: 1.2.3.4"
}

run_scenario "$SCENARIO" "$HERE" body
