#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=captcha

body() {
  echo "[$SCENARIO] adding captcha decision for 1.2.3.4"
  lapi_add_decision 1.2.3.4 captcha 5m

  # Status stays 200 before/after (captcha page vs backend), so gate on the body
  # marker appearing once the captcha decision has been polled.
  echo "[$SCENARIO] captcha page must be served once the decision is polled (200 + marker)"
  wait_for_body_contains "http://127.0.0.1:${WEB_PORT}/foo" "E2E_CAPTCHA_PAGE_MARKER" 15 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] captcha response is HTTP 200 (the captcha page itself, not a 403)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] non-flagged IP must still pass through to the backend"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 5.6.7.8"
}

run_scenario "$SCENARIO" "$HERE" body
