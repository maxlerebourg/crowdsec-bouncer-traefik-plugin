#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=captcha

body() {
  echo "[$SCENARIO] adding captcha decision for 1.2.3.4"
  lapi_add_decision 1.2.3.4 captcha 5m
  lapi_add_decision 1.2.3.5 captcha 5m

  # Status stays 200 before/after (captcha page vs backend), so gate on the body
  # marker appearing once the captcha decision has been polled.
  echo "[$SCENARIO] captcha page must be served once the decision is polled (200 + marker)"
  wait_for_body_contains "http://127.0.0.1:${WEB_PORT}/foo" "E2E_CAPTCHA_PAGE_MARKER" 15 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] captcha response Content-Type is HTML"
  assert_header "http://127.0.0.1:${WEB_PORT}/foo" Content-Type "text/html; charset=utf-8" -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] captcha page is rendered with the configured custom provider"
  assert_body_contains "http://127.0.0.1:${WEB_PORT}/foo" "http://test.com" -H "X-Forwarded-For: 1.2.3.4"
  assert_body_contains "http://127.0.0.1:${WEB_PORT}/foo" 'class="captcha-response"' -H "X-Forwarded-For: 1.2.3.4"
  assert_body_contains "http://127.0.0.1:${WEB_PORT}/foo" 'data-sitekey="1x00000000000000000000AA"' -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] captcha response is HTTP 200 (the captcha page itself, not a 403)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] non-flagged IP must still pass through to the backend"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 5.6.7.8"

  echo "[$SCENARIO] rejected captcha response must re-serve the page (200 + marker)"
  assert_body_contains "http://127.0.0.1:${WEB_PORT}/foo" "E2E_CAPTCHA_PAGE_MARKER" -H "X-Forwarded-For: 1.2.3.4" -X POST -d "response-captcha=ko"

  echo "[$SCENARIO] valid captcha response must solve the challenge (302 to the same URL)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 302 -H "X-Forwarded-For: 1.2.3.4" -X POST -d "response-captcha=ok"

  echo "[$SCENARIO] captcha submitted again after being solved must still redirect even if wrong"
  assert_header "http://127.0.0.1:${WEB_PORT}/foo" Location "/foo" -H "X-Forwarded-For: 1.2.3.4" -X POST -d "response-captcha=ko"

  echo "[$SCENARIO] solved captcha must pass through to the backend"
  assert_body_contains "http://127.0.0.1:${WEB_PORT}/foo" "E2E_BACKEND_OK" -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] solved captcha for user must not pass through for another user"
  assert_body_contains "http://127.0.0.1:${WEB_PORT}/foo" "E2E_CAPTCHA_PAGE_MARKER" -H "X-Forwarded-For: 1.2.3.5"
}

run_scenario "$SCENARIO" "$HERE" body
