#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=captcha-ban-origins

# captchaBanOrigins: ["CAPI", "lists"] — a *ban* from those origins must be
# served the captcha remediation, while bans from any other origin stay bans.
body() {
  echo "[$SCENARIO] ban from a listed origin (CAPI) must render the captcha page"
  lapi_add_decision 1.2.3.4 ban 5m CAPI
  wait_for_body_contains "http://127.0.0.1:${WEB_PORT}/foo" "E2E_CAPTCHA_PAGE_MARKER" 15 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] ... and it is HTTP 200 (the captcha page), not the 403 ban page"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] ban from the other listed origin (lists) also renders the captcha page"
  lapi_add_decision 1.2.3.5 ban 5m lists
  wait_for_body_contains "http://127.0.0.1:${WEB_PORT}/foo" "E2E_CAPTCHA_PAGE_MARKER" 15 -H "X-Forwarded-For: 1.2.3.5"

  echo "[$SCENARIO] ban from an UNLISTED origin (cscli) must stay a 403 ban"
  lapi_add_decision 1.2.3.6 ban 5m cscli
  wait_for_status "http://127.0.0.1:${WEB_PORT}/foo" 403 15 -H "X-Forwarded-For: 1.2.3.6"

  echo "[$SCENARIO] ban from a local scenario (crowdsec) must stay a 403 ban"
  lapi_add_decision 1.2.3.7 ban 5m crowdsec
  wait_for_status "http://127.0.0.1:${WEB_PORT}/foo" 403 15 -H "X-Forwarded-For: 1.2.3.7"

  echo "[$SCENARIO] a captcha decision is unaffected by the mapping"
  lapi_add_decision 1.2.3.8 captcha 5m crowdsec
  wait_for_body_contains "http://127.0.0.1:${WEB_PORT}/foo" "E2E_CAPTCHA_PAGE_MARKER" 15 -H "X-Forwarded-For: 1.2.3.8"

  echo "[$SCENARIO] an IP with no decision still passes through to the backend"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 5.6.7.8"
}

run_scenario "$SCENARIO" "$HERE" body
