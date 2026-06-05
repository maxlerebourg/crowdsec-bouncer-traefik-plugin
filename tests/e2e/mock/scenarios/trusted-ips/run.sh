#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=trusted-ips

body() {
  echo "[$SCENARIO] banning the trusted IP 1.2.3.4 and an untrusted IP 5.6.7.8"
  lapi_add_decision 1.2.3.4 ban 5m
  lapi_add_decision 5.6.7.8 ban 5m

  # The untrusted IP turning 403 is our signal that the bans have been polled;
  # it also doubles as the control proving the bouncer is active.
  echo "[$SCENARIO] untrusted banned IP must be blocked once the bans are polled (HTTP 403)"
  wait_for_status "http://127.0.0.1:${WEB_PORT}/foo" 403 15 -H "X-Forwarded-For: 5.6.7.8"

  echo "[$SCENARIO] trusted IP must bypass the bouncer even though it is banned"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4"
}

run_scenario "$SCENARIO" "$HERE" body
