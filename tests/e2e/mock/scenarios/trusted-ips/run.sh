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

  echo "[$SCENARIO] waiting one stream tick + buffer..."
  sleep 4

  echo "[$SCENARIO] trusted IP must bypass the bouncer even though it is banned"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] untrusted banned IP must be blocked (control: proves the bouncer is active)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 403 -H "X-Forwarded-For: 5.6.7.8"
}

run_scenario "$SCENARIO" "$HERE" body
