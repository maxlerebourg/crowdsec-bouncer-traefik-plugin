#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=forwarded-headers
CLIENT=127.0.0.2
PROXY=127.0.0.3

body() {
  if ! curl -s -o /dev/null --interface "$CLIENT" "http://127.0.0.1:${WEB_PORT}/ping"; then
    echo "[$SCENARIO] skipped: this host cannot send from $CLIENT"
    return 0
  fi

  echo "[$SCENARIO] banning the client $CLIENT and the forwarded IP 5.6.7.8"
  lapi_add_decision "$CLIENT" ban 5m
  lapi_add_decision 5.6.7.8 ban 5m

  echo "[$SCENARIO] banned client without header must be blocked"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 403 --interface "$CLIENT"

  echo "[$SCENARIO] banned client forging the header from an untrusted address must still be blocked"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 403 --interface "$CLIENT" -H "Cf-Connecting-Ip: 1.2.3.4"

  echo "[$SCENARIO] trusted proxy forwarding a banned IP must be blocked"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 403 --interface "$PROXY" -H "Cf-Connecting-Ip: 5.6.7.8"

  echo "[$SCENARIO] trusted proxy forwarding a clean IP must pass"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 --interface "$PROXY" -H "Cf-Connecting-Ip: 1.2.3.4"

  echo "[$SCENARIO] without forwardedHeadersTrustedIps the header is still read from any peer"
  assert_status "http://127.0.0.1:${WEB_PORT}/legacy" 403 --interface "$PROXY" -H "X-Forwarded-For: 5.6.7.8"
  assert_status "http://127.0.0.1:${WEB_PORT}/legacy" 200 --interface "$PROXY" -H "X-Forwarded-For: 1.2.3.4"
}

run_scenario "$SCENARIO" "$HERE" body
