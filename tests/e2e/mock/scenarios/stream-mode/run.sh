#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=stream-mode

body() {
  echo "[$SCENARIO] no decision yet -> request allowed"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] adding ban decision for 1.2.3.4 and 10.0.0.0/8"
  lapi_add_decision 1.2.3.4 ban 5m
  lapi_add_decision 10.0.0.0/24 ban 5m

  echo "[$SCENARIO] banned IP must be blocked once the next stream poll lands (HTTP 403)"
  wait_for_status "http://127.0.0.1:${WEB_PORT}/foo" 403 15 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] non-banned IP must still pass (HTTP 200)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 5.6.7.8"

  echo "[$SCENARIO] banned IP in CIDR must be blocked once polled (HTTP 403)"
  wait_for_status "http://127.0.0.1:${WEB_PORT}/foo" 403 15 -H "X-Forwarded-For: 10.0.0.1"

  echo "[$SCENARIO] deleting ban decision for 1.2.3.4 and 10.0.0.0/8"
  lapi_delete_decision 1.2.3.4
  lapi_delete_decision 10.0.0.0/24

  echo "[$SCENARIO] previously banned IP must pass again once the deletion is polled"
  wait_for_status "http://127.0.0.1:${WEB_PORT}/foo" 200 15 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] previously CIDR-banned IP must pass again once deletion is polled"
  wait_for_status "http://127.0.0.1:${WEB_PORT}/foo" 200 15 -H "X-Forwarded-For: 10.0.0.1"

  echo "[$SCENARIO] making the stream endpoint fail -> bouncer must pass for one more cycle (updateMaxFailure: 2)"
  lapi_set_stream_fail
  sleep 2 # update cache is every 1 seconds then waiting for minimum 1 cycle
  wait_for_status "http://127.0.0.1:${WEB_PORT}/foo" 200 15 -H "X-Forwarded-For: 8.8.8.8"

  echo "[$SCENARIO] bouncer must block everything (isStreamHealthy: false)"
  wait_for_status "http://127.0.0.1:${WEB_PORT}/foo" 403 15 -H "X-Forwarded-For: 8.8.8.8"

  echo "[$SCENARIO] restoring the stream endpoint -> bouncer must recover and pass again"
  lapi_clear_stream_fail
  wait_for_status "http://127.0.0.1:${WEB_PORT}/foo" 200 15 -H "X-Forwarded-For: 8.8.8.8"
}

run_scenario "$SCENARIO" "$HERE" body
