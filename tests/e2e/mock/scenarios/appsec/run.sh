#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=appsec

# AppSec wiring check: the plugin forwards each request to the AppSec engine and
# enforces its verdict. The mock emulates one virtual-patching rule (block any
# URI containing "rpc2"), mirroring examples/appsec-enabled. This proves the
# plugin's AppSec path end to end (header forwarding + allow/block handling); it
# does not test the real WAF's detection accuracy.
body() {
  echo "[$SCENARIO] benign request must pass (AppSec 200)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] request that return 403 must be blocked (AppSec 403)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo/403" 403 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] request that return 500 must be blocked (because CrowdsecAppsecFailureBlock = true) (AppSec 500)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo/500" 403 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] request that return 502 must pass (because CrowdsecAppsecUnreachableBlock = false) (Proxy error 502)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo/502" 200 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] request that send bad body after crowdsecAppsecBodyLimit must pass (AppSec 200)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4" -X POST -d "______&a=0"

  echo "[$SCENARIO] request that send bad body before crowdsecAppsecBodyLimit must pass (AppSec 403)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 403 -H "X-Forwarded-For: 1.2.3.4" -X POST -d "a=0&______"
}

run_scenario "$SCENARIO" "$HERE" body
