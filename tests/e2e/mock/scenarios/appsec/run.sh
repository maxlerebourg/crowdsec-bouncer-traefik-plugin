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
  echo "[$SCENARIO] benign request must pass (AppSec allows)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] request whose URI contains 'rpc2' must be blocked (AppSec 403)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo/rpc2" 403 -H "X-Forwarded-For: 1.2.3.4"
}

run_scenario "$SCENARIO" "$HERE" body
