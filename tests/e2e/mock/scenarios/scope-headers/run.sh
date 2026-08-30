#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=scope-headers
URL="http://127.0.0.1:${WEB_PORT}/foo"

body() {
  echo "[$SCENARIO] no decision -> allowed"
  assert_status "$URL" 200 -H "X-Forwarded-For: 203.0.113.10"

  echo "[$SCENARIO] Country FR ban (header fr) -> 403"
  lapi_add_scope_decision Country FR ban 5m
  wait_for_status "$URL" 403 15 -H "X-Forwarded-For: 203.0.113.10" -H "CF-IPCountry: fr"

  echo "[$SCENARIO] Country placeholder XX does not match FR"
  assert_status "$URL" 200 -H "X-Forwarded-For: 203.0.113.10" -H "CF-IPCountry: XX"

  echo "[$SCENARIO] other country DE does not match FR"
  assert_status "$URL" 200 -H "X-Forwarded-For: 203.0.113.10" -H "CF-IPCountry: DE"

  echo "[$SCENARIO] delete Country FR -> allowed again"
  lapi_delete_scope_decision Country FR
  wait_for_status "$URL" 200 15 -H "X-Forwarded-For: 203.0.113.10" -H "CF-IPCountry: FR"

  echo "[$SCENARIO] AS 13335 ban (header AS13335) -> 403"
  lapi_add_scope_decision AS 13335 ban 5m
  wait_for_status "$URL" 403 15 -H "X-Forwarded-For: 203.0.113.10" -H "CF-ASN: AS13335"

  echo "[$SCENARIO] different ASN does not match"
  assert_status "$URL" 200 -H "X-Forwarded-For: 203.0.113.10" -H "CF-ASN: 15169"
  lapi_delete_scope_decision AS 13335

  echo "[$SCENARIO] username alice -> 403"
  lapi_add_scope_decision username alice ban 5m
  wait_for_status "$URL" 403 15 -H "X-Forwarded-For: 203.0.113.10" -H "X-User: alice"

  echo "[$SCENARIO] other username does not match"
  assert_status "$URL" 200 -H "X-Forwarded-For: 203.0.113.10" -H "X-User: bob"

  echo "[$SCENARIO] missing username header skips the scope"
  assert_status "$URL" 200 -H "X-Forwarded-For: 203.0.113.10"
  lapi_delete_scope_decision username alice

  echo "[$SCENARIO] Range 10.0.0.0/8 contains 10.1.2.3 -> 403"
  lapi_add_scope_decision Range 10.0.0.0/8 ban 5m
  wait_for_status "$URL" 403 15 -H "X-Forwarded-For: 10.1.2.3"

  echo "[$SCENARIO] IP outside the range still passes"
  assert_status "$URL" 200 -H "X-Forwarded-For: 203.0.113.10"
}

run_scenario "$SCENARIO" "$HERE" body
