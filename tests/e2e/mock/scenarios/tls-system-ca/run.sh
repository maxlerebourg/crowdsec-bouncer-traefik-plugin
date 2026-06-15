#!/usr/bin/env bash
# Scenario: HTTPS LAPI with no custom CA configured -> the bouncer must fall back
# to the OS/system trust store (PR #331). In the binary suite the "system trust
# store" is whatever Go's x509.SystemCertPool() reads, which honours SSL_CERT_FILE
# on the Traefik process. We mint a throwaway CA, serve the mock LAPI over HTTPS
# with a cert signed by it, and run the stack twice:
#
#   positive: SSL_CERT_FILE = our CA      -> LAPI trusted        -> 200
#   negative: SSL_CERT_FILE = empty bundle -> LAPI not trusted    -> 403
#
# live mode is fail-closed, so a TLS error becomes a 403. The negative run proves
# the patch still VERIFIES (it is not an insecure skip).
#
# Extra dependency vs other scenarios: openssl.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=tls-system-ca
SCENARIO_NAME="$SCENARIO"
SCENARIO_LOG="/tmp/e2e-mock-${SCENARIO}.log"
CERT_DIR="$(mktemp -d)"

cleanup() {
  local rc=$?
  if (( rc != 0 )); then
    dump_diagnostics > "$SCENARIO_LOG" 2>&1 || true
    echo "[$SCENARIO] failed. Logs written to $SCENARIO_LOG" >&2
  fi
  stop_stack
  rm -rf "$CERT_DIR"
  exit $rc
}
trap cleanup EXIT

echo "[$SCENARIO] minting throwaway CA + LAPI cert (SAN=IP:127.0.0.1)..."
openssl ecparam -name prime256v1 -genkey -noout -out "$CERT_DIR/ca.key" 2>/dev/null
openssl req -x509 -new -key "$CERT_DIR/ca.key" -sha256 -days 3650 \
  -subj "/CN=crowdsec-bouncer e2e test CA" -out "$CERT_DIR/ca.crt" 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "$CERT_DIR/lapi.key" 2>/dev/null
openssl req -new -key "$CERT_DIR/lapi.key" -subj "/CN=lapi" -out "$CERT_DIR/lapi.csr" 2>/dev/null
openssl x509 -req -in "$CERT_DIR/lapi.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
  -CAcreateserial -days 3650 -sha256 -out "$CERT_DIR/lapi.crt" \
  -extfile <(printf "subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth") 2>/dev/null
: > "$CERT_DIR/empty.crt" # an empty bundle = a system store that trusts nothing

# The mock serves the same CA-signed cert in both runs; only Traefik's trust differs.
export LAPI_TLS_CERT="$CERT_DIR/lapi.crt" LAPI_TLS_KEY="$CERT_DIR/lapi.key"

echo "[$SCENARIO] === positive: CA in the system trust store ==="
export TRAEFIK_SSL_CERT_FILE="$CERT_DIR/ca.crt"
start_stack "$HERE"
echo "[$SCENARIO] HTTPS LAPI verifies via system trust store -> request passes (200)"
assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4"
stop_stack

echo "[$SCENARIO] === negative: CA absent from the system trust store ==="
export TRAEFIK_SSL_CERT_FILE="$CERT_DIR/empty.crt"
start_stack "$HERE"
echo "[$SCENARIO] LAPI cert not trusted -> TLS fails, fail-closed (403)"
assert_status "http://127.0.0.1:${WEB_PORT}/foo" 403 -H "X-Forwarded-For: 1.2.3.4"
stop_stack

echo "[$SCENARIO] OK"
