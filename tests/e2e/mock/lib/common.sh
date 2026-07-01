#!/usr/bin/env bash
# Shared helpers for the binary (mock) e2e suite.
#
# Unlike the Docker suite under tests/e2e/scenarios, this one runs Traefik as a
# downloaded binary and replaces Crowdsec with a small HTTP mock (the mocklapi
# Go command). It validates the plugin's own behaviour (modes, cache, trusted
# IPs, ban / captcha rendering, AppSec wiring) — not the accuracy of Crowdsec's
# detection or its WAF engine, which the mock only stands in for.
#
# Dependencies: bash, curl, go, tar. The Traefik binary is downloaded and the
# mock is compiled into .cache/ on first use. That cache persists across local
# runs; CI runs on fresh runners, so both are recreated on every CI run.

set -euo pipefail

# Pinned to match the Docker suite (tests/e2e/scenarios/*/docker-compose.yml).
TRAEFIK_VERSION="${TRAEFIK_VERSION:-v3.7.1}"

WEB_PORT="${WEB_PORT:-8000}"
LAPI_PORT="${LAPI_PORT:-8090}"
BACKEND_PORT="${BACKEND_PORT:-8091}"
APPSEC_PORT="${APPSEC_PORT:-8092}"
LAPI_KEY="${LAPI_KEY:-e2e-mock-key}"

MOCK_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$MOCK_LIB_DIR/../../../.." && pwd)"
CACHE_DIR="$MOCK_LIB_DIR/../.cache"

# Populated by start_stack / run_scenario, consumed by the EXIT trap.
WORKDIR=""
TRAEFIK_PID=""
MOCK_PID=""
SCENARIO_NAME=""
SCENARIO_LOG=""

# Resolve (and cache) the Traefik binary for this host, echoing its path.
ensure_traefik() {
  local bin="$CACHE_DIR/traefik-$TRAEFIK_VERSION"
  if [[ -x "$bin" ]]; then
    echo "$bin"
    return 0
  fi
  mkdir -p "$CACHE_DIR"
  local os arch
  case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
    *) echo "ensure_traefik: unsupported OS $(uname -s)" >&2; return 1 ;;
  esac
  case "$(uname -m)" in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) echo "ensure_traefik: unsupported arch $(uname -m)" >&2; return 1 ;;
  esac
  local url="https://github.com/traefik/traefik/releases/download/${TRAEFIK_VERSION}/traefik_${TRAEFIK_VERSION}_${os}_${arch}.tar.gz"
  echo "ensure_traefik: downloading $url" >&2
  local tmp
  tmp="$(mktemp -d)"
  curl -sSfL "$url" -o "$tmp/traefik.tar.gz"
  tar -xzf "$tmp/traefik.tar.gz" -C "$tmp" traefik
  mv "$tmp/traefik" "$bin"
  chmod +x "$bin"
  rm -rf "$tmp"
  echo "$bin"
}

# Build (and cache) the mock LAPI binary, echoing its path. Go's build cache
# makes the rebuild near-instant after the first run.
ensure_mock() {
  local bin="$CACHE_DIR/mocklapi"
  mkdir -p "$CACHE_DIR"
  ( cd "$MOCK_LIB_DIR/../mocklapi" && go build -o "$bin" . ) >&2
  echo "$bin"
}

# Poll a URL until it returns the expected status code, or fail.
# Usage: wait_for_status URL CODE [TIMEOUT_SECONDS] [curl args...]
wait_for_status() {
  local url="$1" expected="$2" timeout="${3:-30}"
  shift 3 || true
  local elapsed=0 got=""
  while (( elapsed < timeout )); do
    got=$(curl -s -o /dev/null -w '%{http_code}' "$@" "$url" || true)
    if [[ "$got" == "$expected" ]]; then
      return 0
    fi
    sleep 1
    # Note: `((elapsed++))` returns exit 1 when elapsed is 0, which trips set -e.
    elapsed=$((elapsed + 1))
  done
  echo "wait_for_status: $url expected $expected, last seen ${got:-<none>}" >&2
  return 1
}

# Poll a URL until its body contains a substring, or fail. Used when the status
# code alone can't tell the states apart (e.g. captcha page vs backend, both 200).
# Usage: wait_for_body_contains URL NEEDLE [TIMEOUT_SECONDS] [curl args...]
wait_for_body_contains() {
  local url="$1" needle="$2" timeout="${3:-30}"
  shift 3 || true
  local elapsed=0 body=""
  while (( elapsed < timeout )); do
    body=$(curl -s "$@" "$url" || true)
    if grep -q "$needle" <<<"$body"; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  echo "wait_for_body_contains: $url did not contain \"$needle\" within ${timeout}s" >&2
  return 1
}

# Assert a single curl returns the expected status code.
# Usage: assert_status URL CODE [curl args...]
assert_status() {
  local url="$1" expected="$2"
  shift 2 || true
  local got
  got=$(curl -s -o /dev/null -w '%{http_code}' "$@" "$url")
  if [[ "$got" != "$expected" ]]; then
    echo "assert_status: $url expected $expected, got $got" >&2
    return 1
  fi
}

# Assert a response header matches a value (case-insensitive name).
# Usage: assert_header URL HEADER VALUE [curl args...]
assert_header() {
  local url="$1" header="$2" expected="$3"
  shift 3 || true
  local got
  got=$(curl -s -D - -o /dev/null "$@" "$url" | tr -d '\r' \
    | awk -v h="${header,,}" -F': ' 'tolower($1) == h { print $2; exit }')
  if [[ "$got" != "$expected" ]]; then
    echo "assert_header: $url header $header expected \"$expected\", got \"$got\"" >&2
    return 1
  fi
}

# Assert a response body contains a substring.
# Usage: assert_body_contains URL NEEDLE [curl args...]
assert_body_contains() {
  local url="$1" needle="$2"
  shift 2 || true
  local body
  body=$(curl -s "$@" "$url")
  if ! grep -q "$needle" <<<"$body"; then
    echo "assert_body_contains: $url expected to contain \"$needle\", got:" >&2
    echo "$body" >&2
    return 1
  fi
}

# --- mock admin client -------------------------------------------------------

lapi_add_decision() {
  local ip="$1" type="${2:-ban}" duration="${3:-4h}"
  curl -sS -X POST "http://127.0.0.1:${LAPI_PORT}/admin/decisions?ip=${ip}&type=${type}&duration=${duration}" >/dev/null
}

lapi_delete_decision() {
  local ip="$1"
  curl -sS -X DELETE "http://127.0.0.1:${LAPI_PORT}/admin/decisions?ip=${ip}" >/dev/null
}

# --- stack lifecycle ---------------------------------------------------------

# start_stack SCENARIO_DIR
# Spins up the mock + Traefik (with the scenario's dynamic.yml) and waits ready.
start_stack() {
  local scenario_dir="$1"
  local traefik_bin mock_bin
  traefik_bin="$(ensure_traefik)"
  mock_bin="$(ensure_mock)"

  WORKDIR="$(mktemp -d)"
  # Expose the plugin source where Traefik's localPlugins loader expects it.
  mkdir -p "$WORKDIR/plugins-local/src/github.com/maxlerebourg"
  ln -s "$REPO_ROOT" "$WORKDIR/plugins-local/src/github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin"

  cp "$MOCK_LIB_DIR/traefik.yml" "$WORKDIR/traefik.yml"

  # Render the scenario's dynamic config with the live ports / key / paths.
  sed \
    -e "s|@@APIKEY@@|${LAPI_KEY}|g" \
    -e "s|@@LAPI_HOST@@|127.0.0.1:${LAPI_PORT}|g" \
    -e "s|@@APPSEC_HOST@@|127.0.0.1:${APPSEC_PORT}|g" \
    -e "s|@@BACKEND_URL@@|http://127.0.0.1:${BACKEND_PORT}|g" \
    -e "s|@@SCENARIO_DIR@@|${scenario_dir}|g" \
    "$scenario_dir/dynamic.yml" > "$WORKDIR/dynamic.yml"

  # Opt-in HTTPS LAPI: a scenario exports LAPI_TLS_CERT/LAPI_TLS_KEY to serve the
  # LAPI over TLS (used by tls-system-ca). Default empty -> plaintext as before.
  local mock_tls_args=() lapi_scheme=http lapi_curl=()
  if [[ -n "${LAPI_TLS_CERT:-}" && -n "${LAPI_TLS_KEY:-}" ]]; then
    mock_tls_args=(--lapi-tls-cert "$LAPI_TLS_CERT" --lapi-tls-key "$LAPI_TLS_KEY")
    lapi_scheme=https
    lapi_curl=(-k) # the readiness probe ignores trust; the bouncer's trust is what we test
  fi

  "$mock_bin" \
    --lapi-addr "127.0.0.1:${LAPI_PORT}" \
    --backend-addr "127.0.0.1:${BACKEND_PORT}" \
    --appsec-addr "127.0.0.1:${APPSEC_PORT}" \
    "${mock_tls_args[@]}" >"$WORKDIR/mock.log" 2>&1 &
  MOCK_PID=$!

  # Opt-in trust store for the Traefik process: a scenario exports
  # TRAEFIK_SSL_CERT_FILE to point Go's x509.SystemCertPool() at a specific CA
  # bundle. Empty -> Go's default system store (unchanged behaviour).
  ( cd "$WORKDIR" && SSL_CERT_FILE="${TRAEFIK_SSL_CERT_FILE:-}" exec "$traefik_bin" --configfile=traefik.yml ) >"$WORKDIR/traefik.log" 2>&1 &
  TRAEFIK_PID=$!

  wait_for_status "${lapi_scheme}://127.0.0.1:${LAPI_PORT}/health" 200 30 "${lapi_curl[@]}"
  # AppSec stand-in: a bare GET carries no "rpc2" URI, so it answers 200 (allow).
  wait_for_status "http://127.0.0.1:${APPSEC_PORT}/" 200 30
  # /ping is served by Traefik itself once it is up (plugin compilation included).
  wait_for_status "http://127.0.0.1:${WEB_PORT}/ping" 200 60
}

stop_stack() {
  [[ -n "$TRAEFIK_PID" ]] && kill "$TRAEFIK_PID" 2>/dev/null || true
  [[ -n "$MOCK_PID" ]] && kill "$MOCK_PID" 2>/dev/null || true
  [[ -n "$TRAEFIK_PID" ]] && wait "$TRAEFIK_PID" 2>/dev/null || true
  [[ -n "$MOCK_PID" ]] && wait "$MOCK_PID" 2>/dev/null || true
  [[ -n "$WORKDIR" && -d "$WORKDIR" ]] && rm -rf "$WORKDIR" || true
}

dump_diagnostics() {
  echo "=== traefik.log ==="
  cat "$WORKDIR/traefik.log" 2>/dev/null || true
  echo "=== mock.log ==="
  cat "$WORKDIR/mock.log" 2>/dev/null || true
}

# EXIT trap: runs after the scenario body (or after a failed assertion under
# `set -e`), so it relies only on globals, never on run_scenario's locals.
_scenario_cleanup() {
  local rc=$?
  if (( rc != 0 )); then
    dump_diagnostics > "$SCENARIO_LOG" 2>&1 || true
    echo "[$SCENARIO_NAME] failed. Logs written to $SCENARIO_LOG" >&2
  fi
  stop_stack
  exit $rc
}

# run_scenario SCENARIO_NAME SCENARIO_DIR BODY_FN
# Wraps lifecycle + diagnostics so each run.sh stays declarative.
run_scenario() {
  SCENARIO_NAME="$1"
  local dir="$2" body="$3"
  SCENARIO_LOG="/tmp/e2e-mock-${SCENARIO_NAME}.log"
  trap _scenario_cleanup EXIT

  echo "[$SCENARIO_NAME] starting binary stack (Traefik + mock LAPI)..."
  start_stack "$dir"
  "$body"
  echo "[$SCENARIO_NAME] OK"
}
