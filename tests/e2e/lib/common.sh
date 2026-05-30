#!/usr/bin/env bash
# Shared helpers for end-to-end scenarios.
# Dependencies: bash, curl, docker.

# Wait until the Crowdsec LAPI reports ready, or fail after timeout.
# Usage: wait_crowdsec_ready [container_name] [timeout_seconds]
wait_crowdsec_ready() {
  local container="${1:-crowdsec}"
  local timeout="${2:-90}"
  local elapsed=0
  while (( elapsed < timeout )); do
    if docker exec "$container" cscli lapi status >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
    ((elapsed++))
  done
  echo "wait_crowdsec_ready: timed out after ${timeout}s waiting for $container" >&2
  return 1
}

# Poll URL until it returns the expected status code, or fail.
# Usage: wait_for_status URL CODE [TIMEOUT_SECONDS] [curl args...]
wait_for_status() {
  local url="$1" expected="$2" timeout="${3:-30}"
  shift 3 || true
  local elapsed=0
  local got=""
  while (( elapsed < timeout )); do
    got=$(curl -s -o /dev/null -w '%{http_code}' "$@" "$url" || true)
    if [[ "$got" == "$expected" ]]; then
      return 0
    fi
    sleep 1
    ((elapsed++))
  done
  echo "wait_for_status: $url expected $expected, last seen ${got:-<none>}" >&2
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

# Dump diagnostic info for a compose project; called on failure.
# Usage: dump_diagnostics PROJECT COMPOSE_FILE
dump_diagnostics() {
  local project="$1" compose_file="$2"
  echo "=== docker compose ps ==="
  docker compose -p "$project" -f "$compose_file" ps || true
  echo "=== docker compose logs ==="
  docker compose -p "$project" -f "$compose_file" logs --no-color || true
  echo "=== cscli decisions list ==="
  docker exec crowdsec cscli decisions list 2>/dev/null || true
}
