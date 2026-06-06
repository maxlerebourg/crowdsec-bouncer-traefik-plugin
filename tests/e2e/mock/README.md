# Binary e2e suite (Traefik binary + mock LAPI)

This suite runs **Traefik as a downloaded binary** with the plugin loaded from
the local source tree, and replaces Crowdsec with a small **HTTP mock**
([`mocklapi/`](mocklapi/main.go), a stdlib-only Go command). No Docker, no real
Crowdsec.

It is what **CI runs** (`make e2e_mock`). A separate, local-only **Docker
suite** (real Traefik + Crowdsec, under `tests/e2e/scenarios`) is kept for
high-fidelity debugging against a real Crowdsec but is not exercised in CI; it
ships in its own PR (#333).

## Scope — what this suite tests

These tests validate the **plugin's own behaviour**: the request flow through
the Traefik middleware, the live / none / stream modes, caching, trusted-IP
bypass, ban / captcha page rendering, and the AppSec request path (header
forwarding + enforcing the engine's allow/block verdict).

The mock stands in for Crowdsec, emulating the slice of the LAPI HTTP contract
the plugin consumes — including a single, deterministic AppSec rule (block any
URI containing `rpc2`, the probe from [`examples/appsec-enabled`](../../../examples/appsec-enabled)).
It is not the real WAF engine, so this suite exercises the plugin's AppSec
*wiring* rather than the detection accuracy of OWASP CRS / virtual patching —
that lives upstream in Crowdsec.

## What runs

| Component | How |
|-----------|-----|
| Traefik   | Binary `v3.7.1`, downloaded into `.cache/` (reused across local runs; re-downloaded on fresh CI runners) |
| Plugin    | Loaded via `experimental.localPlugins` from the repo root (symlinked into `plugins-local/`) |
| LAPI      | `mocklapi` — a stdlib-only Go command (its own nested module), compiled and cached under `.cache/`, driven through `/admin` endpoints instead of `cscli` |
| AppSec    | WAF stand-in built into the mock — blocks URIs containing `rpc2`, allows the rest |
| Backend   | A plain HTTP responder built into the mock |

Fixed ports (override with env vars if needed): Traefik `8000`, LAPI `8090`,
backend `8091`, AppSec `8092`.

## Running locally

Prerequisites: `bash`, `curl`, `go`, `tar`. On first use the Traefik binary is
fetched and the mock is compiled into `.cache/`. That cache is reused across
local runs; CI runs on fresh runners, so both are recreated on every CI run.

```bash
# one scenario
make e2e_mock_stream-mode
# or directly
./tests/e2e/mock/scenarios/stream-mode/run.sh

# the whole suite
make e2e_mock
```

## Layout

```
mock/
  lib/
    common.sh     # stack lifecycle, Traefik download, mock build, assertions, admin client
    traefik.yml   # static Traefik config (shared by all scenarios)
  mocklapi/
    go.mod        # nested module — kept out of the plugin's build/lint/vendor
    main.go       # mock LAPI + AppSec stand-in + backend
  scenarios/
    <name>/
      dynamic.yml # Traefik dynamic config (router + bouncer middleware + backend)
      run.sh      # assertions for the scenario
      *.html      # optional fixtures (ban / captcha templates)
```

`dynamic.yml` uses placeholders (`@@APIKEY@@`, `@@LAPI_HOST@@`,
`@@BACKEND_URL@@`, `@@SCENARIO_DIR@@`) that `common.sh` substitutes at runtime.

## Adding a scenario

1. Create `scenarios/<name>/dynamic.yml` and `run.sh` (copy `stream-mode/` as a
   template).
2. In `run.sh`, define a `body` function with the assertions and call
   `run_scenario "<name>" "$HERE" body`.
3. Drive decisions with `lapi_add_decision <ip> [type] [duration]` and
   `lapi_delete_decision <ip>`.
4. Add `<name>` to `E2E_MOCK_SCENARIOS` in the `Makefile`.
