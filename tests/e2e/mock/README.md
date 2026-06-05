# Binary e2e suite (Traefik binary + mock LAPI)

This suite runs **Traefik as a downloaded binary** with the plugin loaded from
the local source tree, and replaces Crowdsec with a small **HTTP mock**
([`mocklapi/`](mocklapi/main.go), a stdlib-only Go command). No Docker, no real
Crowdsec.

It is what **CI runs** (`make e2e_mock`). The Docker suite in
[`../scenarios`](../scenarios) is kept for local debugging against a real
Crowdsec, but is not exercised in CI.

## Scope — what this suite does and does NOT test

These tests validate the **plugin's own behaviour**: the request flow through
the Traefik middleware, the live / none / stream modes, caching, trusted-IP
bypass, and ban / captcha page rendering.

They deliberately **do not** test that Crowdsec or its AppSec engine work
correctly — that is validated and owned by the upstream maintainer
([@maxlerebourg](https://github.com/maxlerebourg)), not by this plugin. The
mock only emulates the slice of the LAPI HTTP contract the plugin consumes.

So please **don't open issues here about Crowdsec/AppSec detection accuracy**
based on this suite: the AppSec scenario is intentionally absent, and the mock
returns whatever decisions the test tells it to.

## What runs

| Component | How |
|-----------|-----|
| Traefik   | Binary `v3.7.1`, downloaded once and cached under `.cache/` |
| Plugin    | Loaded via `experimental.localPlugins` from the repo root (symlinked into `plugins-local/`) |
| LAPI      | `mocklapi` — a stdlib-only Go command (its own nested module), compiled and cached under `.cache/`, driven through `/admin` endpoints instead of `cscli` |
| Backend   | A plain HTTP responder built into the mock |

Fixed ports (override with env vars if needed): Traefik `8000`, LAPI `8090`,
backend `8091`.

## Running locally

Prerequisites: `bash`, `curl`, `go`, `tar`. The Traefik binary is fetched and
the mock is compiled automatically on first run (both cached under `.cache/`).

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
    main.go       # mock LAPI + backend
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
3. Drive decisions with `lapi_add_decision <ip> [type] [duration]`,
   `lapi_delete_decision <ip>`, `lapi_reset`.
4. Add `<name>` to `E2E_MOCK_SCENARIOS` in the `Makefile`.
