# End-to-end test suite

These tests spin up real Traefik + Crowdsec containers and exercise the
plugin in the same conditions Traefik uses in production: loaded from a
local path, no module download, no mocking.

Each scenario lives in its own directory under `scenarios/` and owns:

- `docker-compose.yml` — the stack to spin up
- `run.sh` — orchestration + assertions
- optional fixtures (`acquis.yaml`, `ban.html`, ...)

## Running locally

Prerequisites: `docker`, `docker compose`, `curl`, `bash`.

Run a single scenario:

```bash
./tests/e2e/scenarios/stream-mode/run.sh
# or
make e2e_stream-mode
```

Run everything:

```bash
make e2e
```

Scenarios run **sequentially** on a single host: they share the canonical
`crowdsec` container name (so `cscli` commands work uniformly) and the same
`8000:80` port. Each scenario uses its own Docker Compose project
(`-p e2e-<scenario>`) and tears its stack down on exit, so the next one
starts clean. `make e2e` runs them one after another; Docker reuses the
images pulled by the first scenario, so the Traefik / Crowdsec / whoami
images are downloaded only once for the whole suite.

## Writing a new scenario

1. Copy `scenarios/stream-mode/` as a template.
2. Rename `container_name`s (keep `crowdsec` for the LAPI container).
3. Edit `run.sh` to express the behavior under test.
4. Add the scenario name to `E2E_SCENARIOS` in the `Makefile`.

## CI

This Docker suite is **local-only** and intentionally not run in CI: it boots a
real Crowdsec (and downloads the AppSec collections for that scenario), which is
heavier and less deterministic than CI needs. CI instead runs a lighter
binary + mock-LAPI suite that exercises the plugin without Docker or a real
Crowdsec.

Run this suite locally with `make e2e` (all scenarios) or
`make e2e_<scenario>` (one scenario).
