# End-to-end test suite

There are two suites:

- **`scenarios/` (this one)** — real Traefik + Crowdsec **Docker** containers.
  High fidelity, kept for **local debugging**. Run with `make e2e`.
- **[`mock/`](mock/README.md)** — Traefik **binary** + a **mock LAPI**, no
  Docker. This is what **CI runs** (`make e2e_mock`). It validates the
  plugin's own behaviour; Crowdsec / AppSec correctness is out of scope there
  (that is the upstream maintainer's responsibility).

The rest of this document covers the Docker suite.

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

This Docker suite is **not** run in CI — it is meant for local debugging.
`.github/workflows/e2e.yml` runs the [`mock/`](mock/README.md) suite
(`make -k e2e_mock`) instead, which needs neither Docker nor a real Crowdsec.
Run this suite locally with `make e2e` (or `make e2e_<scenario>`).
