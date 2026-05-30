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

Each scenario uses an isolated Docker Compose project (`-p e2e-<scenario>`),
so multiple scenarios can run in parallel without colliding on container
names — except for the `crowdsec` container, which keeps its canonical
name so `cscli` commands work uniformly across scenarios. Run scenarios
serially if you need to invoke them on the same host at the same time.

## Writing a new scenario

1. Copy `scenarios/stream-mode/` as a template.
2. Rename `container_name`s (keep `crowdsec` for the LAPI container).
3. Edit `run.sh` to express the behavior under test.
4. Add the scenario name to the `matrix` in `.github/workflows/e2e.yml`
   and to `E2E_SCENARIOS` in the `Makefile`.

## CI

`.github/workflows/e2e.yml` runs one parallel job per scenario on every
PR and push to `main`. On failure, container logs are uploaded as an
artifact named `logs-<scenario>`.
