# Example
## Using Crowdsec and Traefik in Nomad

[traefik-crowdsec.nomad.hcl](traefik-crowdsec.nomad.hcl) is a single Nomad job with three tasks:

- `whoami`, the backend, registered as a Nomad service;
- `traefik`, which discovers it with the Nomad provider and runs the bouncer on its `web` entrypoint (port 8000);
- `crowdsec`, which serves the LAPI and AppSec, and reads Traefik's access logs.

CrowdSec runs as a sidecar of Traefik, in the same group, so that it can read Traefik's logs from the
allocation directory (`/alloc/logs/traefik.stdout.*`). A prestart task waits for the LAPI before Traefik starts.

The bouncer key is stored in a Nomad variable that only this job's workload identity can read. CrowdSec
registers the bouncer with it (`BOUNCER_KEY_traefik`), and the plugin reads it with `crowdsecLapiKeyFile`.

### Requirements

- Nomad 1.5 or later, with the Docker driver (tested with Nomad 2.1). `nomad agent -dev` is enough to try it.
- ACLs can be on or off. Traefik reaches the Nomad API through the task API socket with the job's workload
  identity, which can read the job's own variables and the Nomad services in its namespace.

### Run it

Create the bouncer key, then the job:
```bash
nomad var put nomad/jobs/traefik-crowdsec bouncer_key=$(openssl rand -hex 32)
nomad job run examples/nomad/traefik-crowdsec.nomad.hcl
```

We can query the whoami service normally:
```bash
curl http://localhost:8000/foo
```

A malicious request is blocked by AppSec:
```bash
curl http://localhost:8000/.env
```
You should get a 403.

Then ban your IP (`127.0.0.1` from the node itself). The plugin runs in stream mode, so the ban applies
within a minute:
```bash
nomad job allocs traefik-crowdsec
nomad alloc exec -task crowdsec <allocation of the traefik group> cscli decisions add --ip 127.0.0.1
curl http://localhost:8000/foo
```

The Traefik dashboard listens on `127.0.0.1:8080` on the node.

### Notes

- `force_inotify: true` makes CrowdSec watch `/alloc/logs` from the start. Without it, CrowdSec only follows
  Traefik's log if the file already exists when CrowdSec loads its acquisition, which races with Traefik's
  start: the prestart task only waits for the LAPI.
- The sticky `ephemeral_disk` keeps the CrowdSec database (`/alloc/data/crowdsec`) when the allocation is
  replaced on the same node. Use a host volume or a CSI volume to keep it anywhere else.
- In a namespace other than `default`, add `--providers.nomad.namespaces=<namespace>` to Traefik.
