### Kubernetes Example

This example deploys, with the official Helm charts:

- [Traefik](https://artifacthub.io/packages/helm/traefik/traefik) with the bouncer plugin, attached to a `whoami` service
- [CrowdSec](https://artifacthub.io/packages/helm/crowdsec/crowdsec): the Local API, an agent reading the Traefik access logs, and the AppSec component

Both charts are pinned. Each chart version ships the image it was written for, so do not set `image.tag` in the values: a CrowdSec image older than its chart makes the Local API fail on startup with `field auto_registration not found`.

Run all the commands from this directory.

#### Requirements

- [kubectl](https://kubernetes.io/docs/tasks/tools/#kubectl) and [Helm](https://helm.sh/docs/intro/install/)
- A cluster whose container runtime is containerd: [kind](https://kind.sigs.k8s.io/), k3s, k3d, `minikube start --container-runtime=containerd` and most managed clusters. If your nodes run Docker, set `container_runtime: docker` in `crowdsec/values.yml`, otherwise CrowdSec cannot parse the Traefik logs.

With kind:

```bash
kind create cluster
```

#### Create the bouncer key

The same key goes into two secrets, one per namespace. CrowdSec registers the `traefik` bouncer from `BOUNCER_KEY_traefik`, and Traefik mounts its copy as a file read by `crowdsecLapiKeyFile`, so the key never appears in the values or in the middleware.

```bash
kubectl create namespace crowdsec
kubectl create namespace traefik
BOUNCER_KEY=$(openssl rand -hex 32)
kubectl -n crowdsec create secret generic crowdsec-keys --from-literal=BOUNCER_KEY_traefik="$BOUNCER_KEY"
kubectl -n traefik create secret generic crowdsec-bouncer-key --from-literal=BOUNCER_KEY_traefik="$BOUNCER_KEY"
```

#### Install CrowdSec

```bash
helm repo add crowdsec https://crowdsecurity.github.io/helm-charts
helm repo update
helm upgrade --install crowdsec crowdsec/crowdsec --version 0.24.3 \
  --namespace crowdsec --values ./crowdsec/values.yml
kubectl -n crowdsec wait --for=condition=Available deployment --all --timeout=5m
```

#### Install Traefik

```bash
helm repo add traefik https://traefik.github.io/charts
helm repo update
helm upgrade --install traefik traefik/traefik --version 42.4.0 \
  --namespace traefik --values ./traefik/values.yml
kubectl -n traefik rollout status deployment/traefik
```

What `traefik/values.yml` sets:

- `experimental.plugins` downloads the plugin from the Traefik plugin catalog when Traefik starts.
- `volumes` mounts the `crowdsec-bouncer-key` secret in `/etc/traefik/crowdsec`.
- `accessLog` writes JSON access logs for the CrowdSec agent. It keeps the `User-Agent` header, which the `crowdsecurity/traefik` parser reads, and drops the others so that cookies and `Authorization` headers stay out of the logs.
- `externalTrafficPolicy: Local` keeps the client IP on the LoadBalancer service. With the default `Cluster` policy, nodes rewrite the source address and every request looks like it comes from a node. If Traefik sits behind another proxy or a CDN, see `ForwardedHeadersTrustedIPs` in the [main README](../../README.md).

#### Install the middleware and whoami

```bash
kubectl apply -f traefik/plugin.yml
kubectl apply -f whoami/
```

`whoami/whoami-ingress.yml` attaches the middleware with the `traefik.ingress.kubernetes.io/router.middlewares: traefik-bouncer@kubernetescrd` annotation. On an `IngressRoute`, list it under `middlewares` instead.

#### Test it

Forward the `web` entrypoint in another terminal:

```bash
kubectl -n traefik port-forward service/traefik 8000:80
```

Through the port-forward, Traefik sees every request as coming from `127.0.0.1`.

- `curl -i http://localhost:8000/` returns `200` from whoami.
- `curl -i http://localhost:8000/.env` returns `403`: AppSec blocks it with the `crowdsecurity/vpatch-env-access` rule.

Ban `127.0.0.1`, wait for the next stream update (60 seconds at most), and the first request returns `403`:

```bash
kubectl -n crowdsec exec deployment/crowdsec-lapi -- cscli decisions add --ip 127.0.0.1 --duration 5m
curl -i http://localhost:8000/
kubectl -n crowdsec exec deployment/crowdsec-lapi -- cscli decisions delete --ip 127.0.0.1
```

#### Useful commands

Check that the bouncer is connected, and that the agent parses the Traefik logs:

```bash
kubectl -n crowdsec exec deployment/crowdsec-lapi -- cscli bouncers list
kubectl -n crowdsec exec daemonset/crowdsec-agent -- cscli metrics show acquisition parsers
```

Read the Traefik logs:

```bash
kubectl -n traefik logs deployment/traefik -f
```

Open the Traefik dashboard at [localhost:8080/dashboard/](http://localhost:8080/dashboard/):

```bash
kubectl -n traefik port-forward deployment/traefik 8080:8080
```

Open a shell in the CrowdSec Local API container:

```bash
kubectl -n crowdsec exec -it deployment/crowdsec-lapi -- sh
```

Delete the kind cluster:

```bash
kind delete cluster
```
