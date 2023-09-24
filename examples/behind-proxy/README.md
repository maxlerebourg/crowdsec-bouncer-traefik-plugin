# example
## Behind another proxy service (ex: clouflare)

You need to configure your Traefik to trust Forwarded headers by your front proxy
In the example we use another instance of traefik with the container named cloudflare to simulate a front proxy

The "internal" Traefik instance is configured to trust the cloudflare forward headers
This helps Traefik choose the right IP of the client: see https://doc.traefik.io/traefik/routing/entrypoints/#forwarded-headers
```yaml
  - "--entrypoints.web.forwardedheaders.trustedips=172.21.0.5"
```

We configure the middleware to trust as well the IP:
```yaml
    - "traefik.http.middlewares.crowdsec1.plugin.bouncer.forwardedheaderstrustedips=172.21.0.5"
```

To play the demo environment run:
```bash
make run_behindproxy
```
