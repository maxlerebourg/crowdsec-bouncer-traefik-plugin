# Exemple
## Using Trusted IP (ex: LAN OR VPN) that won't get filtered by crowdsec

You need to configure your Traefik to trust Forwarded headers by your front proxy
In the example we use a whoami container protected by crowdsec, and we ban our IP before allowing using TrustedIPs

If you are using another proxy in front, you need to add its IP in the trusted IP for the forwarded headers.
This helps Traefik choose the right IP of the client: see https://doc.traefik.io/traefik/routing/entrypoints/#forwarded-headers
The "internal" Traefik instance is configured to trust the forward headers
```yaml
  - "--entrypoints.web.forwardedheaders.trustedips=172.21.0.5"
```

We configure the middleware to trust as well as the IP of the intermediate proxy if needed:
```yaml
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.forwardedheaderstrustedips=172.21.0.5"
```

Add your IP to the ban list
```bash
docker exec crowdsec cscli decisions add --ip 10.0.10.30 -d 10m
```
You should get a 403 on http://localhost/foo

> Replace *10.0.10.30* by your IP

Add the IPs that will not be filtered by the plugin
```yaml
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.clientTrustedips=10.0.10.30/32"
```

> Replace *10.0.10.30/32* by your IP or IP range, so it's not getting checked against ban cache of crowdsec

You should get a 200 on http://localhost/foo even if you are on the ban cache

To play the demo environment run:
```bash
make run_trustedips
```