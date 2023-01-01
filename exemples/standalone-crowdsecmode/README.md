#### Generate CAPI credentials (only for `alone` mode)
You need to create a crowdsec API credentials for the CAPI.
You can follow the documentation here: https://docs.crowdsec.net/docs/central_api/intro

```bash
curl -X POST "https://api.crowdsec.net/v2/watchers" -H  "accept: application/json" -H  "Content-Type: application/json" -d "{ \"password\": \"PASSWORD\",  \"machine_id\": \"LOGIN\"}"
```

These CAPI credentials must be set in your docker-compose.yml or in your config files
```yaml
...
traefik:
  command:
    ...
    - "--experimental.plugins.bouncer.modulename=github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin"
    - "--experimental.plugins.bouncer.version=v1.0.0"
    ...
whoami:
  labels:
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.crowdseccapilogin=LOGIN"
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.crowdseccapipwd=PASSWORD"
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.crowdseccapiscenarios=scenario1, scenario2, ..."
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.enabled=true"
```

You can then run all the containers:
```bash
docker-compose up -d
```