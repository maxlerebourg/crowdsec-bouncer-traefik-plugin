#### Generate CAPI credentials (only for `alone` mode)
You need to create a crowdsec API credentials for the CAPI.
You can follow the documentation here: https://docs.crowdsec.net/docs/central_api/intro

```bash
curl -X POST "https://api.crowdsec.net/v2/watchers" -H  "accept: application/json" -H  "Content-Type: application/json" -d "{ \"password\": \"PASSWORD\",  \"machine_id\": \"LOGIN\"}"
```

These CAPI credentials must be set in your docker-compose.yml or in your config files
```yaml
...
whoami:
  labels:
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.enabled=true"
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.crowdsecMode=alone"
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.crowdsecCapiMachineId=LOGIN"
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.crowdsecCapiPassword=PASSWORD"
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.crowdsecCapiScenarios=crowdsecurity/http-generic-bf,crowdsecurity/http-xss-probing,..."
```

You can then run all the containers:
```bash
docker-compose up -d
```