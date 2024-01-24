# Example
## Enabling AppSec WAF feature from crowdsec

You mostly need to configure Crowdsec for this to work by enabling virtual patching and configuring some custom rules.
In the example we use a whoami container protected by crowdsec with virtual patching enabled.

The Traefik instance just needs to know where appsec engine is located
```yaml
  labels:
      
      - "traefik.http.middlewares.crowdsec-bar.plugin.bouncer.crowdsecappsecenabled=true"
      - "traefik.http.middlewares.crowdsec-bar.plugin.bouncer.crowdsecappsechost=crowdsec:7422"
```
We can try to query normally the whoami server:

Add your IP to the ban list
```bash
docker exec crowdsec cscli decisions add --ip 10.0.10.30 -d 10m
```
You should get a 403 on http://localhost/foo/rpc2 but http://localhost/foo should respond with a normal 200.


To play the demo environment run:
```bash
make run_appsec
```
