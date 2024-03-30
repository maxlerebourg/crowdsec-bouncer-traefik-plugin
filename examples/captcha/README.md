# Example
## Enabling catpcha response from crowdsec

FIXME

The Traefik instance just needs to know where appsec engine is located
```yaml
  labels:
      
      - "traefik.http.middlewares.crowdsec-bar.plugin.bouncer.crowdsecappsecenabled=true"
      - "traefik.http.middlewares.crowdsec-bar.plugin.bouncer.crowdsecappsechost=crowdsec:7422"
```
We can try to query normally the whoami server:
```bash
curl http://localhost:8000/foo
```

And then we verify that a malicious request will be blocked: 
```bash
curl http://localhost:8000/foo/rpc2
```
You should get a 403 on http://localhost:8000/foo/rpc2

To play the demo environment run:
```bash
make run_captcha
```
