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

We can try to ban ourself

```bash
docker exec crowdsec cscli decisions add --ip 10.0.0.10 -d 10m --type captcha
```

We will see in the browser the captcha validation page:

![alt text](image_captcha_validation.png)

To play the demo environment run:
```bash
make run_captcha
```
