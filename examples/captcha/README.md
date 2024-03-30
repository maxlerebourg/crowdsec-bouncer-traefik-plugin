# Example
## Enabling catpcha response from crowdsec

FIXME

The Traefik instance just needs to know where appsec engine is located
```yaml
  labels:
      # Choose captcha provider
      - "traefik.http.middlewares.crowdsec.plugin.bouncer.captchaProvider=hcaptcha"
      # Define captcha site key
      - "traefik.http.middlewares.crowdsec.plugin.bouncer.captchaSiteKey=FIXME"
      # Define captcha secret key
      - "traefik.http.middlewares.crowdsec.plugin.bouncer.captchaSecretKey=FIXME"
      # Define captcha grade period seconds
      - "traefik.http.middlewares.crowdsec.plugin.bouncer.captchaGracePeriodSeconds=20"
      # Define captcha HTML file path
      - "traefik.http.middlewares.crowdsec.plugin.bouncer.captchaHTMLFilePath=/captcha.html"
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
