# Example
## Enabling catpcha response from crowdsec

Crowdsec support 3 remediations solutions `ban`, `captcha`, and `throttle`.  
This plugins support the `ban` and `captcha` remediation.  

The minimal configuration is defined below.
For now 3 captcha providers are supported:
 - [hcaptcha](https://www.hcaptcha.com/)
 - [recaptcha](https://www.google.com/recaptcha/about/)
 - [turnstile](https://www.cloudflare.com/fr-fr/products/turnstile/)

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

The captcha HTML file must be present in the Traefik container (bind mounted or added during a custom build)

```yaml
  ...
  traefik:
    image: "traefik:v2.11.0"
    volumes:
      - './captcha.html:/captcha.html'
  ...
```
## Exemple navigation
We can try to query normally the whoami server:
```bash
curl http://localhost:8000/foo
```

We can try to ban ourself

```bash
docker exec crowdsec cscli decisions add --ip 10.0.0.20 -d 4h --type captcha
```

![image decision captcha](image_decision_catpcha.png)

We will see in the browser the captcha validation page:

![image captcha validation](image_captcha_validation.png)

To play the demo environment run:
```bash
make run_captcha
```

> Note, if we are banned with a "ban" decision from crowdsec a captcha will not be asked and you will have to wait for the decision to expire.  

```bash
docker exec crowdsec cscli decisions add --ip 10.0.0.10 -d 10m --type ban
```

