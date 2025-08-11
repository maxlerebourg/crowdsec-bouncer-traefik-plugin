# Example

Read the example captcha before this, to better understand what is done here.

### Traefik configuration

The minimal configuration is defined below to implement custom captcha.  
This documentation use https://github.com/a-ve/wicketpeeker, a self-hosted captcha provider that have a similar API than big providers.

Minimal API requirement:

- the JS file URL to load the captcha on the served `captcha.html`
- the HTML className to tell to the JS where to display the challenge
- the verify URL endpoint to send the response from the captcha
- the name of the field in the verify URL

- the JS file need to respect the `data-callback` on the div that contains the captcha if you use our template, but you can customize it by your side

```yaml
  traefik:
    ...
    labels:
      # Choose captcha provider
      - "traefik.http.middlewares.crowdsec.plugin.bouncer.captchaProvider=custom"
      # Define captcha grace period seconds
      - "traefik.http.middlewares.crowdsec.plugin.bouncer.captchaGracePeriodSeconds=1800"
      - "traefik.http.middlewares.crowdsec.plugin.bouncer.captchaCustomJsURL=http://captcha.localhost:8000/fast.js"
      # Inside Traefik container the plugin must be able to reach wicketkeeper service so we can go through a Traefik localhost
      # domain which would resolve traefik itself and the port for the dashboard
      - "traefik.http.middlewares.crowdsec.plugin.bouncer.CaptchaCustomValidateURL=http://wicketkeeper:8080/v0/siteverify"
      - "traefik.http.middlewares.crowdsec.plugin.bouncer.CaptchaCustomKey=wicketkeeper"
      - "traefik.http.middlewares.crowdsec.plugin.bouncer.CaptchaCustomResponse=wicketkeeper_solution"
      # Define captcha HTML file path
      - "traefik.http.middlewares.crowdsec.plugin.bouncer.captchaHTMLFilePath=/captcha.html"
```

```yaml
wicketkeeper:
  image: ghcr.io/a-ve/wicketkeeper:latest
  user: root
  ports:
    - "8080:8080"
  environment:
    - ROOT_URL=http://localhost:8080
    - LISTEN_PORT=8080
    - REDIS_ADDR=redis:6379
    - DIFFICULTY=4
    - ALLOWED_ORIGINS=*
    - PRIVATE_KEY_PATH=/data/wicketkeeper.key
  volumes:
    - ./data:/data
  depends_on:
    - redis
redis:
  image: redis/redis-stack-server:latest
```

## Exemple navigation

We can try to query normally the whoami server:

```bash
curl http://localhost:8000/foo
```

We can try to ban ourself and retry.

```bash
docker exec crowdsec cscli decisions add --ip 10.0.0.20 -d 10m --type captcha
```

To play the demo environment run:

```bash
make run_custom_captcha
```
