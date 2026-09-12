# Example
## Bot detection with the AppSec challenge

AppSec bot detection, added in CrowdSec 1.8.0, answers a request that has no valid
`__crowdsec_challenge` cookie with a challenge page instead of a plain block.
See the CrowdSec documentation for the feature itself:
[intro](https://docs.crowdsec.net/docs/appsec/bot_detection/intro),
[how it works](https://docs.crowdsec.net/docs/appsec/bot_detection/how_it_works) and
[challenge protocol](https://docs.crowdsec.net/docs/appsec/bot_detection/challenge_protocol). The browser
solves a proof-of-work, returns an encrypted fingerprint, and AppSec grants a sealed cookie
that lets the following requests through.

That only works if the bouncer relays what AppSec sends back. A ban is a status code and
nothing else, but a challenge is a status code **plus a body, cookies and headers**, so the
plugin forwards the whole remediation rather than turning it into a 403.

Everything specific to this lives on the CrowdSec side. Traefik only needs to know where the
AppSec component is:

```yaml
  labels:
      - "traefik.http.middlewares.crowdsec.plugin.bouncer.crowdsecappsecenabled=true"
      - "traefik.http.middlewares.crowdsec.plugin.bouncer.crowdsecappsechost=crowdsec:7422"
```

One setting does matter here. The browser posts the solved challenge back, so the request
body has to reach AppSec; `crowdsecAppsecBodyLimit: 0` would stop the challenge from ever
being validated and leave the client in a loop.

Two details are easy to get wrong, and both fail silently.

**The router has to cover `/crowdsec-internal`.** The challenge page loads its fingerprint
script from `/crowdsec-internal/challenge/fpscanner.js`, an absolute path. If the router only
matches your application prefix, that script 404s, the proof-of-work never runs and the
challenge can never be solved — you are left looking at the challenge page forever:

```yaml
  - "traefik.http.routers.router-foo.rule=PathPrefix(`/foo`) || PathPrefix(`/crowdsec-internal`)"
```

**The acquisition has to load the config that sends the challenge.** `-scoring` calls
`SendChallenge()` in `post_eval`; `-scoring-balanced` only carries the rejection threshold.
Loading the latter alone means AppSec processes requests and never challenges anything:

```yaml
appsec_configs:
  - crowdsecurity/appsec-bot-challenge-scoring
  - crowdsecurity/appsec-bot-challenge-scoring-balanced
```

CrowdSec logs `WAF challenge runtime initialized` at startup when this is right. The
wildcard is the form used by the official
[enable guide](https://docs.crowdsec.net/docs/appsec/bot_detection/enable), and it matters:
it matches installed configs only, so it also loads the exclusions the collection ships
(verified crawlers, static paths) which a hand-written list easily misses.

Referencing a config that is not installed is fatal rather than degraded — CrowdSec refuses
to start, and because `crowdsecAppsecFailureBlock` defaults to true every request then gets
a 403 that looks like a WAF decision. `crowdsecurity/appsec-default` needs
`crowdsecurity/appsec-virtual-patching` and `crowdsecurity/appsec-generic-rules`, which is
why both are in `COLLECTIONS`.

This example runs the plugin from the working tree with
`--experimental.localplugins`, because relaying the AppSec remediation is not in a released
build yet. Once it ships, swap in the catalog lines already present in the compose file:

```yaml
      - "--experimental.plugins.bouncer.modulename=github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin"
      - "--experimental.plugins.bouncer.version=v1.8.0"
```
and drop the `./../../:/plugins-local/...` mount.

To play the demo environment run:
```bash
make run_bot_detection
```

Open http://localhost:8000/foo in a browser: you get the challenge page, the browser solves
the proof-of-work, and the whoami output follows.

curl receives the same challenge page but has no javascript engine to solve it, which is the
point — it never reaches whoami:

```bash
curl -i http://localhost:8000/foo
```

Note the response is a `200` carrying an HTML body and a `Content-Security-Policy` header,
all produced by AppSec and relayed as-is. That is the whole feature: a ban is a status code,
a challenge is a status code plus a body, cookies and headers.

To troubleshoot, watch the AppSec counters:
```bash
docker exec crowdsec cscli metrics show appsec
```
`Ch. Requested` staying at 0 while `Processed` climbs means requests reach AppSec but no
challenge is being issued, so the problem is the CrowdSec configuration rather than the
bouncer. `cscli collections list` confirms the bot-challenge collection is enabled.

The collection also ships scenarios for clients that keep asking for challenges without ever
submitting one, so repeat offenders end up with an ordinary CrowdSec decision and are banned
by the usual path.

Other scoring profiles are available if `balanced` is too strict or too loose for your
traffic: `crowdsecurity/appsec-bot-challenge-permissive` and
`crowdsecurity/appsec-bot-challenge-strict`. There are also exclusion configs to let through
search engines, monitoring, feeds and static files, for example
`crowdsecurity/appsec-bot-challenge-exclude-search-engines`.

> Bot detection is flagged **Alpha** by CrowdSec: its configuration, helpers and shipped
> rules may change between releases. The challenge also needs SSE4.1 and writable-executable
> memory, so hardened or older clients cannot solve it, and a visitor with cookies disabled
> is shown an explicit error.
