# Decisions

## Language

**Decision type**:
The CrowdSec action on a match (`ban` or `captcha`).
_Avoid_: remediation scope, country

**Decision scope**:
The CrowdSec target of a decision (`Ip`, `Range`, `Country`, `AS`, or another open string).
_Avoid_: remediation type, header

## Overview

The bouncer stores stream decisions in the shared cache and looks them up on each request. Ip is the client address. Range is CIDR containment. Country and AS are existing request headers named in config.

## How to use

- Add `countryHeader` and/or `asnHeader` when you want Country or AS matching.
- Those headers must be set by a trusted hop (CDN or Traefik). A client-supplied value is not trusted identity.
- Empty header names leave Country/AS off. LAPI stream then asks only `ip,range`.
- Do not resolve GeoIP in this plugin. Read the header that already has the code or ASN.
- Ignore custom scopes (`username`, `session`). There is no request identity for them.

## Pattern snippet

```yaml
http:
  middlewares:
    crowdsec:
      plugin:
        bouncer:
          countryHeader: CF-IPCountry
          asnHeader: CF-ASN
```

## Key files

- `pkg/decision/` — scope normalize, cache keys, range index
- `bouncer_decisions.go` — stream scopes, live extra queries, cache lookup
- `pkg/configuration/configuration.go` — `CountryHeader`, `AsnHeader`

## Gotchas

- LAPI stream defaults to Ip+Range. Country and AS never arrive unless `scopes=` is sent (this plugin adds it when the header is configured).
- ASN values are decimal digits (`13335`). A header like `AS13335` is stripped before compare.
- Cloudflare `XX` and `T1` do not match a Country decision.
- Range membership lives in the shared cache (`range-index`) so instances that do not ingest the stream can still match.
- Country and ASN headers are not authenticated. If Traefik is the edge, the client can send them.
