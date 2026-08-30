# Decisions

## Language

**Decision type**:
The CrowdSec action on a match (`ban` or `captcha`).
_Avoid_: remediation scope, country

**Decision scope**:
The CrowdSec target of a decision (`Ip`, `Range`, `Country`, `AS`, or another open string).
_Avoid_: remediation type, header

## Overview

The bouncer stores stream decisions in the shared cache and looks them up on each request. Ip is the client address. Range is CIDR containment. Other scopes come from `decisionScopeHeaders` (scope name → request header). Country and AS keep ad-hoc value normalization.

## How to use

- Add `decisionScopeHeaders` when you want Country, AS, or another CrowdSec scope matched from a request header.
- Those headers must be set by a trusted hop (CDN or Traefik). A client-supplied value is not trusted identity.
- Empty `decisionScopeHeaders` leaves header scopes off. LAPI stream then asks only `ip,range`.
- Do not resolve GeoIP in this plugin. Read the header that already has the code or ASN.
- Do not map `Ip` or `Range`. Those are not header scopes.
- Unmapped custom scopes (`username`, `session`) are ignored.

## Pattern snippet

```yaml
http:
  middlewares:
    crowdsec:
      plugin:
        bouncer:
          decisionScopeHeaders:
            Country: CF-IPCountry
            AS: CF-ASN
            username: X-User
```

## Key files

- `decision_scope.go`, `decision_ranges.go` — scope normalize, cache keys, range index
- `bouncer_decisions.go` — stream scopes, live extra queries, cache lookup
- `pkg/configuration/configuration.go` — `DecisionScopeHeaders`

## Gotchas

- LAPI stream defaults to Ip+Range. Country, AS, and custom scopes never arrive unless `scopes=` is sent (this plugin adds configured keys).
- ASN values are decimal digits (`13335`). A header like `AS13335` is stripped before compare.
- Cloudflare `XX` and `T1` do not match a Country decision.
- Custom scopes compare the trimmed header string to the decision value. The scope name must match what LAPI stored (`username` is not `user`).
- Range membership and verdict live on one shared key (`range-index`, lines `cidr=remediation`) so instances that do not ingest the stream can still match.
- Request lookup is one `GetMany` for the IP, present header-scope keys, and `range-index` (stream/alone only). A missed stream `Deleted` stays on the index until the next full refresh.
- Scope headers are not authenticated. If Traefik is the edge, the client can send them.
