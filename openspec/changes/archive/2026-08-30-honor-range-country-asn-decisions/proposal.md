# Proposal

Honor CrowdSec **Range**, **Country**, and **AS** decision scopes in addition to **Ip**.

Country and AS come from existing request headers named in plugin config (`countryHeader`, `asnHeader`). The plugin does not look up GeoIP itself.

## Why

Stream mode stores `decision.Value` and looks up only the client IP. A CIDR, country code, or ASN in that map never matches. LAPI stream also defaults to `ip,range`, so Country and AS never arrive unless the bouncer asks for them.

## New vs Modified

- **New:** `core_bouncer_decisions_scopes` — FindSpecHost `new` (no baseline spec; new public config and match path).

## Scope

- In: Ip, Range, Country, AS match; stream `scopes=` on LAPI; live extra queries; two header config keys; README.
- Out: GeoIP inside the plugin; username/session/custom scopes; radix tree; metrics-by-scope; AppSec; new decision types beyond `ban` / `captcha`.
