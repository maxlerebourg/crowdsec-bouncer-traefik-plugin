# Design

## Context

`Decision.Scope` is unused. Stream keys the cache by `Value`. `ServeHTTP` `Get`s the remote IP. Live `?ip=` already expands Range on LAPI. Stream without `scopes=` is filtered to Ip+Range. One instance writes the shared cache (`updated` lock).

## Approach

1. **Config:** `countryHeader`, `asnHeader` (empty = scope off).
2. **LAPI stream:** `scopes=ip,range` plus `country` and/or `AS` when the matching header is set. CAPI stream unchanged.
3. **Cache keys:** Ip stays the address. `country:<ISO>`, `as:<digits>`, `range:<cidr>`, index `range-index` (newline CIDRs). Required so Redis replicas can match without ingesting the stream.
4. **Lookup order:** Ip, Range, Country, AS. Prefer `ban` over `captcha`.
5. **Normalize:** scope `ip`/`range`/`country`/`as` → `Ip`/`Range`/`Country`/`AS`. Country case-fold. ASN strip optional `AS` prefix. Ip `/32`/`/128` stored as the host.
6. **Live:** keep `?ip=`; if a header is present, `?scope=Country&value=` and/or `?scope=AS&value=`.
7. **Missing header:** skip that scope.

## Risks

- Range index is O(n) per request. CrowdSec range decisions are typically few (community lists are mostly IPs). No radix tree this change.
- Index read-modify-write is not atomic; same as the existing single-writer stream update.
