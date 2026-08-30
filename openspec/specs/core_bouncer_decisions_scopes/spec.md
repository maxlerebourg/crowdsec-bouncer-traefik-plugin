# core_bouncer_decisions_scopes

Match CrowdSec decisions by scope (Ip, Range, Country, AS) using the client IP and optional request headers.

## Purpose

The bouncer remediates requests from Range, Country, and AS decisions, not only exact IP keys.

## Requirements

### Requirement: LAPI stream asks for configured scopes

The LAPI stream request SHALL include `scopes=ip,range`. When `countryHeader` is set, the request SHALL also include `country`. When `asnHeader` is set, the request SHALL also include `AS`. The CAPI stream SHALL NOT add a `scopes` query parameter.

### Requirement: Range decisions match by CIDR containment

When a decision scope is `Range` (any case), the bouncer SHALL treat `value` as a CIDR and remediate a request whose client IP is inside that network. Range membership SHALL be stored in the shared cache so instances that do not ingest the stream can still match.

### Requirement: Country decisions match a configured request header

When `countryHeader` is set, the bouncer SHALL compare the header value to Country decision values as ISO 3166-1 alpha-2, case-insensitive. An empty or missing header SHALL skip Country matching. Values `XX` and `T1` SHALL NOT match a Country decision.

### Requirement: AS decisions match a configured request header

When `asnHeader` is set, the bouncer SHALL compare the header value to AS decision values as decimal digits. A leading `AS` or `as` prefix on the header or the decision value SHALL be ignored. An empty or missing header SHALL skip AS matching.

### Requirement: Ip decisions stay exact-address keys

An `Ip` decision SHALL be cached and looked up by the client IP. If the decision value is a `/32` or `/128` CIDR, the bouncer SHALL store the host address.

### Requirement: Live query expands Range on LAPI and queries Country and AS locally

In live or none mode, the bouncer SHALL keep querying `v1/decisions?ip=<clientIP>` (LAPI containment includes Range). When a country or ASN header is present, the bouncer SHALL also query `scope` and `value` for that scope.

### Requirement: Custom scopes are ignored

Decisions whose scope is not `Ip`, `Range`, `Country`, or `AS` SHALL NOT be used for remediation.

### Requirement: Type remediations are unchanged

Decision `type` `ban` and `captcha` SHALL keep their current remediations. Unknown types SHALL be ignored. When several matching decisions exist, `ban` SHALL win over `captcha`.

### Requirement: Header config is public

`countryHeader` and `asnHeader` SHALL be plugin config strings, default empty. Empty means that scope is not requested on the stream and is not matched on the request.
