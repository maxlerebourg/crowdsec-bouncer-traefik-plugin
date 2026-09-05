# core_bouncer_decisions_scopes

Match CrowdSec decisions by scope (Ip, Range, Country, AS, and optional custom scopes) using the client IP and configured request headers.

## Purpose

The bouncer remediates requests from Range, Country, AS, and other CrowdSec scopes that are mapped to a request header, not only exact IP keys.

## Requirements

### Requirement: LAPI stream asks for configured scopes

The LAPI stream request SHALL include `scopes=ip,range`. For each key in `decisionScopeHeaders`, the request SHALL also include that scope (`country` when the key is Country, `AS` when the key is AS, otherwise the configured name). The CAPI stream SHALL NOT add a `scopes` query parameter.

### Requirement: Range decisions match by CIDR containment

When a decision scope is `Range` (any case), the bouncer SHALL treat `value` as a CIDR and remediate a request whose client IP is inside that network. Range membership SHALL be stored in the shared cache so instances that do not ingest the stream can still match.

### Requirement: Country decisions match a configured request header

When `decisionScopeHeaders` maps `Country` (any case) to a header, the bouncer SHALL compare the header value to Country decision values as ISO 3166-1 alpha-2, case-insensitive. An empty or missing header SHALL skip Country matching. Values `XX` and `T1` SHALL NOT match a Country decision.

### Requirement: AS decisions match a configured request header

When `decisionScopeHeaders` maps `AS` (any case) to a header, the bouncer SHALL compare the header value to AS decision values as decimal digits. A leading `AS` or `as` prefix on the header or the decision value SHALL be ignored. An empty or missing header SHALL skip AS matching.

### Requirement: Custom header scopes match by exact value

When `decisionScopeHeaders` maps a scope other than `Ip`, `Range`, `Country`, or `AS` to a header, the bouncer SHALL compare the trimmed header value to that scope's decision value. An empty or missing header SHALL skip that scope. Unmapped custom scopes SHALL NOT be stored or used for remediation.

### Requirement: Ip decisions stay exact-address keys

An `Ip` decision SHALL be cached and looked up by the client IP. If the decision value is a `/32` or `/128` CIDR, the bouncer SHALL store the host address.

### Requirement: Live query expands Range on LAPI and queries header scopes locally

In live or none mode, the bouncer SHALL keep querying `v1/decisions?ip=<clientIP>` (LAPI containment includes Range). For each configured header scope whose request value is present, the bouncer SHALL also query `scope` and `value` for that scope.

### Requirement: Type remediations are unchanged

Decision `type` `ban` and `captcha` SHALL keep their current remediations. Unknown types SHALL be ignored. When several matching decisions exist, `ban` SHALL win over `captcha`.

### Requirement: Header config is a scope-to-header map

`decisionScopeHeaders` SHALL be a plugin config map from CrowdSec scope name to request header name, default empty. Empty means only `ip,range` are requested on the stream. Keys `Ip` and `Range` (any case) SHALL be rejected. Country and AS values SHALL keep their ad-hoc normalization; other scopes SHALL use the trimmed header string.
