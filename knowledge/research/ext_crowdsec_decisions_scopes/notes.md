# Decision scopes

Official CrowdSec decision scope values a bouncer can receive and how each is matched.

Fetched: 2026-08-30. Engine pin: `github.com/crowdsecurity/crowdsec@e5da1b24a5dc0311ddcab74a5522b8feafbcbaee`.

## Type versus scope

**Scope** is the *target* of a decision (what the remediation applies to). **Type** is the *action* (what to do). They are different fields.

- Decision `scope`: "does it apply to an IP, a range, a username, etc". ([swagger](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/models/localapi_swagger.yaml), extract `.sources/localapi_swagger.yaml.md`)
- Decision `type`: "might be 'ban', 'captcha' or something custom". ([swagger](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/models/localapi_swagger.yaml))
- `cscli decisions list` table: `SCOPE:VALUE` is the target; `ACTION` is the type (`ban`, `captcha`, …). `COUNTRY` and `AS` columns on that table are **GeoIP enrichment on the source IP**, not the decision scope. ([decisions_mgmt](https://docs.crowdsec.net/u/user_guides/decisions_mgmt/), extract `.sources/decisions_mgmt.md`)
- `cscli decisions add --type` examples: `ban`, `captcha`, `throttle`. `--scope` examples: `ip`, `range`, `username`. ([cscli add](https://docs.crowdsec.net/docs/next/cscli/cscli_decisions_add.md), extract `.sources/cscli_decisions_add.md`)

## Are there scopes besides Ip, Range, Country, and AS?

**Yes.** Scope is an open string, not a closed enum.

Strongest owners:

1. Official scenario format: "CrowdSec and Bouncers can work with **any scope**." `scope.type` is "a string representing the scope name"; `expression` fetches the value. Example: `type: username`. ([scenario format](https://docs.crowdsec.net/docs/next/log_processor/scenarios/format.md), extract `.sources/scenarios_format.md`)
2. Official custom bouncer: `scope` is "Most likely `Ip` or `Range` with the default config, **but can be any value set in your scenarios**." ([custom bouncer](https://docs.crowdsec.net/u/bouncers/custom/), extract `.sources/custom.md`)
3. Engine constants plus normalize: only `Ip`, `Range`, `Country`, and `AS` are remapped to a canonical spelling. Any other string is stored as given. ([event.go](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/types/event.go), extract `.sources/event.go.md`)

There is no LAPI validator that rejects an unknown scope. Swagger `Decision.scope` is a required string with no enum. ([decision.go](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/models/decision.go), extract `.sources/decision.go.md`)

## Exact scope strings (canonical)

Engine constants in `pkg/types` ([event.go](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/types/event.go)):

| Constant | Stored string | Normalized from |
|---|---|---|
| `types.Ip` | `Ip` | `ip` (any case) |
| `types.Range` | `Range` | `range` (any case) |
| `types.Country` | `Country` | `country` (any case) |
| `types.AS` | `AS` | `as` (any case) |
| `types.Filter` | `Filter` | not remapped |
| `types.Undefined` | `""` | — |

`NormalizeScope` only remaps those four. `ip` / `IP` / `Ip` become `Ip`. Anything else (`username`, `user`, `session`) is left unchanged. LAPI applies this on alert ingest. ([alerts.go](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/apiserver/controllers/v1/alerts.go), extract `.sources/alerts.go.md`)

CAPI pull only unifies `ip`→`Ip` and `range`→`Range`. It does not unify `country`/`as` on that path. ([apic.go](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/apiserver/apic.go), extract `.sources/apic.go.md`)

**Official vs source conflict (follow source for this version):** `Alert.GetScope()` docs say most common is `Ip`, and that `Country` and **`As`** are used for distributed attacks. ([other helpers](https://docs.crowdsec.net/docs/next/expr/other_helpers.md), extract `.sources/other_helpers.md`) The engine constant is **`AS`**, not `As`. `NormalizeScope("as")` returns `"AS"`.

**Official vs source conflict (docs incomplete):** LAPI remediation-component page describes stream as having a single `startup` argument. ([LAPI bouncers](https://docs.crowdsec.net/docs/next/local_api/bouncers.md), extract `.sources/lapi_bouncers.md`) Swagger and the controller also accept `scopes` (and other filters). Unfiltered stream **defaults to `ip,range`**. Follow source. ([decisions.go](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/apiserver/controllers/v1/decisions.go), extract `.sources/stream_decisions.go.md`; [swagger](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/models/localapi_swagger.yaml))

Wire-format examples from official LAPI docs (casing is inconsistent on the wire): `scope: "Ip"` with `value: "192.168.1.1"`; `scope: "Range"` with `value: "2.2.3.0/24"`; `scope: "ip"` with `value: "91.241.19.122/32"` (CAPI); `scope: "username"` with `value: "myuser"`. ([LAPI bouncers](https://docs.crowdsec.net/docs/next/local_api/bouncers.md))

`cscli decisions add --scope` default is `Ip`. Help text says `ie. ip,range,username`. ([cscli add](https://docs.crowdsec.net/docs/next/cscli/cscli_decisions_add.md))

## Username, Session, user, Filter

| Name | In engine constants? | Official mention | What happens |
|---|---|---|---|
| `username` | no | `cscli decisions add --scope username --value foobar`; LAPI query `?scope=username&value=myuser`; scenario `scope.type: username` | Stored as `username` (not remapped). Live query matches that string. Stream only if `scopes` includes `username`. |
| `user` | no | decisions_mgmt lists `user` as an example (`ip`,`range`,`user`…); LAPI tests use `--scope user` / `scopes=user` | Stored as `user`. **Does not match `username`.** |
| `session` | no | `cscli decisions list --scope` help: `ie. ip,range,session`; swagger GET `/decisions` scope: `IP/Range/Username/Session/...` | Example only. No constant, no engine test that creates a session decision. Same open-string path as `username`. |
| `Filter` | yes (`types.Filter = "Filter"`) | none as a decision scope | Named constant exists. No cscli/LAPI/docs usage as a decision scope was found at this commit. |

Username / session / user are **not** first-class remapped scopes. They work because scope is free-form. ([event.go](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/types/event.go); [cscli add](https://docs.crowdsec.net/docs/next/cscli/cscli_decisions_add.md); [cscli list](https://docs.crowdsec.net/docs/next/cscli/cscli_decisions_list.md), extract `.sources/cscli_decisions_list.md`; [swagger](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/models/localapi_swagger.yaml); [stream bats](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/test/bats/99_lapi-stream-mode-scopes.bats), extract `.sources/99_lapi-stream-mode-scopes.bats.md`)

Default shipped profiles only emit decisions for `Alert.GetScope() == "Ip"` and `"Range"`. A `username` (or Country/AS) alert does not get a decision unless a profile matches that scope. ([profiles.yaml](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/config/profiles.yaml), extract `.sources/profiles.yaml.md`)

## Value encoding

### Ip

- `cscli decisions add --ip 1.2.3.4` is shorthand for `--scope ip --value <IP>`. Value is a single address. ([cscli add](https://docs.crowdsec.net/docs/next/cscli/cscli_decisions_add.md); [sanitize.go](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/cmd/crowdsec-cli/clialert/sanitize.go), extract `.sources/sanitize.go.md`)
- Overflows set `Source.Value` to `Meta[source_ip]` (bare IP). ([overflows.go](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/leakybucket/overflows.go), extract `.sources/overflows.go.md`)
- CAPI stream examples can send `scope: "ip"` with `value: "91.241.19.122/32"` (CIDR on an Ip-scoped decision). ([LAPI bouncers](https://docs.crowdsec.net/docs/next/local_api/bouncers.md))
- On persist, Ip/Range values are parsed with `csnet.NewRange` (accepts bare IP or CIDR) so LAPI can do containment queries. ([alerts.go](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/database/alerts.go), extract `.sources/alerts_db.go.md`; [csnet](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/csnet/ip.go), extract `.sources/csnet_ip.go.md`)

### Range

- Encoded as CIDR. Official examples: `1.2.3.0/24`, `2.2.3.0/24`. ([cscli add](https://docs.crowdsec.net/docs/next/cscli/cscli_decisions_add.md); [LAPI bouncers](https://docs.crowdsec.net/docs/next/local_api/bouncers.md))
- `cscli --range` validates with `net.ParseCIDR`. ([sanitize.go](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/cmd/crowdsec-cli/clialert/sanitize.go))
- Overflows set Range value from enriched `SourceRange` (`net.IPNet.String()`, CIDR) or from a scope expression. ([overflows.go](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/leakybucket/overflows.go))

### Country

- Official PHP bouncer: "decisions with a scope of `Country`, and **2-letters code** value." Test: `cscli decisions add --scope Country --value FR -t captcha`. ([php](https://docs.crowdsec.net/u/bouncers/php.md), extract `.sources/php.md`)
- GeoIP enrichment writes MaxMind `Country.IsoCode` into `evt.Enriched.IsoCode` (ISO 3166-1 alpha-2). ([enrich_geoip.go](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/parser/enrich_geoip.go), extract `.sources/enrich_geoip.go.md`)
- Profile tests use scope `Country` and value `CH`. ([csprofiles_test](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/csprofiles/csprofiles_test.go) — cited only as confirming `CH`; extract not required beyond Country encoding already owned by php + enrich)

### AS / ASN

- Canonical scope string is `AS`. ([event.go](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/types/event.go))
- Official docs name `As` as an alert scope for distributed attacks. They do **not** document `cscli decisions add --scope AS` or the value format. ([other helpers](https://docs.crowdsec.net/docs/next/expr/other_helpers.md))
- GeoIP ASN enrichment stores `AutonomousSystemNumber` as a **decimal string with no `AS` prefix** (`strconv.FormatUint`, e.g. `13335` not `AS13335`). Fields: `ASNNumber` / `ASNumber`. ([enrich_geoip.go](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/parser/enrich_geoip.go))
- Authority **inference**: a scenario with `scope.type: AS` and `expression` over `evt.Enriched.ASNNumber` would produce value `13335`. LAPI does not rewrite AS values. A bouncer matching `AS13335` against `13335` would miss. Files read: [enrich_geoip.go](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/parser/enrich_geoip.go), [overflows.go](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/leakybucket/overflows.go) `default` branch copies the expression string as `value`.

### username / other custom

- Value is the expression result or the `--value` string. Official example: `username:myuser`, `username:foobar`. ([LAPI bouncers](https://docs.crowdsec.net/docs/next/local_api/bouncers.md); [cscli add](https://docs.crowdsec.net/docs/next/cscli/cscli_decisions_add.md))

## How a bouncer is expected to match

Two LAPI modes. ([LAPI bouncers](https://docs.crowdsec.net/docs/next/local_api/bouncers.md); [bouncer specs](https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs.md), extract `.sources/bouncer_appsec_specs.md`)

### Live / query — `GET /v1/decisions`

LAPI does the match. Shortcuts:

- `?ip=<addr>` — decisions whose stored range **contains** that IP (an Ip decision or a Range that covers it). Example: query `2.2.3.42` returns `scope: Range, value: 2.2.3.0/24`. ([LAPI bouncers](https://docs.crowdsec.net/docs/next/local_api/bouncers.md); [decisionfilter.go](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/database/decisionfilter.go), extract `.sources/decisionfilter.go.md`)
- `?range=<cidr>` — containment; `contains=true` (default) vs `contains=false` (outer contains inner). ([LAPI bouncers](https://docs.crowdsec.net/docs/next/local_api/bouncers.md); swagger `contains`)
- `?scope=<name>&value=<value>` — exact value on that scope. Example: `scope=username&value=myuser`. ([LAPI bouncers](https://docs.crowdsec.net/docs/next/local_api/bouncers.md))

Bouncer-spec note: for IP remediation, `scope: ip` is the relevant live query. ([bouncer specs](https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs.md))

Live query does **not** default-filter to ip/range the way stream does. Country/AS/username appear if they match the query.

### Stream — `GET /v1/decisions/stream`

LAPI returns decisions; the **bouncer matches locally**.

- If the client omits `scopes`, LAPI injects `scopes=ip,range`. Country, AS, username, user, session are **not** in the stream unless requested. ([decisions.go](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/apiserver/controllers/v1/decisions.go); [stream bats](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/test/bats/99_lapi-stream-mode-scopes.bats); [bouncer specs](https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs.md) "scopes: default to ip,range")
- Filter remap for query `scopes`: `ip`→`Ip`, `range`→`Range`, `country`→`Country`, `as`→`AS`. Other tokens (`user`, `username`) are used as-is and must match the stored string. ([decisionfilter.go](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/database/decisionfilter.go))
- Official HAProxy SPOA: `scopes: ["ip", "range", "country"]` — "Only pull decisions matching these scopes." ([haproxy](https://docs.crowdsec.net/u/bouncers/haproxy_spoa.md), extract `.sources/haproxy_spoa.md`)
- Official custom bouncer: set `scopes` to what the script can handle; default empty in the yaml example means "no extra filter from the bouncer," but LAPI still defaults stream to ip,range if the query param is absent. ([custom](https://docs.crowdsec.net/u/bouncers/custom/))
- Authority **inference**: a stream bouncer that never sends `scopes` will never see Country/AS/username. To receive them it must pass e.g. `scopes=ip,range,country,AS` (filter accepts any case for those four).

Expected local match by scope (owners as above):

| Scope | Bouncer match |
|---|---|
| `Ip` | Client IP equals decision value, or is the host in a `/32`/`/128` value. Live: LAPI `?ip=`. |
| `Range` | Client IP is inside the CIDR. Live: LAPI `?ip=` returns the covering Range. Stream: bouncer does CIDR contains. |
| `Country` | GeoIP the client IP; compare ISO 3166-1 alpha-2 to `value` (`FR`, `CH`). Official PHP does this with MaxMind; default off. |
| `AS` | GeoIP ASN of the client IP; compare to `value`. Official docs do not specify the compare string. Inference: decimal ASN (`13335`). |
| `username` / `user` / `session` / other | Exact string on that scope. Live: `?scope=&value=`. Stream: only if `scopes` includes that exact stored name. No IP/GeoIP match. |

Scope expression for non-Ip/non-Range is mandatory at scenario compile. Ip forbids a filter expression. Range may omit it (uses enriched CIDR). ([scopetype.go](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/leakybucket/scopetype.go), extract `.sources/scopetype.go.md`)

Profile-generated decisions copy `Alert.Source.Value` as the decision value. If a profile overrides `scope` (e.g. to `Country`) without a Country-scoped alert value, the value is still the alert source value (often an IP). ([csprofiles.go](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/csprofiles/csprofiles.go), extract `.sources/csprofiles.go.md`)

## Stream / decisions API: all scopes or filtered?

- **Stream default: filtered to `Ip` + `Range`.** Not all scopes. ([decisions.go](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/apiserver/controllers/v1/decisions.go); [stream bats](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/test/bats/99_lapi-stream-mode-scopes.bats))
- **Stream with `scopes=`:** only those scopes. Comma-separated. ([swagger](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/models/localapi_swagger.yaml))
- **Live `GET /decisions`:** no default scope list. Filter by `scope`/`value`/`ip`/`range`/`type` as provided. ([swagger](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/models/localapi_swagger.yaml); [LAPI bouncers](https://docs.crowdsec.net/docs/next/local_api/bouncers.md))

## References

- Official: [decisions management](https://docs.crowdsec.net/u/user_guides/decisions_mgmt/), [cscli decisions add](https://docs.crowdsec.net/docs/next/cscli/cscli_decisions_add.md), [cscli decisions list](https://docs.crowdsec.net/docs/next/cscli/cscli_decisions_list.md), [LAPI for remediation components](https://docs.crowdsec.net/docs/next/local_api/bouncers.md), [scenario format](https://docs.crowdsec.net/docs/next/log_processor/scenarios/format.md), [expr helpers](https://docs.crowdsec.net/docs/next/expr/other_helpers.md), [PHP bouncer](https://docs.crowdsec.net/u/bouncers/php.md), [custom bouncer](https://docs.crowdsec.net/u/bouncers/custom/), [HAProxy SPOA](https://docs.crowdsec.net/u/bouncers/haproxy_spoa.md), [bouncer AppSec specs](https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs.md)
- Source: `github.com/crowdsecurity/crowdsec@e5da1b24` paths listed above
- Extracts: `.sources/`
