---
url: https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/leakybucket/overflows.go
title: SourceFromEvent scope values
fetched: 2026-08-30
authority: source
ref: github.com/crowdsecurity/crowdsec@e5da1b24a5dc0311ddcab74a5522b8feafbcbaee:pkg/leakybucket/overflows.go
---

Ip: value = Meta[source_ip] (must parse as IP).
Range: value = enriched SourceRange as net.IPNet.String() (CIDR), or scope expression if set.
GeoIP on Ip/Range sources: ASNumber/ASNNumber, IsoCode → Source.Cn, ASNOrg → AsName (enrichment, not decision scope).
default (any other scope): require RunTimeFilter; value = string result of the expression; Scope = scenario scope type as written.
