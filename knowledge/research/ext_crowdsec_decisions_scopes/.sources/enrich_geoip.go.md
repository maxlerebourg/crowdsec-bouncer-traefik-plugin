---
url: https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/parser/enrich_geoip.go
title: GeoIP ASN and country enrichment
fetched: 2026-08-30
authority: source
ref: github.com/crowdsecurity/crowdsec@e5da1b24a5dc0311ddcab74a5522b8feafbcbaee:pkg/parser/enrich_geoip.go
---

ASN: strconv.FormatUint(record.AutonomousSystemNumber, 10) — decimal, no AS prefix.
Writes ASNNumber and ASNumber (same string), plus ASNOrg.
Country: MaxMind IsoCode → Enriched.IsoCode (ISO 3166-1 alpha-2).
IpToRange writes SourceRange as *net.IPNet.String() (CIDR).
