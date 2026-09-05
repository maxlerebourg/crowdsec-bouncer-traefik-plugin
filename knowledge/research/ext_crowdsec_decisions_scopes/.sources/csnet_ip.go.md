---
url: https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/csnet/ip.go
title: csnet.NewRange
fetched: 2026-08-30
authority: source
ref: github.com/crowdsecurity/crowdsec@e5da1b24a5dc0311ddcab74a5522b8feafbcbaee:pkg/csnet/ip.go
---

NewRange(anyIP) delegates to types.Addr2Ints.
Accepts a single address or a CIDR and yields Start/End integers used by LAPI containment queries.
