---
url: https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/database/alerts.go
title: Persist decision IP/range integers
fetched: 2026-08-30
authority: source
ref: github.com/crowdsecurity/crowdsec@e5da1b24a5dc0311ddcab74a5522b8feafbcbaee:pkg/database/alerts.go
---

When decision scope ToLower is ip or range, value is parsed with csnet.NewRange and stored as start/end/ip_size.
Invalid CIDR/IP on those scopes is skipped (logged).
Other scopes still store Scope and Value strings; IP integers stay zero-sized (no containment index).
