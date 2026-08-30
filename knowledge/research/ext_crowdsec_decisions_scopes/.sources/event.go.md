---
url: https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/types/event.go
title: pkg/types/event.go scope constants
fetched: 2026-08-30
authority: source
ref: github.com/crowdsecurity/crowdsec@e5da1b24a5dc0311ddcab74a5522b8feafbcbaee:pkg/types/event.go
---

Constants: Undefined="", Ip="Ip", Range="Range", Filter="Filter", Country="Country", AS="AS".
NormalizeScope lowercases then remaps ip→Ip, range→Range, as→AS, country→Country.
default: return the original string unchanged (username, user, session, Filter stay as given).
