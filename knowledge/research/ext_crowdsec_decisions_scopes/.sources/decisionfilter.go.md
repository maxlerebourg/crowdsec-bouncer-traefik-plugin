---
url: https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/database/decisionfilter.go
title: applyDecisionFilter scopes
fetched: 2026-08-30
authority: source
ref: github.com/crowdsecurity/crowdsec@e5da1b24a5dc0311ddcab74a5522b8feafbcbaee:pkg/database/decisionfilter.go
---

Accepts query keys scopes or scope. Splits on comma.
Remap ToLower: ip→types.Ip, range→types.Range, country→types.Country, as→types.AS.
Other tokens left as entered, then decision.ScopeIn(...).
type filter is TypeEQ (separate from scope).
ip/range params parse via csnet.NewRange and apply containment (contains default true).
