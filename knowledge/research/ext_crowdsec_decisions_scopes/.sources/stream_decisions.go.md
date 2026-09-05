---
url: https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/apiserver/controllers/v1/decisions.go
title: StreamDecision default scopes
fetched: 2026-08-30
authority: source
ref: github.com/crowdsecurity/crowdsec@e5da1b24a5dc0311ddcab74a5522b8feafbcbaee:pkg/apiserver/controllers/v1/decisions.go
---

StreamDecision: if URL query has no scopes key, set filters["scopes"] = []string{"ip,range"}.
startup=true resets cursor to 0 (full active set under that filter).
FormatDecisions copies db Decision.Scope and Type unchanged onto the wire.
GetDecision (live) uses QueryDecisionWithFilter on the raw query; no default scopes injection.
