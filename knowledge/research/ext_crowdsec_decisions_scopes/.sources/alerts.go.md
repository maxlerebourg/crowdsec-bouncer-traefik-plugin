---
url: https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/apiserver/controllers/v1/alerts.go
title: LAPI alert ingest NormalizeScope
fetched: 2026-08-30
authority: source
ref: github.com/crowdsecurity/crowdsec@e5da1b24a5dc0311ddcab74a5522b8feafbcbaee:pkg/apiserver/controllers/v1/alerts.go
---

On alert POST, Source.Scope and each Decision.Scope are passed through types.NormalizeScope.
ip/IP become Ip; country/Country become Country; as/AS become AS; username stays username.
