---
url: https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/apiserver/apic.go
title: CAPI decision scope unify
fetched: 2026-08-30
authority: source
ref: github.com/crowdsecurity/crowdsec@e5da1b24a5dc0311ddcab74a5522b8feafbcbaee:pkg/apiserver/apic.go
---

Comment: CAPI might send lower case scopes, unify it.
Only ip→types.Ip and range→types.Range.
Country/AS not unified on this CAPI ingest path.
