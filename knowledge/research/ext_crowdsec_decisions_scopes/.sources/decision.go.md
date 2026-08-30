---
url: https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/models/decision.go
title: models.Decision
fetched: 2026-08-30
authority: source
ref: github.com/crowdsecurity/crowdsec@e5da1b24a5dc0311ddcab74a5522b8feafbcbaee:pkg/models/decision.go
---

scope: required string. Comment: applies to an IP, a range, a username, etc. No enum.
type: required string. Comment: might be ban, captcha or something custom.
value: required string. Comment: an IP, a range, a username, etc.
Validate only checks required, not allowed values.
