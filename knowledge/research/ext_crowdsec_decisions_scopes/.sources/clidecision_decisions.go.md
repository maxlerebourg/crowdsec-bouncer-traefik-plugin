---
url: https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/cmd/crowdsec-cli/clidecision/decisions.go
title: cscli decisions add/list flags
fetched: 2026-08-30
authority: source
ref: github.com/crowdsecurity/crowdsec@e5da1b24a5dc0311ddcab74a5522b8feafbcbaee:cmd/crowdsec-cli/clidecision/decisions.go
---

list --scope help: ie. ip,range,session.
list --type help: ie. ban,captcha.
add --scope default types.Ip, help ie. ip,range,username.
add example: --scope username --value foobar.
add --type default ban, help ie. ban,captcha,throttle.
--ip sets value and scope types.Ip; --range sets value and scope types.Range.
Decision.Type and Decision.Scope are separate fields on the alert posted to LAPI.
