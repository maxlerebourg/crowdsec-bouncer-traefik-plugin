---
url: https://docs.crowdsec.net/docs/next/local_api/bouncers.md
title: For Remediation Components
fetched: 2026-08-30
authority: official
---

Bouncers are restricted to /decisions.
Stream: /decisions/stream with startup true|false. This page describes only the startup argument.
Query: specific ip/range/username etc.
cscli list display: Range:2.2.3.0/24 and Ip:192.168.1.1.
GET /v1/decisions?ip=192.168.1.1 returns scope "Ip", type "ban", value "192.168.1.1".
GET ?ip=2.2.3.42 returns the covering Range 2.2.3.0/24.
contains=false on range query returns inner Ip decisions.
Non-IP: cscli decisions add --scope username --value myuser --type enforce_mfa.
GET ?scope=username&value=myuser returns scope "username", type "enforce_mfa".
Stream examples: scope "Ip" value "123.206.50.249"; scope "ip" value "91.241.19.122/32" (CAPI).
New decision after add -i 3.3.3.4: scope "Ip", type "ban", value "3.3.3.4".
