---
url: https://docs.crowdsec.net/docs/next/cscli/cscli_decisions_add.md
title: cscli decisions add
fetched: 2026-08-30
authority: official
---

Examples include --ip, --range 1.2.3.0/24, --type captcha, --scope username --value foobar.
--ip is shorthand for --scope ip --value <IP>.
--range is shorthand for --scope range --value <RANGE>.
--scope default is "Ip". Help: ie. ip,range,username.
--type default is ban. Help: ie. ban,captcha,throttle.
