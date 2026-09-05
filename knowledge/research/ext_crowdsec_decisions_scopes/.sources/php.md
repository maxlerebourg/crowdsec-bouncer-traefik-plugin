---
url: https://docs.crowdsec.net/u/bouncers/php.md
title: PHP Standalone remediation
fetched: 2026-08-30
authority: official
---

Supports ban and captcha remediations, and decisions of type Ip, Range or Country (geolocation).
Handles ip, range and country scoped decisions.
Geolocation remediation expects scope Country and a 2-letters code value.
Test command: cscli decisions add --scope Country --value FR -t captcha.
Uses MaxMind; geolocation.enabled default false.
