---
url: https://docs.crowdsec.net/u/bouncers/custom/
title: CrowdSec Custom Remediation
fetched: 2026-08-30
authority: official
---

scopes: [] filters decisions pulled from LAPI. Example scopes: ["Ip"].
Recommend setting scopes to what the script can handle.
JSON decision: scope most likely Ip or Range with default config, but can be any value set in scenarios.
type most likely ban or captcha, but can be any value set in profiles.
value examples include 192.168.1.1 and CH.
scope and type are separate fields.
