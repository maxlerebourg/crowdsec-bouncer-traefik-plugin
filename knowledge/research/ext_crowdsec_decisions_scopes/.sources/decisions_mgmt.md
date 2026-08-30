---
url: https://docs.crowdsec.net/u/user_guides/decisions_mgmt/
title: Decisions
fetched: 2026-08-30
authority: official
---

SCOPE:VALUE is the target of the decision.
- scope: ip, range, user...
- value: ip_addr, ip_range, username...
ACTION is the type of the decision (ban, captcha...).
COUNTRY and AS columns are GeoIP enrichment if present, not the decision scope.
cscli decisions add --ip / --range use CIDR for ranges (example 1.2.3.0/24).
Import default scope is ip; value is mandatory (ip, range, username, ...).
type defaults to ban.
