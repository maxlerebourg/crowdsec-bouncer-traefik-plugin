---
url: https://docs.crowdsec.net/docs/next/expr/other_helpers.md
title: Other helpers — Alert.GetScope
fetched: 2026-08-30
authority: official
---

Alert.GetScope() returns the scope of an alert.
Most common value is Ip.
Country and As are generally used for more distributed attacks detection/remediation.
Alert.GetValue() is the Source value: IPv4, IPv6, or other if Scope is not Ip.
Conflicts with engine constant AS (not As). Follow source for stored spelling.
