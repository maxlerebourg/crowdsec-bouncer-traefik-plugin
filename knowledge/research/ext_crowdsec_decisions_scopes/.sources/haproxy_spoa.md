---
url: https://docs.crowdsec.net/u/bouncers/haproxy_spoa.md
title: HAProxy SPOA bouncer
fetched: 2026-08-30
authority: official
---

Supports IP / range / country decisions.
Config scopes: []string — only pull decisions matching these scopes (for example ip, range, country).
Example: scopes: ["ip", "range", "country"].
GeoIP headers (ASN / Country) are a separate feature from decision scope.
