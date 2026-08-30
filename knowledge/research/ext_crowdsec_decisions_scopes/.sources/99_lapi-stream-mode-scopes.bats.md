---
url: https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/test/bats/99_lapi-stream-mode-scopes.bats
title: LAPI stream mode scopes bats
fetched: 2026-08-30
authority: source
ref: github.com/crowdsecurity/crowdsec@e5da1b24a5dc0311ddcab74a5522b8feafbcbaee:test/bats/99_lapi-stream-mode-scopes.bats
---

Adds Ip decision 1.2.3.6 and --scope user --value toto.
GET /v1/decisions/stream?startup=true (implicit scopes): includes 1.2.3.6, excludes toto.
startup=true&scopes=ip: same.
startup=true&scopes=user: includes toto, excludes IP.
startup=true&scopes=user,ip: both.
Proves stream default hides non-ip/range scopes.
