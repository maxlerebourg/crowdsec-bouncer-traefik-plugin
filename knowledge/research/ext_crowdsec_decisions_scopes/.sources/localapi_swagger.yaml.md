---
url: https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/models/localapi_swagger.yaml
title: LAPI swagger — decisions
fetched: 2026-08-30
authority: source
ref: github.com/crowdsecurity/crowdsec@e5da1b24a5dc0311ddcab74a5522b8feafbcbaee:pkg/models/localapi_swagger.yaml
---

GET /decisions/stream query: startup (bool), scopes (comma-separated scopes to fetch), origins, scenarios_containing, scenarios_not_containing.
GET /decisions query: scope (ie. IP/Range/Username/Session/...), value, type, ip, range, contains.
Decision.scope / Decision.type / Decision.value are required strings, no enum.
Session and Username appear only in the GET /decisions scope description.
