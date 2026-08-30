---
url: https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs.md
title: Specifications for Remediation Component and AppSec Capabilities
fetched: 2026-08-30
authority: official
---

Swagger: https://crowdsecurity.github.io/api_doc/lapi/
Stream GET /decisions/stream. scopes default to "ip,range" for stream mode.
"ip,range" is the only relevant scopes value when remediating on IPs.
Live GET /decisions: scope "ip" is the only relevant value when remediating on IPs.
ip / range query params are shortcuts for scope+value.
type filter: leave blank to get any decision types.
