---
url: https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/config/profiles.yaml
title: Default profiles.yaml
fetched: 2026-08-30
authority: source
ref: github.com/crowdsecurity/crowdsec@e5da1b24a5dc0311ddcab74a5522b8feafbcbaee:config/profiles.yaml
---

default_ip_remediation: Alert.GetScope() == "Ip" → type ban 4h, on_success break.
default_range_remediation: Alert.GetScope() == "Range" → type ban 4h, on_success break.
No Country, AS, or username profile in the shipped default file.
