---
url: https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/csprofiles/csprofiles.go
title: GenerateDecisionFromProfile
fetched: 2026-08-30
authority: source
ref: github.com/crowdsecurity/crowdsec@e5da1b24a5dc0311ddcab74a5522b8feafbcbaee:pkg/csprofiles/csprofiles.go
---

If the profile decision sets Scope, that wins; else copy Alert.Source.Scope.
Decision.Type comes from the profile.
Decision.Value is always copied from Alert.Source.Value (profile does not set value).
Origin crowdsec. Type and scope remain separate fields.
