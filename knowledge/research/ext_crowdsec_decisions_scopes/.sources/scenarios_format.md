---
url: https://docs.crowdsec.net/docs/next/log_processor/scenarios/format.md
title: Scenario format — scope
fetched: 2026-08-30
authority: official
---

CrowdSec and Bouncers can work with any scope.
scope.type is a string (the scope name).
scope.expression is expr that fetches the value.
Example: type Range with expression evt.Parsed.mySourceRange.
Example: type username with expression evt.Meta.target_user.
Matching profile: Alert.GetScope() == "username", decisions type enforce_mfa scope username.
Resulting list row: username:rura / ACTION enforce_mfa.
