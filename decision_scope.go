package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"net"
	"strings"
)

// Canonical CrowdSec scope strings after normalizeScope.
const (
	scopeIP      = "Ip"
	scopeRange   = "Range"
	scopeCountry = "Country"
	scopeAS      = "AS"
)

// normalizeScope returns the CrowdSec stored spelling for ip, range, country, and AS.
func normalizeScope(scope string) string {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "ip":
		return scopeIP
	case "range":
		return scopeRange
	case "country":
		return scopeCountry
	case "as":
		return scopeAS
	default:
		return strings.TrimSpace(scope)
	}
}

// normalizeCountry returns an upper-case ISO 3166-1 alpha-2 code, or empty if unusable.
func normalizeCountry(value string) string {
	code := strings.ToUpper(strings.TrimSpace(value))
	if len(code) != 2 {
		return ""
	}
	if code == "XX" || code == "T1" {
		return ""
	}
	for _, char := range code {
		if char < 'A' || char > 'Z' {
			return ""
		}
	}
	return code
}

// normalizeASN returns decimal ASN digits, stripping an optional AS/as prefix.
func normalizeASN(value string) string {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) >= 2 && strings.EqualFold(trimmed[:2], "as") {
		trimmed = strings.TrimSpace(trimmed[2:])
	}
	if trimmed == "" {
		return ""
	}
	for _, char := range trimmed {
		if char < '0' || char > '9' {
			return ""
		}
	}
	return trimmed
}

// headerScopeKey is the shared-cache key for a header-matched scope (Country, AS, or custom).
func headerScopeKey(scope, value string) string {
	return strings.ToLower(scope) + ":" + value
}

// normalizeDecisionScopeHeaders keeps configured header scopes. Ip and Range are not header scopes.
func normalizeDecisionScopeHeaders(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for rawScope, rawHeader := range in {
		header := strings.TrimSpace(rawHeader)
		if header == "" {
			continue
		}
		scope := normalizeScope(rawScope)
		if scope == "" || scope == scopeIP || scope == scopeRange {
			continue
		}
		out[scope] = header
	}
	return out
}

// ipCacheKey is the cache key for an Ip-scoped decision value (bare IP or /32 / /128).
func ipCacheKey(value string) string {
	trimmed := strings.TrimSpace(value)
	ipAddr, ipNet, err := net.ParseCIDR(trimmed)
	if err != nil {
		return trimmed
	}
	ones, bits := ipNet.Mask.Size()
	if ones == bits {
		return ipAddr.String()
	}
	return trimmed
}
