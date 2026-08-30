// Package decision normalizes CrowdSec decision scopes and matches them in cache.
package decision

import (
	"net"
	"strings"
)

// Canonical CrowdSec scope strings after NormalizeScope.
const (
	ScopeIP      = "Ip"
	ScopeRange   = "Range"
	ScopeCountry = "Country"
	ScopeAS      = "AS"
)

// NormalizeScope returns the CrowdSec stored spelling for ip, range, country, and AS.
// Any other string is returned trimmed as-is (open scope).
func NormalizeScope(scope string) string {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "ip":
		return ScopeIP
	case "range":
		return ScopeRange
	case "country":
		return ScopeCountry
	case "as":
		return ScopeAS
	default:
		return strings.TrimSpace(scope)
	}
}

// NormalizeCountry returns an upper-case ISO 3166-1 alpha-2 code, or empty if unusable.
// Cloudflare placeholders XX and T1 are treated as unknown.
func NormalizeCountry(value string) string {
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

// NormalizeASN returns decimal ASN digits, stripping an optional AS/as prefix.
func NormalizeASN(value string) string {
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

// IPCacheKey is the cache key for an Ip-scoped decision value (bare IP or /32 / /128).
func IPCacheKey(value string) string {
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
