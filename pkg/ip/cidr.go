package ip

import (
	"net"
	"strings"
)

// CIDRKeys returns all possible CIDR prefixes of an IP, from the most specific (/32 for IPv4, /128 for IPv6) to the least specific (/0).
func CIDRKeys(ipStr string) []string {
	parsed, maxBits := parseForPrefix(ipStr)
	if parsed == nil {
		return nil
	}
	keys := make([]string, 0, maxBits+1)
	for bits := maxBits; bits >= 0; bits-- {
		keys = append(keys, cidrKey(parsed, bits, maxBits))
	}
	return keys
}

// NormalizeCIDR parses a CIDR string and returns its normalized form, or an empty string if invalid.
func NormalizeCIDR(cidrStr string) string {
	_, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidrStr))
	if err != nil {
		return ""
	}
	return ipNet.String()
}

// parseForPrefix returns the IP in the native form of its family, and that family's bit length.
func parseForPrefix(ipStr string) (net.IP, int) {
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return nil, 0
	}
	if parsed4 := parsed.To4(); parsed4 != nil {
		return parsed4, 32
	}
	return parsed.To16(), 128
}

// cidrKey builds the key of the CIDR of bits length containing the IP.
// It formats through net.IPNet like NormalizeCIDR, so writes and lookups agree.
func cidrKey(parsed net.IP, bits, maxBits int) string {
	mask := net.CIDRMask(bits, maxBits)
	ipNet := net.IPNet{IP: parsed.Mask(mask), Mask: mask}
	return ipNet.String()
}
