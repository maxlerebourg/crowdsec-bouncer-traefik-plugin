package ip

import (
	"net"
	"strconv"
	"strings"
)

// CIDRKeys returns all possible CIDR prefixes of an IP, from the most specific (/32 for IPv4, /128 for IPv6) to the least specific (/0).
func CIDRKeys(ipStr string) []string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}
	ip4 := ip.To4()
	if ip4 != nil {
		keys := make([]string, 0, 33)
		for bits := 32; bits >= 0; bits-- {
			mask := net.CIDRMask(bits, 32)
			n := make(net.IP, 4)
			for i := 0; i < 4; i++ {
				n[i] = ip4[i] & mask[i]
			}
			keys = append(keys, n.String()+"/"+strconv.Itoa(bits))
		}
		return keys
	}
	ip16 := ip.To16()
	keys := make([]string, 0, 129)
	for bits := 128; bits >= 0; bits-- {
		mask := net.CIDRMask(bits, 128)
		n := make(net.IP, 16)
		for i := 0; i < 16; i++ {
			n[i] = ip16[i] & mask[i]
		}
		keys = append(keys, n.String()+"/"+strconv.Itoa(bits))
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
