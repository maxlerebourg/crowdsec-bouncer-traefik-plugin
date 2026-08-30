package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"strings"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	ip "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/ip"
)

const (
	countryKeyPrefix = "country:"
	asKeyPrefix      = "as:"
	rangeIndexKey    = "range-index"
	rangeIndexTTL    = 365 * 24 * 3600
)

func countryKey(country string) string {
	return countryKeyPrefix + country
}

func asKey(asn string) string {
	return asKeyPrefix + asn
}

// addRange upserts a Range decision on the shared index as cidr=remediation.
func addRange(cacheClient *cache.Client, cidr, remediation string, _ int64) {
	network := strings.TrimSpace(cidr)
	if network == "" || !isActiveRemediation(remediation) {
		return
	}
	index := upsertIndexCIDR(readRangeIndex(cacheClient), network, remediation)
	cacheClient.Set(rangeIndexKey, index, rangeIndexTTL)
}

// removeRange drops a Range decision from the shared index.
func removeRange(cacheClient *cache.Client, cidr string) {
	next := removeCIDRFromIndex(readRangeIndex(cacheClient), strings.TrimSpace(cidr))
	if next == "" {
		cacheClient.Delete(rangeIndexKey)
		return
	}
	cacheClient.Set(rangeIndexKey, next, rangeIndexTTL)
}

// matchRange returns the remediation for a containing CIDR. Ban wins if several match.
func matchRange(cacheClient *cache.Client, remoteIP string) string {
	return matchRangeFromIndex(readRangeIndex(cacheClient), remoteIP)
}

// matchRangeFromIndex walks cidr=remediation lines. Ban wins if several match.
func matchRangeFromIndex(index, remoteIP string) string {
	if index == "" {
		return ""
	}
	chosen := ""
	for _, line := range strings.Split(index, "\n") {
		network, remediation := parseIndexLine(line)
		if network == "" || !isActiveRemediation(remediation) {
			continue
		}
		inside, err := ip.InNetwork(remoteIP, network)
		if err != nil || !inside {
			continue
		}
		chosen = preferRemediation(chosen, remediation)
		if chosen == cache.BannedValue {
			return cache.BannedValue
		}
	}
	return chosen
}

func parseIndexLine(line string) (string, string) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", ""
	}
	network, remediation, ok := strings.Cut(trimmed, "=")
	if !ok {
		return trimmed, ""
	}
	return network, remediation
}

func upsertIndexCIDR(index, cidr, remediation string) string {
	kept := make([]string, 0)
	replaced := false
	for _, line := range strings.Split(index, "\n") {
		existing, existingRem := parseIndexLine(line)
		if existing == "" {
			continue
		}
		if existing == cidr {
			kept = append(kept, cidr+"="+remediation)
			replaced = true
			continue
		}
		if existingRem == "" {
			kept = append(kept, existing)
			continue
		}
		kept = append(kept, existing+"="+existingRem)
	}
	if !replaced {
		kept = append(kept, cidr+"="+remediation)
	}
	return strings.Join(kept, "\n")
}

func readRangeIndex(cacheClient *cache.Client) string {
	index, err := cacheClient.Get(rangeIndexKey)
	if err != nil {
		return ""
	}
	return index
}

func removeCIDRFromIndex(index, cidr string) string {
	kept := make([]string, 0)
	for _, line := range strings.Split(index, "\n") {
		network, remediation := parseIndexLine(line)
		if network == "" || network == cidr {
			continue
		}
		if remediation == "" {
			kept = append(kept, network)
			continue
		}
		kept = append(kept, network+"="+remediation)
	}
	return strings.Join(kept, "\n")
}
