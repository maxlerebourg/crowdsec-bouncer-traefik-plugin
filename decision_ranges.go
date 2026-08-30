package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"strings"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	ip "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/ip"
)

const (
	countryKeyPrefix = "country:"
	asKeyPrefix      = "as:"
	rangeKeyPrefix   = "range:"
	rangeIndexKey    = "range-index"
	rangeIndexTTL    = 365 * 24 * 3600
)

func countryKey(country string) string {
	return countryKeyPrefix + country
}

func asKey(asn string) string {
	return asKeyPrefix + asn
}

func rangeKey(cidr string) string {
	return rangeKeyPrefix + cidr
}

// addRange stores a Range decision and lists its CIDR on the shared index.
func addRange(cacheClient *cache.Client, cidr, remediation string, duration int64) {
	network := strings.TrimSpace(cidr)
	if network == "" {
		return
	}
	cacheClient.Set(rangeKey(network), remediation, duration)
	index := readRangeIndex(cacheClient)
	if !indexHasCIDR(index, network) {
		if index == "" {
			index = network
		} else {
			index = index + "\n" + network
		}
	}
	cacheClient.Set(rangeIndexKey, index, rangeIndexTTL)
}

// removeRange drops a Range decision and removes its CIDR from the index.
func removeRange(cacheClient *cache.Client, cidr string) {
	network := strings.TrimSpace(cidr)
	cacheClient.Delete(rangeKey(network))
	index := readRangeIndex(cacheClient)
	next := removeCIDRFromIndex(index, network)
	if next == "" {
		cacheClient.Delete(rangeIndexKey)
		return
	}
	cacheClient.Set(rangeIndexKey, next, rangeIndexTTL)
}

// matchRange returns the remediation for a containing CIDR. Ban wins if several match.
func matchRange(cacheClient *cache.Client, remoteIP string) string {
	index := readRangeIndex(cacheClient)
	if index == "" {
		return ""
	}
	chosen := ""
	for _, network := range strings.Split(index, "\n") {
		if network == "" {
			continue
		}
		inside, err := ip.InNetwork(remoteIP, network)
		if err != nil || !inside {
			continue
		}
		remediation, err := cacheClient.Get(rangeKey(network))
		if err != nil {
			continue
		}
		if remediation == cache.BannedValue {
			return cache.BannedValue
		}
		if chosen == "" {
			chosen = remediation
		}
	}
	return chosen
}

func readRangeIndex(cacheClient *cache.Client) string {
	index, err := cacheClient.Get(rangeIndexKey)
	if err != nil {
		return ""
	}
	return index
}

func indexHasCIDR(index, cidr string) bool {
	for _, network := range strings.Split(index, "\n") {
		if network == cidr {
			return true
		}
	}
	return false
}

func removeCIDRFromIndex(index, cidr string) string {
	kept := make([]string, 0)
	for _, network := range strings.Split(index, "\n") {
		if network == "" || network == cidr {
			continue
		}
		kept = append(kept, network)
	}
	return strings.Join(kept, "\n")
}
