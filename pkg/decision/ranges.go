package decision

import (
	"strings"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	ip "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/ip"
)

// AddRange stores a Range decision and lists its CIDR on the shared index.
func AddRange(cacheClient *cache.Client, cidr, remediation string, duration int64) {
	network := strings.TrimSpace(cidr)
	if network == "" {
		return
	}
	cacheClient.Set(RangeKey(network), remediation, duration)
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

// RemoveRange drops a Range decision and removes its CIDR from the index.
func RemoveRange(cacheClient *cache.Client, cidr string) {
	network := strings.TrimSpace(cidr)
	cacheClient.Delete(RangeKey(network))
	index := readRangeIndex(cacheClient)
	next := removeCIDRFromIndex(index, network)
	if next == "" {
		cacheClient.Delete(rangeIndexKey)
		return
	}
	cacheClient.Set(rangeIndexKey, next, rangeIndexTTL)
}

// MatchRange returns the remediation for the first containing CIDR.
// Ban wins if several ranges match.
func MatchRange(cacheClient *cache.Client, remoteIP string) string {
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
		remediation, err := cacheClient.Get(RangeKey(network))
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
