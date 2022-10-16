package cache

import (
	"fmt"

	ttl_map "github.com/leprosus/golang-ttl-map"

	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)
const (
	cacheBannedValue        = "t"
	cacheNoBannedValue      = "f"
)

var cache = ttl_map.New()

// Get Decision check in the cache if the IP has the banned / not banned value.
// Otherwise return with an error to add the IP in cache if we are on.
func GetDecision(clientIP string) (bool, error) {
	banned, isCached := cache.Get(clientIP)
	bannedString, isValid := banned.(string)
	if isCached && isValid && len(bannedString) > 0 {
		return bannedString == cacheBannedValue, nil
	}
	return false, fmt.Errorf("no cache data")
}

func SetDecision(clientIP string, isBanned bool, duration int64) {
	if isBanned {
		logger.Debug(fmt.Sprintf("%v banned", clientIP))
		cache.Set(clientIP, cacheBannedValue, duration)
	} else {
		cache.Set(clientIP, cacheNoBannedValue, duration)
	}
}

func DeleteDecision(clientIP string) {
	cache.Del(clientIP)
}
