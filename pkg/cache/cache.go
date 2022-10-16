package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v9"
	ttl_map "github.com/leprosus/golang-ttl-map"

	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

const (
	cacheBannedValue   = "t"
	cacheNoBannedValue = "f"
)

var ctx = context.Background()
var cache = ttl_map.New()
var rdb *redis.Client
var redisEnabled = false

// Get Decision check in the cache if the IP has the banned / not banned value.
// Otherwise return with an error to add the IP in cache if we are on.
func GetDecision(clientIP string) (bool, error) {
	if redisEnabled {
		return getDecisionRedisCache(clientIP)
	} else {
		return getDecisionLocalCache(clientIP)
	}
}

func getDecisionLocalCache(clientIP string) (bool, error) {
	banned, isCached := cache.Get(clientIP)
	bannedString, isValid := banned.(string)
	if isCached && isValid && len(bannedString) > 0 {
		return bannedString == cacheBannedValue, nil
	}
	return false, fmt.Errorf("no cache data")
}

func getDecisionRedisCache(clientIP string) (bool, error) {
	banned, err := rdb.Get(ctx, clientIP).Result()
	if err != nil {
		return false, fmt.Errorf("no cache data")
	} else {
		return banned == cacheBannedValue, nil
	}
}

func SetDecision(clientIP string, isBanned bool, duration int64) {
	var value string
	if isBanned {
		logger.Debug(fmt.Sprintf("%v banned", clientIP))
		value = cacheBannedValue
	} else {
		value = cacheNoBannedValue
	}
	if redisEnabled {
		SetDecisionRedisCache(clientIP, value, duration)
	} else {
		SetDecisionLocalCache(clientIP, value, duration)
	}
}

func SetDecisionRedisCache(clientIP string, value string, duration int64) {
	err := rdb.Set(ctx, clientIP, value, time.Duration(duration)).Err()
	if err != nil {
		logger.Info("Error, could not insert in redis cache IP")
	}
	// errors are not handled
}

func SetDecisionLocalCache(clientIP string, value string, duration int64) {
	cache.Set(clientIP, value, duration)
}

func DeleteDecision(clientIP string) {
	if redisEnabled {
		DeleteDecisionRedisCache(clientIP)
	} else {
		DeleteDecisionLocalCache(clientIP)
	}

}

func DeleteDecisionRedisCache(clientIP string) {
	err := rdb.Del(ctx, clientIP).Err()
	if err != nil {
		logger.Info("Error, could not delete in redis cache IP")
	}
	// errors are not handled
}

func DeleteDecisionLocalCache(clientIP string) {
	cache.Del(clientIP)
}

func InitRedisClient(addr string, port int, password string) {
	rdb = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%v:%d", addr, port),
		Password: password,
		DB:       0, // use default DB
	})
	redisEnabled = true
}
