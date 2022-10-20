package cache

import (
	"context"
	"fmt"

	ttl_map "github.com/leprosus/golang-ttl-map"

	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
	simpleredis "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/redis"
)

const (
	cacheBannedValue   = "t"
	cacheNoBannedValue = "f"
)

var cache = ttl_map.New()
var redis simpleredis.SimpleRedis

var redisEnabled = false


func getDecisionLocalCache(clientIP string) (bool, error) {
	banned, isCached := cache.Get(clientIP)
	bannedString, isValid := banned.(string)
	if isCached && isValid && len(bannedString) > 0 {
		return bannedString == cacheBannedValue, nil
	}
	return false, fmt.Errorf("no cache data")
}

func SetDecisionLocalCache(clientIP string, value string, duration int64) {
	cache.Set(clientIP, value, duration)
}

func DeleteDecisionLocalCache(clientIP string) {
	cache.Del(clientIP)
}

func getDecisionRedisCache(clientIP string) (bool, error) {
	banned, err := redis.Do("GET", clientIP, nil)
	bannedString := string(banned)
	logger.Info(fmt.Sprintf("%v banned", bannedString))
	if err == nil && len(bannedString) > 0 {
		return bannedString == cacheBannedValue, nil
	}
	return false, fmt.Errorf("no cache data")
}

func SetDecisionRedisCache(clientIP string, value string, duration int64) {
	redis.Do("SET", clientIP, []byte(value))
}

func DeleteDecisionRedisCache(clientIP string) {
	// err := rdb.Del(ctx, clientIP).Err()
	// if err != nil {
	// 	logger.Info("Error, could not delete in redis cache IP")
	// }
	// errors are not handled
}



func DeleteDecision(clientIP string) {
	if redisEnabled {
		DeleteDecisionRedisCache(clientIP)
	} else {
		DeleteDecisionLocalCache(clientIP)
	}
}
// Get Decision check in the cache if the IP has the banned / not banned value.
// Otherwise return with an error to add the IP in cache if we are on.
func GetDecision(clientIP string) (bool, error) {
	if redisEnabled {
		return getDecisionRedisCache(clientIP)
	} else {
		return getDecisionLocalCache(clientIP)
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

func InitRedisClient(host string, password string) {
	logger.Debug("connect to redis")
	redisEnabled = true
	redis.Init(host)
}
