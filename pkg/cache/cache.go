package cache

import (
	"context"
	"fmt"

	ttl_map "github.com/leprosus/golang-ttl-map"

	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
	redis "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/redis"
)

const (
	cacheBannedValue   = "t"
	cacheNoBannedValue = "f"
)

var ctx = context.Background()
var cache = ttl_map.New()


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
	// banned, err := redis.Do(ctx, redis.B().Get().Key("key").Build()).ToString()
	// if err != nil {
	// 	return false, fmt.Errorf("no cache data")
	// } else {
	// 	return banned == cacheBannedValue, nil
	// }
	return false, nil
}

func SetDecisionRedisCache(clientIP string, value string, duration int64) {
	// ctx := context.Background()
	// redis.Do(ctx, redis.B().Set().Key("key").Value("val").Nx().Build()).Error()
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

func InitRedisClient(host string, password string) error {
	// redis, err := rueidis.NewClient(rueidis.ClientOption{
	// 	InitAddress: []string{host},
	// })
	// if err != nil {
	// 	return fmt.Errorf("error instanciate redis: %w", err)
	// }
	// redisEnabled = true
	writter, reader := redis.Init(host, password)
	// writter.PrintfLine("[caca, true, caca]")
	return nil
}
