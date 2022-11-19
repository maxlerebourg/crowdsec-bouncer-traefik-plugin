// Package cache implements utility routines for manipulating cache.
// It supports currently local file and redis cache.
package cache

import (
	"fmt"

	ttl_map "github.com/leprosus/golang-ttl-map"

	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
	simpleredis "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/simpleredis"
)

const (
	cacheBannedValue   = "t"
	cacheNoBannedValue = "f"
)

var cache = ttl_map.New()
var redis simpleredis.SimpleRedis

var redisEnabled = false

// CLASSIC

func getDecisionLocalCache(clientIP string) (bool, error) {
	banned, isCached := cache.Get(clientIP)
	bannedString, isValid := banned.(string)
	if isCached && isValid && len(bannedString) > 0 {
		return bannedString == cacheBannedValue, nil
	}
	return false, fmt.Errorf("cache:miss")
}

func setDecisionLocalCache(clientIP string, value string, duration int64) {
	cache.Set(clientIP, value, duration)
}

func deleteDecisionLocalCache(clientIP string) {
	cache.Del(clientIP)
}

// REDIS

func getDecisionRedisCache(clientIP string) (bool, error) {
	banned, err := redis.Get(clientIP)
	bannedString := string(banned)
	if err == nil && len(bannedString) > 0 {
		return bannedString == cacheBannedValue, nil
	}
	return false, err
}

func setDecisionRedisCache(clientIP string, value string, duration int64) {
	if err := redis.Set(clientIP, []byte(value), duration); err != nil {
		logger.Error(fmt.Sprintf("cache:setDecisionRedisCache %s", err.Error()))
	}
}

func deleteDecisionRedisCache(clientIP string) {
	if err := redis.Del(clientIP); err != nil {
		logger.Error(fmt.Sprintf("cache:deleteDecisionRedisCache %s", err.Error()))
	}
}

// DeleteDecision delete decision in cache.
func DeleteDecision(clientIP string) {
	if redisEnabled {
		deleteDecisionRedisCache(clientIP)
	} else {
		deleteDecisionLocalCache(clientIP)
	}
}

// GetDecision check in the cache if the IP has the banned / not banned value.
// Otherwise return with an error to add the IP in cache if we are on.
func GetDecision(clientIP string) (bool, error) {
	if redisEnabled {
		return getDecisionRedisCache(clientIP)
	}
	return getDecisionLocalCache(clientIP)
}

// SetDecision update the cache with the IP as key and the value banned / not banned.
func SetDecision(clientIP string, isBanned bool, duration int64) {
	var value string
	if isBanned {
		logger.Debug(fmt.Sprintf("cache:SetDecision ip:%v banned", clientIP))
		value = cacheBannedValue
	} else {
		value = cacheNoBannedValue
	}
	if redisEnabled {
		setDecisionRedisCache(clientIP, value, duration)
	} else {
		setDecisionLocalCache(clientIP, value, duration)
	}
}

// InitRedisClient loads variables.
func InitRedisClient(host string) {
	redisEnabled = true
	redis.Init(host)
	logger.Debug("cache:InitRedisClient redis:initialized")
}
