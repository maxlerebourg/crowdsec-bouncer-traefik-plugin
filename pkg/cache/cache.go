// Package cache implements utility routines for manipulating cache.
// It supports currently local file and redis cache.
package cache

import (
	"fmt"

	ttl_map "github.com/leprosus/golang-ttl-map"
	simpleredis "github.com/maxlerebourg/simpleredis"

	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

const (
	cacheBannedValue   = "t"
	cacheNoBannedValue = "f"
	cacheCaptchaValue  = "c"
	CacheMiss          = "cache:miss" // CacheMiss error string when cache is miss.
)

//nolint:gochecknoglobals
var (
	redis simpleredis.SimpleRedis
	cache = ttl_map.New()
)

type localCache struct{}

func (localCache) getDecision(clientIP string) (bool, bool, error) {
	banned, isCached := cache.Get(clientIP)
	bannedString, isValid := banned.(string)
	logger.Debug(fmt.Sprintf("cache:getDecision:bannedString '%s', isValid '%t', isCached '%t'", bannedString, isValid, isCached))
	if isCached && isValid && len(bannedString) > 0 {
		isBanned := bannedString == cacheBannedValue || bannedString == cacheCaptchaValue
		isCaptcha := bannedString == cacheCaptchaValue
		return isBanned, isCaptcha, nil
	}
	return false, false, fmt.Errorf(CacheMiss)
}

func (localCache) setDecision(clientIP string, value string, duration int64) {
	cache.Set(clientIP, value, duration)
}

func (localCache) deleteDecision(clientIP string) {
	cache.Del(clientIP)
}

type redisCache struct{}

func (redisCache) getDecision(clientIP string) (bool, bool, error) {
	banned, err := redis.Get(clientIP)
	bannedString := string(banned)
	if err == nil && len(bannedString) > 0 {
		isBanned := bannedString == cacheBannedValue || bannedString == cacheCaptchaValue
		isCaptcha := bannedString == cacheCaptchaValue
		return isBanned, isCaptcha, nil
	}
	if err.Error() == simpleredis.RedisMiss {
		return false, false, fmt.Errorf(CacheMiss)
	}
	return false, false, err
}

func (redisCache) setDecision(clientIP string, value string, duration int64) {
	if err := redis.Set(clientIP, []byte(value), duration); err != nil {
		logger.Error(fmt.Sprintf("cache:setDecisionRedisCache %s", err.Error()))
	}
}

func (redisCache) deleteDecision(clientIP string) {
	if err := redis.Del(clientIP); err != nil {
		logger.Error(fmt.Sprintf("cache:deleteDecisionRedisCache %s", err.Error()))
	}
}

type cacheInterface interface {
	setDecision(clientIP string, value string, duration int64)
	getDecision(clientIP string) (bool, bool, error)
	deleteDecision(clientIP string)
}

// Client Cache client.
type Client struct {
	cache cacheInterface
}

// New Initialize cache client.
func (client *Client) New(isRedis bool, host, pass, database string) {
	if isRedis {
		redis.Init(host, pass, database)
		client.cache = &redisCache{}
	} else {
		client.cache = &localCache{}
	}
	logger.Debug(fmt.Sprintf("cache:New initialized isRedis:%v", isRedis))
}

// DeleteDecision delete decision in cache.
func (client *Client) DeleteDecision(clientIP string) {
	logger.Debug(fmt.Sprintf("cache:DeleteDecision ip:%v", clientIP))
	client.cache.deleteDecision(clientIP)
}

// GetDecision check in the cache if the IP has the banned / not banned value.
// Otherwise, return with an error to add the IP in cache if we are on.
func (client *Client) GetDecision(clientIP string) (bool, bool, error) {
	logger.Debug(fmt.Sprintf("cache:GetDecision ip:%v", clientIP))
	return client.cache.getDecision(clientIP)
}

// SetDecision update the cache with the IP as key and the value banned / not banned.
func (client *Client) SetDecision(clientIP string, banDecision string, duration int64) {
	logger.Debug(fmt.Sprintf("cache:SetDecision ip:%v banDecision:%v duration:%vs", clientIP, banDecision, duration))
	client.cache.setDecision(clientIP, banDecision, duration)
}
