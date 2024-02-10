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
)

// CacheMiss error string when cache is miss.
const CacheMiss = "cache:miss"

//nolint:gochecknoglobals
var (
	redis simpleredis.SimpleRedis
	cache = ttl_map.New()
)

type localCache struct{}

func (localCache) getDecision(clientIP string) (bool, error) {
	banned, isCached := cache.Get(clientIP)
	bannedString, isValid := banned.(string)
	if isCached && isValid && len(bannedString) > 0 {
		return bannedString == cacheBannedValue, nil
	}
	return false, fmt.Errorf(CacheMiss)
}

func (localCache) setDecision(clientIP string, value string, duration int64) {
	cache.Set(clientIP, value, duration)
}

func (localCache) deleteDecision(clientIP string) {
	cache.Del(clientIP)
}

type redisCache struct{
	log *logger.Log
}

func (redisCache) getDecision(clientIP string) (bool, error) {
	banned, err := redis.Get(clientIP)
	bannedString := string(banned)
	if err == nil && len(bannedString) > 0 {
		return bannedString == cacheBannedValue, nil
	}
	if err.Error() == simpleredis.RedisMiss {
		return false, fmt.Errorf(CacheMiss)
	}
	return false, err
}

func (rc redisCache) setDecision(clientIP string, value string, duration int64) {
	if err := redis.Set(clientIP, []byte(value), duration); err != nil {
		rc.log.Error(fmt.Sprintf("cache:setDecisionRedisCache %s", err.Error()))
	}
}

func (rc redisCache) deleteDecision(clientIP string) {
	if err := redis.Del(clientIP); err != nil {
		rc.log.Error(fmt.Sprintf("cache:deleteDecisionRedisCache %s", err.Error()))
	}
}

type cacheInterface interface {
	setDecision(clientIP string, value string, duration int64)
	getDecision(clientIP string) (bool, error)
	deleteDecision(clientIP string)
}

// Client Cache client.
type Client struct {
	cache cacheInterface
	log   *logger.Log
}

// Init Initialize cache client.
func (c *Client) Init(log *logger.Log, isRedis bool, host, pass, database string) {
	c.log = log
	if isRedis {
		redis.Init(host, pass, database)
		c.cache = &redisCache{log: log}
	} else {
		c.cache = &localCache{}
	}
	c.log.Debug(fmt.Sprintf("cache:New initialized isRedis:%v", isRedis))
}

// DeleteDecision delete decision in cache.
func (c *Client) DeleteDecision(clientIP string) {
	c.log.Debug(fmt.Sprintf("cache:DeleteDecision ip:%v", clientIP))
	c.cache.deleteDecision(clientIP)
}

// GetDecision check in the cache if the IP has the banned / not banned value.
// Otherwise return with an error to add the IP in cache if we are on.
func (c *Client) GetDecision(clientIP string) (bool, error) {
	c.log.Debug(fmt.Sprintf("cache:GetDecision ip:%v", clientIP))
	return c.cache.getDecision(clientIP)
}

// SetDecision update the cache with the IP as key and the value banned / not banned.
func (c *Client) SetDecision(clientIP string, isBanned bool, duration int64) {
	c.log.Debug(fmt.Sprintf("cache:SetDecision ip:%v isBanned:%v duration:%vs", clientIP, isBanned, duration))
	var value string
	if isBanned {
		value = cacheBannedValue
	} else {
		value = cacheNoBannedValue
	}
	c.cache.setDecision(clientIP, value, duration)
}
