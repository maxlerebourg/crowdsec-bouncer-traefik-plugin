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
	BannedValue   = "t"
	CaptchaValue  = "c"
	NoBannedValue = "f"
)

// CacheMiss error string when cache is miss.
const CacheMiss = "cache:miss"

//nolint:gochecknoglobals
var (
	redis simpleredis.SimpleRedis
	cache = ttl_map.New()
)

type localCache struct{}

func (localCache) get(clientIP string) (string, error) {
	value, isCached := cache.Get(clientIP)
	valueString, isValid := value.(string)
	if isCached && isValid && len(valueString) > 0 {
		return valueString, nil
	}
	return NoBannedValue, fmt.Errorf(CacheMiss)
}

func (localCache) set(clientIP string, value string, duration int64) {
	cache.Set(clientIP, value, duration)
}

func (localCache) delete(clientIP string) {
	cache.Del(clientIP)
}

type redisCache struct{}

func (redisCache) get(clientIP string) (string, error) {
	banned, err := redis.Get(clientIP)
	bannedString := string(banned)
	if err == nil && len(bannedString) > 0 {
		return bannedString, nil
	}
	if err.Error() == simpleredis.RedisMiss {
		return NoBannedValue, fmt.Errorf(CacheMiss)
	}
	return NoBannedValue, err
}

func (redisCache) set(clientIP string, value string, duration int64) {
	if err := redis.Set(clientIP, []byte(value), duration); err != nil {
		logger.Error(fmt.Sprintf("cache:setDecisionRedisCache %s", err.Error()))
	}
}

func (redisCache) delete(clientIP string) {
	if err := redis.Del(clientIP); err != nil {
		logger.Error(fmt.Sprintf("cache:deleteDecisionRedisCache %s", err.Error()))
	}
}

type cacheInterface interface {
	set(clientIP string, value string, duration int64)
	get(clientIP string) (string, error)
	delete(clientIP string)
}

// Client Cache client.
type Client struct {
	cache cacheInterface
}

func (c *Client) Debug(message string) {
	logger.Debug(fmt.Sprintf("cacheClient: %s", message))
}

// New Initialize cache client.
func (c *Client) New(isRedis bool, host, pass, database string) {
	if isRedis {
		redis.Init(host, pass, database)
		c.cache = &redisCache{}
	} else {
		c.cache = &localCache{}
	}
	c.Debug(fmt.Sprintf("New initialized isRedis:%v", isRedis))
}

// DeleteDecision delete decision in cache.
func (c *Client) Delete(key string) {
	c.Debug(fmt.Sprintf("Delete key:%v", key))
	c.cache.delete(key)
}

// GetDecision check in the cache if the IP has the banned / not banned value.
// Otherwise return with an error to add the IP in cache if we are on.
func (c *Client) Get(clientIP string) (string, error) {
	c.Debug(fmt.Sprintf("Get key:%v", clientIP))
	return c.cache.get(clientIP)
}

// SetDecision update the cache with the IP as key and the value banned / not banned.
func (c *Client) Set(key string, value string, duration int64) {
	c.cache.set(key, value, duration)
}
