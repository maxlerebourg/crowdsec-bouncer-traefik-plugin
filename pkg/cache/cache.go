// Package cache implements utility routines for manipulating cache.
// It supports currently local file and redis cache.
package cache

import (
	"errors"
	"fmt"

	ttl_map "github.com/leprosus/golang-ttl-map"
	simpleredis "github.com/maxlerebourg/simpleredis"

	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

const (
	// BannedValue Banned string.
	BannedValue = "t"
	// NoBannedValue No banned string.
	NoBannedValue = "f"
	// CaptchaValue Need captcha string.
	CaptchaValue = "c"
	// CaptchaDoneValue Captcha done string.
	CaptchaDoneValue = "d"
	// CacheMiss error string when cache is miss.
	CacheMiss = "cache:miss"
	// CacheUnreachable error string when cache is unreachable.
	CacheUnreachable = "cache:unreachable"
)

//nolint:gochecknoglobals
var (
	redis simpleredis.SimpleRedis
	cache = ttl_map.New()
)

type localCache struct{}

func (localCache) get(key string) (string, error) {
	value, isCached := cache.Get(key)
	valueString, isValid := value.(string)
	if isCached && isValid && len(valueString) > 0 {
		return valueString, nil
	}
	return "", errors.New(CacheMiss)
}

func (localCache) set(key, value string, duration int64) {
	cache.Set(key, value, duration)
}

func (localCache) delete(key string) {
	cache.Del(key)
}

type redisCache struct {
	log *logger.Log
}

func (redisCache) get(key string) (string, error) {
	value, err := redis.Get(key)
	valueString := string(value)
	if err == nil && len(valueString) > 0 {
		return valueString, nil
	}
	errRedisMessage := err.Error()
	if errRedisMessage == simpleredis.RedisMiss {
		return "", errors.New(CacheMiss)
	}
	if errRedisMessage == simpleredis.RedisUnreachable {
		return "", errors.New(CacheUnreachable)
	}
	return "", err
}

func (rc redisCache) set(key, value string, duration int64) {
	if err := redis.Set(key, []byte(value), duration); err != nil {
		rc.log.Error("cache:setDecisionRedisCache" + err.Error())
	}
}

func (rc redisCache) delete(key string) {
	if err := redis.Del(key); err != nil {
		rc.log.Error("cache:deleteDecisionRedisCache " + err.Error())
	}
}

type cacheInterface interface {
	set(key, value string, duration int64)
	get(key string) (string, error)
	delete(key string)
}

// Client Cache client.
type Client struct {
	cache cacheInterface
	log   *logger.Log
}

// New Initialize cache client.
func (c *Client) New(log *logger.Log, isRedis bool, host, pass, database string) {
	c.log = log
	if isRedis {
		redis.Init(host, pass, database)
		c.cache = &redisCache{log: log}
	} else {
		c.cache = &localCache{}
	}
	c.log.Debug(fmt.Sprintf("cache:New initialized isRedis:%v", isRedis))
}

// Delete delete decision in cache.
func (c *Client) Delete(key string) {
	c.log.Trace(fmt.Sprintf("cache:Delete key:%v", key))
	c.cache.delete(key)
}

// Get check in the cache if the IP has the banned / not banned value.
// Otherwise return with an error to add the IP in cache if we are on.
func (c *Client) Get(key string) (string, error) {
	c.log.Trace(fmt.Sprintf("cache:Get key:%v", key))
	return c.cache.get(key)
}

// Set update the cache with the IP as key and the value banned / not banned.
func (c *Client) Set(key string, value string, duration int64) {
	c.log.Trace(fmt.Sprintf("cache:Set key:%v value:%v duration:%vs", key, value, duration))
	c.cache.set(key, value, duration)
}
