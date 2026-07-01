// Package cache implements utility routines for manipulating cache.
// It supports currently local file and redis cache.
package cache

import (
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"

	ttl_map "github.com/leprosus/golang-ttl-map"
	simpleredis "github.com/maxlerebourg/simpleredis"
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
var cache = ttl_map.New()

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
	log     *slog.Logger
	writer  simpleredis.SimpleRedis
	readers []simpleredis.SimpleRedis
	counter atomic.Uint64
}

func (rc *redisCache) nextReader() *simpleredis.SimpleRedis {
	n := len(rc.readers)
	if n == 0 {
		return &rc.writer
	}
	idx := rc.counter.Add(1) % uint64(n)
	return &rc.readers[idx]
}

func redisResultToString(value []byte, err error) (string, error) {
	if err == nil {
		valueString := string(value)
		if len(valueString) > 0 {
			return valueString, nil
		}
	}
	if err != nil {
		switch err.Error() {
		case simpleredis.RedisMiss:
			return "", errors.New(CacheMiss)
		case simpleredis.RedisUnreachable:
			return "", errors.New(CacheUnreachable)
		}
		return "", err
	}
	return "", errors.New(CacheMiss)
}

func (rc *redisCache) get(key string) (string, error) {
	value, err := rc.nextReader().Get(key)
	return redisResultToString(value, err)
}

func (rc *redisCache) set(key, value string, duration int64) {
	if err := rc.writer.Set(key, []byte(value), duration); err != nil {
		rc.log.Error("cache:setDecisionRedisCache" + err.Error())
	}
}

func (rc *redisCache) delete(key string) {
	if err := rc.writer.Del(key); err != nil {
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
	log   *slog.Logger
}

// New Initialize cache client.
func (c *Client) New(log *slog.Logger, isRedis bool, writeHost string, readHosts []string, pass, database string) {
	c.log = log
	if isRedis {
		rc := &redisCache{log: log}
		rc.writer.Init(writeHost, pass, database)
		for _, h := range readHosts {
			var r simpleredis.SimpleRedis
			r.Init(h, pass, database)
			rc.readers = append(rc.readers, r)
		}
		c.cache = rc
	} else {
		c.cache = &localCache{}
	}
	c.log.Debug(fmt.Sprintf("cache:New initialized isRedis:%v writeHost:%v readHosts:%v", isRedis, writeHost, readHosts))
}

// Delete delete decision in cache.
func (c *Client) Delete(key string) {
	c.log.Debug(fmt.Sprintf("cache:Delete key:%v", key))
	c.cache.delete(key)
}

// Get check in the cache if the IP has the banned / not banned value.
// Otherwise return with an error to add the IP in cache if we are on.
func (c *Client) Get(key string) (string, error) {
	c.log.Debug(fmt.Sprintf("cache:Get key:%v", key))
	return c.cache.get(key)
}

// Set update the cache with the IP as key and the value banned / not banned.
func (c *Client) Set(key string, value string, duration int64) {
	c.log.Debug(fmt.Sprintf("cache:Set key:%v value:%v duration:%vs", key, value, duration))
	c.cache.set(key, value, duration)
}
