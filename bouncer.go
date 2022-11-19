// Package crowdsec_bouncer_traefik_plugin implements a middleware that communicates with crowdsec.
// It can cache results to filesystem or redis, or even ask crowdsec for every requests.
package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"text/template"
	"time"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	ip "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/ip"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
	simpleredis "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/simpleredis"
)

const (
	streamMode              = "stream"
	liveMode                = "live"
	noneMode                = "none"
	crowdsecLapiHeader      = "X-Api-Key"
	crowdsecLapiRoute       = "v1/decisions"
	crowdsecLapiStreamRoute = "v1/decisions/stream"
	cacheTimeoutKey         = "updated"
)

//nolint:gochecknoglobals
var (
	crowdsecStreamHealthy = false
	ticker                chan bool
)

// Config the plugin configuration.
type Config struct {
	Enabled                    bool     `json:"enabled,omitempty"`
	LogLevel                   string   `json:"logLevel,omitempty"`
	CrowdsecMode               string   `json:"crowdsecMode,omitempty"`
	CrowdsecLapiScheme         string   `json:"crowdsecLapiScheme,omitempty"`
	CrowdsecLapiHost           string   `json:"crowdsecLapiHost,omitempty"`
	CrowdsecLapiKey            string   `json:"crowdsecLapiKey,omitempty"`
	UpdateIntervalSeconds      int64    `json:"updateIntervalSeconds,omitempty"`
	DefaultDecisionSeconds     int64    `json:"defaultDecisionSeconds,omitempty"`
	ForwardedHeadersCustomName string   `json:"forwardedheaderscustomheader,omitempty"`
	ForwardedHeadersTrustedIPs []string `json:"forwardedHeadersTrustedIps,omitempty"`
	ClientTrustedIPs           []string `json:"clientTrustedIps,omitempty"`
	RedisCacheEnabled          bool     `json:"redisCacheEnabled,omitempty"`
	RedisCacheHost             string   `json:"redisCacheHost,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Enabled:                    false,
		LogLevel:                   "INFO",
		CrowdsecMode:               liveMode,
		CrowdsecLapiScheme:         "http",
		CrowdsecLapiHost:           "crowdsec:8080",
		CrowdsecLapiKey:            "",
		UpdateIntervalSeconds:      60,
		DefaultDecisionSeconds:     60,
		ClientTrustedIPs:           []string{},
		ForwardedHeadersTrustedIPs: []string{},
		ForwardedHeadersCustomName: "X-Forwarded-For",
		RedisCacheEnabled:          false,
		RedisCacheHost:             "redis:6379",
	}
}

// Bouncer a Bouncer struct.
type Bouncer struct {
	next     http.Handler
	name     string
	template *template.Template

	enabled                bool
	crowdsecScheme         string
	crowdsecHost           string
	crowdsecKey            string
	crowdsecMode           string
	updateInterval         int64
	defaultDecisionTimeout int64
	customHeader           string
	clientPoolStrategy     *ip.PoolStrategy
	serverPoolStrategy     *ip.PoolStrategy
	client                 *http.Client
}

// New creates the crowdsec bouncer plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	logger.Init(config.LogLevel)
	err := validateParams(config)
	if err != nil {
		logger.Info(err.Error())
		return nil, err
	}

	serverChecker, _ := ip.NewChecker(config.ForwardedHeadersTrustedIPs)
	clientChecker, _ := ip.NewChecker(config.ClientTrustedIPs)

	bouncer := &Bouncer{
		next:     next,
		name:     name,
		template: template.New("CrowdsecBouncer").Delims("[[", "]]"),

		enabled:                config.Enabled,
		crowdsecMode:           config.CrowdsecMode,
		crowdsecScheme:         config.CrowdsecLapiScheme,
		crowdsecHost:           config.CrowdsecLapiHost,
		crowdsecKey:            config.CrowdsecLapiKey,
		updateInterval:         config.UpdateIntervalSeconds,
		customHeader:           config.ForwardedHeadersCustomName,
		defaultDecisionTimeout: config.DefaultDecisionSeconds,
		serverPoolStrategy: &ip.PoolStrategy{
			Checker: serverChecker,
		},
		clientPoolStrategy: &ip.PoolStrategy{
			Checker: clientChecker,
		},
		client: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:    10,
				IdleConnTimeout: 30 * time.Second,
			},
			Timeout: 5 * time.Second,
		},
	}
	if config.RedisCacheEnabled {
		cache.InitRedisClient(config.RedisCacheHost)
	}
	if config.CrowdsecMode == streamMode && ticker == nil {
		ticker = startTicker(config, func() {
			handleStreamCache(bouncer)
		})
		go handleStreamCache(bouncer)
	}

	return bouncer, nil
}

// ServeHTTP principal function of plugin.
//
//nolint:nestif
func (bouncer *Bouncer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if !bouncer.enabled {
		bouncer.next.ServeHTTP(rw, req)
		return
	}

	// Here we check for the trusted IPs in the customHeader
	remoteIP, err := ip.GetRemoteIP(req, bouncer.serverPoolStrategy, bouncer.customHeader)
	if err != nil {
		logger.Error(fmt.Sprintf("ServeHTTP ip:%s %w", remoteIP, err))
		rw.WriteHeader(http.StatusForbidden)
		return
	}
	trusted, err := bouncer.clientPoolStrategy.Checker.Contains(remoteIP)
	if err != nil {
		logger.Info(err.Error())
		return
	}
	// if our IP is in the trusted list we bypass the next checks
	logger.Debug(fmt.Sprintf("ServeHTTP ip:%s isTrusted:%v", remoteIP, trusted))
	if trusted {
		bouncer.next.ServeHTTP(rw, req)
		return
	}

	// TODO This should be simplified
	healthy := crowdsecStreamHealthy
	if bouncer.crowdsecMode != noneMode {
		isBanned, err := cache.GetDecision(remoteIP)
		if err != nil {
			logger.Debug(err.Error())
			if err.Error() == simpleredis.RedisUnreachable {
				healthy = false
			}
		} else {
			logger.Debug(fmt.Sprintf("ServeHTTP ip:%s cache:hit isBanned:%v", remoteIP, isBanned))
			if isBanned {
				rw.WriteHeader(http.StatusForbidden)
			} else {
				bouncer.next.ServeHTTP(rw, req)
			}
			return
		}
	}

	// Right here if we cannot join the stream we forbid the request to go on.
	if bouncer.crowdsecMode == streamMode {
		if healthy {
			bouncer.next.ServeHTTP(rw, req)
		} else {
			rw.WriteHeader(http.StatusForbidden)
		}
	} else {
		handleNoStreamCache(bouncer, rw, req, remoteIP)
	}
}

// CUSTOM CODE.
// TODO place in another file.

// Decision Body returned from Crowdsec LAPI.
type Decision struct {
	ID        int    `json:"id"`
	Origin    string `json:"origin"`
	Type      string `json:"type"`
	Scope     string `json:"scope"`
	Value     string `json:"value"`
	Duration  string `json:"duration"`
	Scenario  string `json:"scenario"`
	Simulated bool   `json:"simulated"`
}

// Stream Body returned from Crowdsec Stream LAPI.
type Stream struct {
	Deleted []Decision `json:"deleted"`
	New     []Decision `json:"new"`
}

func contains(source []string, target string) bool {
	for _, item := range source {
		if item == target {
			return true
		}
	}
	return false
}

func startTicker(config *Config, work func()) chan bool {
	ticker := time.NewTicker(time.Duration(config.UpdateIntervalSeconds) * time.Second)
	stop := make(chan bool, 1)
	go func() {
		defer logger.Debug("ticker:stopped")
		for {
			select {
			case <-ticker.C:
				go work()
			case <-stop:
				return
			}
		}
	}()
	return stop
}

// We are now in none or live mode.
func handleNoStreamCache(bouncer *Bouncer, rw http.ResponseWriter, req *http.Request, remoteIP string) {
	routeURL := url.URL{
		Scheme:   bouncer.crowdsecScheme,
		Host:     bouncer.crowdsecHost,
		Path:     crowdsecLapiRoute,
		RawQuery: fmt.Sprintf("ip=%v&banned=true", remoteIP),
	}
	body, err := crowdsecQuery(bouncer, routeURL.String())
	if err != nil {
		logger.Error(err.Error())
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	if bytes.Equal(body, []byte("null")) {
		if bouncer.crowdsecMode == liveMode {
			cache.SetDecision(remoteIP, false, bouncer.defaultDecisionTimeout)
		}
		bouncer.next.ServeHTTP(rw, req)
		return
	}

	var decisions []Decision
	err = json.Unmarshal(body, &decisions)
	if err != nil {
		logger.Error(fmt.Sprintf("handleNoStreamCache:parseBody: %w", err))
		rw.WriteHeader(http.StatusForbidden)
		return
	}
	if len(decisions) == 0 {
		if bouncer.crowdsecMode == liveMode {
			cache.SetDecision(remoteIP, false, bouncer.defaultDecisionTimeout)
		}
		bouncer.next.ServeHTTP(rw, req)
		return
	}
	rw.WriteHeader(http.StatusForbidden)
	duration, err := time.ParseDuration(decisions[0].Duration)
	if err != nil {
		logger.Error(fmt.Sprintf("handleNoStreamCache:parseDuration %w", err))
		return
	}
	if bouncer.crowdsecMode == liveMode {
		cache.SetDecision(remoteIP, true, int64(duration.Seconds()))
	}
}

func handleStreamCache(bouncer *Bouncer) {
	// TODO clean properly on exit.
	// Instead of blocking the goroutine interval for all the secondary node,
	// if the master service is shut down, other goroutine can take the lead
	// because updated routine information is in the cache
	_, err := cache.GetDecision(cacheTimeoutKey)
	if err == nil {
		logger.Debug("handleStreamCache:alreadyUpdated")
		return
	}
	cache.SetDecision(cacheTimeoutKey, false, bouncer.updateInterval-1)
	streamRouteURL := url.URL{
		Scheme:   bouncer.crowdsecScheme,
		Host:     bouncer.crowdsecHost,
		Path:     crowdsecLapiStreamRoute,
		RawQuery: fmt.Sprintf("startup=%t", !crowdsecStreamHealthy),
	}
	body, err := crowdsecQuery(bouncer, streamRouteURL.String())
	if err != nil {
		logger.Error(err.Error())
		crowdsecStreamHealthy = false
		return
	}
	var stream Stream
	err = json.Unmarshal(body, &stream)
	if err != nil {
		logger.Error(fmt.Sprintf("handleStreamCache:parsingBody %w", err))
		crowdsecStreamHealthy = false
		return
	}
	for _, decision := range stream.New {
		duration, err := time.ParseDuration(decision.Duration)
		if err == nil {
			cache.SetDecision(decision.Value, true, int64(duration.Seconds()))
		}
	}
	for _, decision := range stream.Deleted {
		cache.DeleteDecision(decision.Value)
	}
	crowdsecStreamHealthy = true
}

func crowdsecQuery(bouncer *Bouncer, stringURL string) ([]byte, error) {
	var req *http.Request
	req, _ = http.NewRequest(http.MethodGet, stringURL, nil)
	req.Header.Add(crowdsecLapiHeader, bouncer.crowdsecKey)
	res, err := bouncer.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crowdsecQuery url:%s %w", stringURL, err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crowdsecQuery url:%s, statusCode:%d", stringURL, res.StatusCode)
	}
	defer func() {
		if err = res.Body.Close(); err != nil {
			logger.Error(fmt.Sprintf("crowdsecQuery:closeBody %w", err))
		}
	}()
	body, err := io.ReadAll(res.Body)

	if err != nil {
		return nil, fmt.Errorf("crowdsecQuery:readBody %w", err)
	}
	return body, nil
}

func validateParams(config *Config) error {
	requiredStrings := map[string]string{
		"CrowdsecLapiScheme": config.CrowdsecLapiScheme,
		"CrowdsecLapiHost":   config.CrowdsecLapiHost,
		"CrowdsecLapiKey":    config.CrowdsecLapiKey,
		"CrowdsecMode":       config.CrowdsecMode,
	}
	requiredInt := map[string]int64{
		"UpdateIntervalSeconds":  config.UpdateIntervalSeconds,
		"DefaultDecisionSeconds": config.DefaultDecisionSeconds,
	}
	for key, val := range requiredInt {
		if val < 1 {
			return fmt.Errorf("%v: cannot be less than 1", key)
		}
	}
	for key, val := range requiredStrings {
		if len(val) == 0 {
			return fmt.Errorf("%v: cannot be empty", key)
		}
	}
	if !contains([]string{noneMode, liveMode, streamMode}, config.CrowdsecMode) {
		return fmt.Errorf("CrowdsecMode: must be one of 'none', 'live' or 'stream'")
	}
	if !contains([]string{"http", "https"}, config.CrowdsecLapiScheme) {
		return fmt.Errorf("CrowdsecLapiScheme: must be one of 'http' or 'https'")
	}
	testURL := url.URL{
		Scheme: config.CrowdsecLapiScheme,
		Host:   config.CrowdsecLapiHost,
	}
	_, err := http.NewRequest(http.MethodGet, testURL.String(), nil)
	if err != nil {
		return fmt.Errorf("CrowdsecLapiScheme://CrowdsecLapiHost: '%v://%v' must be an URL", config.CrowdsecLapiScheme, config.CrowdsecLapiHost)
	}
	if len(config.ForwardedHeadersTrustedIPs) > 0 {
		_, err = ip.NewChecker(config.ForwardedHeadersTrustedIPs)
		if err != nil {
			return fmt.Errorf("ForwardedHeadersTrustedIPs must be a list of IP/CIDR :%w", err)
		}
	} else {
		logger.Debug("No IP provided for ForwardedHeadersTrustedIPs")
	}
	if len(config.ClientTrustedIPs) > 0 {
		_, err = ip.NewChecker(config.ClientTrustedIPs)
		if err != nil {
			return fmt.Errorf("TrustedIPs must be a list of IP/CIDR :%w", err)
		}
	} else {
		logger.Debug("No IP provided for TrustedIPs")
	}

	return nil
}
