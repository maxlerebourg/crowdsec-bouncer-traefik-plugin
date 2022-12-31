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
	"strings"
	"text/template"
	"time"

	simpleredis "github.com/maxlerebourg/simpleredis"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	ip "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/ip"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

const (
	crowdsecLapiHeader      = "X-Api-Key"
	crowdsecLapiRoute       = "v1/decisions"
	crowdsecLapiStreamRoute = "v1/decisions/stream"
	cacheTimeoutKey         = "updated"
)

//nolint:gochecknoglobals
var (
	isCrowdsecStreamHealthy = false
	ticker                  chan bool
)

// CreateConfig creates the default plugin configuration.
func CreateConfig() *configuration.Config {
	return configuration.New()
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
func New(ctx context.Context, next http.Handler, config *configuration.Config, name string) (http.Handler, error) {
	logger.Init(config.LogLevel)
	err := configuration.ValidateParams(config)
	if err != nil {
		logger.Info(fmt.Sprintf("New:validateParams %s", err.Error()))
		return nil, err
	}

	serverChecker, _ := ip.NewChecker(config.ForwardedHeadersTrustedIPs)
	clientChecker, _ := ip.NewChecker(config.ClientTrustedIPs)

	tlsConfig, err := configuration.GetTLSConfigCrowdsec(config)
	if err != nil {
		logger.Error(fmt.Sprintf("New:getTLSConfigCrowdsec fail to get tlsConfig %s", err.Error()))
		return nil, err
	}
	apiKey, err := configuration.GetVariable(config, "CrowdsecLapiKey")
	if err != nil && len(tlsConfig.Certificates) == 0 {
		logger.Error(fmt.Sprintf("New:crowdsecLapiKey fail to get CrowdsecLapiKey and no client certificate setup %s", err.Error()))
		return nil, err
	}
	apiKey = strings.TrimSuffix(apiKey, "\n")

	bouncer := &Bouncer{
		next:     next,
		name:     name,
		template: template.New("CrowdsecBouncer").Delims("[[", "]]"),

		enabled:                config.Enabled,
		crowdsecMode:           config.CrowdsecMode,
		crowdsecScheme:         config.CrowdsecLapiScheme,
		crowdsecHost:           config.CrowdsecLapiHost,
		crowdsecKey:            apiKey,
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
				TLSClientConfig: tlsConfig,
			},
			Timeout: 10 * time.Second,
		},
	}
	if config.RedisCacheEnabled {
		cache.InitRedisClient(config.RedisCacheHost)
	}
	if config.CrowdsecMode == configuration.StreamMode && ticker == nil {
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
		logger.Error(fmt.Sprintf("ServeHTTP:getRemoteIp ip:%s %s", remoteIP, err.Error()))
		rw.WriteHeader(http.StatusForbidden)
		return
	}
	isTrusted, err := bouncer.clientPoolStrategy.Checker.Contains(remoteIP)
	if err != nil {
		logger.Error(fmt.Sprintf("ServeHTTP:checkerContains ip:%s %s", remoteIP, err.Error()))
		rw.WriteHeader(http.StatusForbidden)
		return
	}
	// if our IP is in the trusted list we bypass the next checks
	logger.Debug(fmt.Sprintf("ServeHTTP ip:%s isTrusted:%v", remoteIP, isTrusted))
	if isTrusted {
		bouncer.next.ServeHTTP(rw, req)
		return
	}

	// TODO This should be simplified
	if bouncer.crowdsecMode != configuration.NoneMode {
		isBanned, erro := cache.GetDecision(remoteIP)
		if erro != nil {
			logger.Debug(fmt.Sprintf("ServeHTTP:getDecision ip:%s %s", remoteIP, erro.Error()))
			if erro.Error() == simpleredis.RedisUnreachable {
				rw.WriteHeader(http.StatusForbidden)
				return
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
	if bouncer.crowdsecMode == configuration.StreamMode {
		if isCrowdsecStreamHealthy {
			bouncer.next.ServeHTTP(rw, req)
		} else {
			logger.Error(fmt.Sprintf("ServeHTTP:isCrowdsecStreamHealthy ip:%s", remoteIP))
			rw.WriteHeader(http.StatusForbidden)
		}
	} else {
		err = handleNoStreamCache(bouncer, remoteIP)
		if err != nil {
			logger.Debug(fmt.Sprintf("ServeHTTP:handleNoStreamCache ip:%s %s", remoteIP, err.Error()))
			rw.WriteHeader(http.StatusForbidden)
		} else {
			bouncer.next.ServeHTTP(rw, req)
		}
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

func startTicker(config *configuration.Config, work func()) chan bool {
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
func handleNoStreamCache(bouncer *Bouncer, remoteIP string) error {
	isLiveMode := bouncer.crowdsecMode == configuration.LiveMode
	routeURL := url.URL{
		Scheme:   bouncer.crowdsecScheme,
		Host:     bouncer.crowdsecHost,
		Path:     crowdsecLapiRoute,
		RawQuery: fmt.Sprintf("ip=%v&banned=true", remoteIP),
	}
	body, err := crowdsecQuery(bouncer, routeURL.String())
	if err != nil {
		return err
	}

	if bytes.Equal(body, []byte("null")) {
		if isLiveMode {
			cache.SetDecision(remoteIP, false, bouncer.defaultDecisionTimeout)
		}
		return nil
	}

	var decisions []Decision
	err = json.Unmarshal(body, &decisions)
	if err != nil {
		return fmt.Errorf("handleNoStreamCache:parseBody %w", err)
	}
	if len(decisions) == 0 {
		if isLiveMode {
			cache.SetDecision(remoteIP, false, bouncer.defaultDecisionTimeout)
		}
		return nil
	}
	duration, err := time.ParseDuration(decisions[0].Duration)
	if err != nil {
		return fmt.Errorf("handleNoStreamCache:parseDuration %w", err)
	}
	if isLiveMode {
		cache.SetDecision(remoteIP, true, int64(duration.Seconds()))
	}
	return fmt.Errorf("handleNoStreamCache:banned")
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
		RawQuery: fmt.Sprintf("startup=%t", !isCrowdsecStreamHealthy),
	}
	body, err := crowdsecQuery(bouncer, streamRouteURL.String())
	if err != nil {
		logger.Error(err.Error())
		isCrowdsecStreamHealthy = false
		return
	}
	var stream Stream
	err = json.Unmarshal(body, &stream)
	if err != nil {
		logger.Error(fmt.Sprintf("handleStreamCache:parsingBody %s", err.Error()))
		isCrowdsecStreamHealthy = false
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
	isCrowdsecStreamHealthy = true
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
			logger.Error(fmt.Sprintf("crowdsecQuery:closeBody %s", err.Error()))
		}
	}()
	body, err := io.ReadAll(res.Body)

	if err != nil {
		return nil, fmt.Errorf("crowdsecQuery:readBody %w", err)
	}
	return body, nil
}
