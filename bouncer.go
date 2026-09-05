// Package crowdsec_bouncer_traefik_plugin implements a middleware that communicates with crowdsec.
// It can cache results in memory or using redis, or even ask crowdsec for every requests.
package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"text/template"
	"time"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	captcha "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	ip "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/ip"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

const (
	crowdsecAppsecIPHeader   = "X-Crowdsec-Appsec-Ip"
	crowdsecAppsecURIHeader  = "X-Crowdsec-Appsec-Uri"
	crowdsecAppsecHostHeader = "X-Crowdsec-Appsec-Host"
	crowdsecAppsecVerbHeader = "X-Crowdsec-Appsec-Verb"
	crowdsecAppsecHeader     = "X-Crowdsec-Appsec-Api-Key"
	crowdsecAppsecUserAgent  = "X-Crowdsec-Appsec-User-Agent"
	crowdsecLapiHeader       = "X-Api-Key"
	crowdsecLapiRoute        = "v1/decisions"
	crowdsecLapiStreamRoute  = "v1/decisions/stream"
	crowdsecLapiMetricsRoute = "v1/usage-metrics"
	crowdsecCapiHost         = "api.crowdsec.net"
	crowdsecCapiHeader       = "Authorization"
	crowdsecCapiLoginRoute   = "v2/watchers/login"
	crowdsecCapiStreamRoute  = "v2/decisions/stream"
	cacheTimeoutKey          = "updated"
)

// ##############################################################
// Important: traefik creates an instance of the bouncer per route.
// We rely on globals (both here and in the memory cache) to share info between
// routes. This means that some of the plugins parameters will only work "once"
// and will take the values of the first middleware that was instantiated even
// if you have different middlewares with different parameters. This design
// makes it impossible to have multiple crowdsec implementations per cluster (unless you have multiple traefik deployments in it)
// - updateInterval
// - updateMaxFailure
// - defaultDecisionTimeout
// - redisUnreachableBlock
// - appsecEnabled
// - appsecHost
// - metricsUpdateIntervalSeconds
// - others...
// ###################################

//nolint:gochecknoglobals
var (
	isCrowdsecStreamStartup = true
	isCrowdsecStreamHealthy = true
	updateFailure           int64
	streamTicker            chan bool
	metricsTicker           chan bool
	lastMetricsPush         time.Time
	blockedRequests         int64
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

	enabled                   bool
	appsecEnabled             bool
	appsecScheme              string
	appsecHost                string
	appsecPath                string
	appsecKey                 string
	appsecFailureBlock        bool
	appsecUnreachableBlock    bool
	appsecUnreadableBodyBlock bool
	appsecBodyLimit           int64
	crowdsecScheme            string
	crowdsecHost              string
	crowdsecPath              string
	crowdsecKey               string
	crowdsecMode              string
	crowdsecMachineID         string
	crowdsecPassword          string
	crowdsecScenarios         []string
	updateInterval            int64
	updateMaxFailure          int64
	defaultDecisionTimeout    int64
	remediationStatusCode     int
	remediationCustomHeader   string
	forwardedCustomHeader     string
	decisionScopeHeaders      map[string]string
	crowdsecStreamRoute       string
	crowdsecHeader            string
	redisUnreachableBlock     bool
	banTemplate               *template.Template
	banTemplateContentType    string
	traceCustomHeader         string
	clientPoolStrategy        *ip.PoolStrategy
	serverPoolStrategy        *ip.PoolStrategy
	httpClient                *http.Client
	httpAppsecClient          *http.Client
	cacheClient               *cache.Client
	captchaClient             *captcha.Client
	log                       *slog.Logger
}

// New creates the crowdsec bouncer plugin.
//
//nolint:nestif,gocyclo,gocognit,funlen,maintidx
func New(_ context.Context, next http.Handler, config *configuration.Config, name string) (http.Handler, error) {
	config.LogLevel = strings.ToUpper(config.LogLevel)
	log := logger.NewWithFormat(config.LogLevel, config.LogFilePath, config.LogFormat)

	if config.BanFilePath == "" && config.BanHTMLFilePath != "" {
		config.BanFilePath = config.BanHTMLFilePath
	}
	if config.CaptchaHTMLFilePath != "" {
		config.CaptchaFilePath = config.CaptchaHTMLFilePath
	}

	err := configuration.ValidateParams(config, log)
	if err != nil {
		log.Error("New:validateParams " + err.Error())
		return nil, err
	}

	serverChecker, _ := ip.NewChecker(log, config.ForwardedHeadersTrustedIPs)
	clientChecker, _ := ip.NewChecker(log, config.ClientTrustedIPs)

	var tlsAppsecConfig *tls.Config
	if config.CrowdsecAppsecEnabled {
		tlsAppsecConfig, err = configuration.GetTLSConfigCrowdsec(config, log, true)
		if config.CrowdsecAppsecScheme == "" {
			config.CrowdsecAppsecScheme = config.CrowdsecLapiScheme
		}
		if err != nil {
			log.Error("New:getTLSConfigCrowdsec fail to get tlsAppsecConfig " + err.Error())
			return nil, err
		}
		apiAppsecKey, errAppsecKey := configuration.GetVariable(config, "CrowdsecAppsecKey")
		if errAppsecKey != nil && len(tlsAppsecConfig.Certificates) == 0 {
			log.Info("New:crowdsecLapiKey fail to get CrowdsecAppsecKey and no client certificate setup " + errAppsecKey.Error())
		}
		config.CrowdsecAppsecKey = apiAppsecKey
	}

	var tlsConfig *tls.Config
	crowdsecStreamRoute := ""
	crowdsecHeader := ""
	if config.CrowdsecMode == configuration.AloneMode {
		config.CrowdsecCapiMachineID, _ = configuration.GetVariable(config, "CrowdsecCapiMachineID")
		config.CrowdsecCapiPassword, _ = configuration.GetVariable(config, "CrowdsecCapiPassword")
		config.CrowdsecLapiScheme = configuration.HTTPS
		config.CrowdsecLapiHost = crowdsecCapiHost
		config.CrowdsecLapiPath = "/"
		config.UpdateIntervalSeconds = 7200 // 2 hours
		crowdsecStreamRoute = crowdsecCapiStreamRoute
		crowdsecHeader = crowdsecCapiHeader
	} else {
		crowdsecStreamRoute = crowdsecLapiStreamRoute
		crowdsecHeader = crowdsecLapiHeader
		tlsConfig, err = configuration.GetTLSConfigCrowdsec(config, log, false)
		if err != nil {
			log.Error("New:getTLSConfigCrowdsec fail to get tlsConfig " + err.Error())
			return nil, err
		}
		apiKey, errKey := configuration.GetVariable(config, "CrowdsecLapiKey")
		if errKey != nil && len(tlsConfig.Certificates) == 0 {
			log.Error("New:crowdsecLapiKey fail to get CrowdsecLapiKey and no client certificate setup " + errKey.Error())
			return nil, errKey
		}
		config.CrowdsecLapiKey = apiKey
		if config.CrowdsecAppsecKey == "" {
			config.CrowdsecAppsecKey = apiKey
		}
	}

	var banTemplate *template.Template
	var banTemplateContentType string
	if config.BanFilePath != "" {
		banTemplate, banTemplateContentType, _ = configuration.GetTemplate(config.BanFilePath)
	}

	bouncer := &Bouncer{
		next:     next,
		name:     name,
		template: template.New("CrowdsecBouncer").Delims("[[", "]]"),

		enabled:                   config.Enabled,
		crowdsecMode:              config.CrowdsecMode,
		appsecEnabled:             config.CrowdsecAppsecEnabled,
		appsecScheme:              config.CrowdsecAppsecScheme,
		appsecHost:                config.CrowdsecAppsecHost,
		appsecPath:                config.CrowdsecAppsecPath,
		appsecKey:                 config.CrowdsecAppsecKey,
		appsecFailureBlock:        config.CrowdsecAppsecFailureBlock,
		appsecUnreachableBlock:    config.CrowdsecAppsecUnreachableBlock,
		appsecUnreadableBodyBlock: config.CrowdsecAppsecUnreadableBodyBlock,
		appsecBodyLimit:           config.CrowdsecAppsecBodyLimit,
		crowdsecScheme:            config.CrowdsecLapiScheme,
		crowdsecHost:              config.CrowdsecLapiHost,
		crowdsecPath:              config.CrowdsecLapiPath,
		crowdsecKey:               config.CrowdsecLapiKey,
		crowdsecMachineID:         config.CrowdsecCapiMachineID,
		crowdsecPassword:          config.CrowdsecCapiPassword,
		crowdsecScenarios:         config.CrowdsecCapiScenarios,
		updateInterval:            config.UpdateIntervalSeconds,
		updateMaxFailure:          config.UpdateMaxFailure,
		remediationCustomHeader:   config.RemediationHeadersCustomName,
		forwardedCustomHeader:     config.ForwardedHeadersCustomName,
		decisionScopeHeaders:      normalizeDecisionScopeHeaders(config.DecisionScopeHeaders),
		defaultDecisionTimeout:    config.DefaultDecisionSeconds,
		remediationStatusCode:     config.RemediationStatusCode,
		redisUnreachableBlock:     config.RedisCacheUnreachableBlock,
		banTemplate:               banTemplate,
		banTemplateContentType:    banTemplateContentType,
		traceCustomHeader:         config.TraceHeadersCustomName,
		crowdsecStreamRoute:       crowdsecStreamRoute,
		crowdsecHeader:            crowdsecHeader,
		log:                       log,
		serverPoolStrategy: &ip.PoolStrategy{
			Checker: serverChecker,
		},
		clientPoolStrategy: &ip.PoolStrategy{
			Checker: clientChecker,
		},
		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     30 * time.Second,
				TLSClientConfig:     tlsConfig,
			},
			Timeout: time.Duration(config.HTTPTimeoutSeconds) * time.Second,
		},
		httpAppsecClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     30 * time.Second,
				TLSClientConfig:     tlsAppsecConfig,
			},
			Timeout: time.Duration(config.HTTPTimeoutSeconds) * time.Second,
		},
		cacheClient:   &cache.Client{},
		captchaClient: &captcha.Client{},
	}
	if config.CrowdsecMode == configuration.AppsecMode {
		return bouncer, nil
	}
	config.RedisCachePassword, _ = configuration.GetVariable(config, "RedisCachePassword")
	bouncer.cacheClient.New(
		log,
		config.RedisCacheEnabled,
		config.RedisCacheHost,
		config.RedisCacheReadHosts,
		config.RedisCachePassword,
		config.RedisCacheDatabase,
	)
	config.CaptchaSiteKey, _ = configuration.GetVariable(config, "CaptchaSiteKey")
	config.CaptchaSecretKey, _ = configuration.GetVariable(config, "CaptchaSecretKey")
	err = bouncer.captchaClient.New(
		log,
		bouncer.cacheClient,
		&http.Client{
			Transport: &http.Transport{MaxIdleConns: 10, MaxIdleConnsPerHost: 10, IdleConnTimeout: 30 * time.Second},
			Timeout:   time.Duration(config.HTTPTimeoutSeconds) * time.Second,
		},
		config.CaptchaProvider,
		config.CaptchaCustomJsURL,
		config.CaptchaCustomKey,
		config.CaptchaCustomResponse,
		config.CaptchaCustomValidateURL,
		config.CaptchaSiteKey,
		config.CaptchaSecretKey,
		config.RemediationHeadersCustomName,
		config.CaptchaFilePath,
		config.CaptchaGracePeriodSeconds,
	)
	if err != nil {
		log.Error("CaptchaClient not valid " + err.Error())
		return nil, err
	}

	if (config.CrowdsecMode == configuration.StreamMode || config.CrowdsecMode == configuration.AloneMode) && streamTicker == nil {
		if config.CrowdsecMode == configuration.AloneMode {
			if err := getToken(bouncer); err != nil {
				bouncer.log.Error("New:getToken " + err.Error())
				return nil, err
			}
		}
		if config.StreamStartupBlock {
			handleStreamTicker(bouncer)
		} else {
			go handleStreamTicker(bouncer)
		}
		streamTicker = startTicker("stream", config.UpdateIntervalSeconds, log, func() {
			handleStreamTicker(bouncer)
		})
	}

	// Start metrics ticker if not already running
	if metricsTicker == nil && config.MetricsUpdateIntervalSeconds > 0 {
		lastMetricsPush = time.Now() // Initialize lastMetricsPush when starting the metrics ticker
		go handleMetricsTicker(bouncer)
		metricsTicker = startTicker("metrics", config.MetricsUpdateIntervalSeconds, log, func() {
			handleMetricsTicker(bouncer)
		})
	}

	bouncer.log.Debug("New initialized mode:" + config.CrowdsecMode)

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

	// Here we check for the trusted IPs in the forwardedCustomHeader
	remoteIP, err := ip.GetRemoteIP(req, bouncer.serverPoolStrategy, bouncer.forwardedCustomHeader)
	if err != nil {
		bouncer.log.Error(fmt.Sprintf("ServeHTTP:getRemoteIp ip:%s %s", remoteIP, err.Error()))
		bouncer.handleBanServeHTTP(rw, req, remoteIP, configuration.ReasonTECH)
		return
	}
	isTrusted, err := bouncer.clientPoolStrategy.Checker.Contains(remoteIP)
	if err != nil {
		bouncer.log.Error(fmt.Sprintf("ServeHTTP:checkerContains ip:%s %s", remoteIP, err.Error()))
		bouncer.handleBanServeHTTP(rw, req, remoteIP, configuration.ReasonTECH)
		return
	}
	// if our IP is in the trusted list we bypass the next checks
	bouncer.log.Debug(fmt.Sprintf("ServeHTTP ip:%s isTrusted:%v", remoteIP, isTrusted))
	if isTrusted {
		bouncer.next.ServeHTTP(rw, req)
		return
	}

	if bouncer.crowdsecMode == configuration.AppsecMode {
		bouncer.handleNextServeHTTP(rw, req, remoteIP)
		return
	}

	// TODO This should be simplified
	scopes := requestScopeValues(bouncer, req)

	// Cache lookup: Ip, Range, then configured header scopes. Live still queries LAPI on miss.
	if bouncer.crowdsecMode != configuration.NoneMode {
		value, cacheErr := lookupCachedRemediation(bouncer, remoteIP, scopes)
		switch {
		case cacheErr != nil:
			cacheErrString := cacheErr.Error()
			bouncer.log.Debug(fmt.Sprintf("ServeHTTP:Get ip:%s isBanned:false %s", remoteIP, cacheErrString))
			if !bouncer.redisUnreachableBlock && cacheErrString == cache.CacheUnreachable {
				bouncer.log.Error(fmt.Sprintf("ServeHTTP:Get ip:%s redisUnreachable=true", remoteIP))
				bouncer.handleNextServeHTTP(rw, req, remoteIP)
				return
			}
			if cacheErrString != cache.CacheMiss {
				bouncer.log.Error(fmt.Sprintf("ServeHTTP:Get ip:%s %s", remoteIP, cacheErrString))
				bouncer.handleBanServeHTTP(rw, req, remoteIP, configuration.ReasonTECH)
				return
			}
		case isActiveRemediation(value):
			bouncer.log.Debug(fmt.Sprintf("ServeHTTP ip:%s cache:hit isBanned:%v", remoteIP, value))
			bouncer.handleRemediationServeHTTP(rw, req, remoteIP, value)
			return
		case value == cache.NoBannedValue:
			bouncer.handleNextServeHTTP(rw, req, remoteIP)
			return
		}
	}

	// Stream/alone: miss means not on the ban list. Live/none: ask LAPI.
	if bouncer.crowdsecMode == configuration.StreamMode || bouncer.crowdsecMode == configuration.AloneMode {
		if isCrowdsecStreamHealthy {
			bouncer.handleNextServeHTTP(rw, req, remoteIP)
		} else {
			bouncer.log.Debug(fmt.Sprintf("ServeHTTP isCrowdsecStreamHealthy:false ip:%s updateFailure:%d", remoteIP, updateFailure))
			bouncer.handleBanServeHTTP(rw, req, remoteIP, configuration.ReasonTECH)
		}
	} else {
		value, err := handleNoStreamCache(bouncer, remoteIP, scopes)
		if err != nil {
			bouncer.log.Debug("handleNoStreamCache:crowdsecQuery " + err.Error())
		}
		if value == cache.NoBannedValue {
			bouncer.handleNextServeHTTP(rw, req, remoteIP)
		} else {
			bouncer.log.Debug(fmt.Sprintf("ServeHTTP:handleNoStreamCache ip:%s isBanned:%v %s", remoteIP, value, err.Error()))
			bouncer.handleRemediationServeHTTP(rw, req, remoteIP, value)
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

// Login Body returned from Crowdsec Login CAPI.
type Login struct {
	Code   int    `json:"code"`
	Token  string `json:"token"`
	Expire string `json:"expire"`
}

// To append Headers we need to call rw.WriteHeader after set any header.
func (bouncer *Bouncer) handleBanServeHTTP(rw http.ResponseWriter, req *http.Request, remoteIP, reason string) {
	atomic.AddInt64(&blockedRequests, 1)

	if bouncer.remediationCustomHeader != "" {
		rw.Header().Set(bouncer.remediationCustomHeader, "ban")
	}
	rw.Header().Set("Content-Type", bouncer.banTemplateContentType)
	rw.WriteHeader(bouncer.remediationStatusCode)
	if bouncer.banTemplate == nil || req.Method == http.MethodHead {
		return
	}
	templateData := map[string]string{
		"RemediationReason": reason,
		"ClientIP":          remoteIP,
	}

	if bouncer.traceCustomHeader != "" {
		headerVal := req.Header.Get(bouncer.traceCustomHeader)

		if headerVal != "" {
			templateData["TraceID"] = headerVal
		}
	}

	err := bouncer.banTemplate.Execute(rw, templateData)

	if err != nil {
		bouncer.log.Warn("handleBanServeHTTP could not write template to ResponseWriter: " + err.Error())
	}
}

func (bouncer *Bouncer) handleRemediationServeHTTP(rw http.ResponseWriter, req *http.Request, remoteIP, remediation string) {
	bouncer.log.Debug(fmt.Sprintf("handleRemediationServeHTTP ip:%s remediation:%s", remoteIP, remediation))
	if bouncer.captchaClient.Valid && remediation == cache.CaptchaValue && req.Method != http.MethodHead {
		if bouncer.captchaClient.Check(remoteIP) {
			bouncer.handleNextServeHTTP(rw, req, remoteIP)
			return
		}
		atomic.AddInt64(&blockedRequests, 1) //  If we serve a captcha that should count as a dropped request.
		bouncer.captchaClient.ServeHTTP(rw, req, remoteIP)
		return
	}
	bouncer.handleBanServeHTTP(rw, req, remoteIP, configuration.ReasonLAPI)
}

func (bouncer *Bouncer) handleNextServeHTTP(rw http.ResponseWriter, req *http.Request, remoteIP string) {
	if bouncer.appsecEnabled {
		if err := appsecQuery(bouncer, remoteIP, req); err != nil {
			bouncer.log.Debug(fmt.Sprintf("handleNextServeHTTP ip:%s isWaf:true %s", remoteIP, err.Error()))
			bouncer.handleBanServeHTTP(rw, req, remoteIP, configuration.ReasonAPPSEC)
			return
		}
	}
	bouncer.next.ServeHTTP(rw, req)
}

func handleStreamTicker(bouncer *Bouncer) {
	if err := handleStreamCache(bouncer); err != nil {
		bouncer.log.Warn(fmt.Sprintf("handleStreamTicker updateFailure:%d isCrowdsecStreamHealthy:%t %s", updateFailure, isCrowdsecStreamHealthy, err.Error()))
		if bouncer.updateMaxFailure != -1 && updateFailure >= bouncer.updateMaxFailure && isCrowdsecStreamHealthy {
			isCrowdsecStreamHealthy = false
			bouncer.log.Error(fmt.Sprintf("handleStreamTicker:error updateFailure:%d %s", updateFailure, err.Error()))
		}
		updateFailure++
	} else {
		isCrowdsecStreamHealthy = true
		updateFailure = 0
	}
}

func handleMetricsTicker(bouncer *Bouncer) {
	if err := reportMetrics(bouncer); err != nil {
		bouncer.log.Error("handleMetricsTicker:reportMetrics " + err.Error())
	}
}

func startTicker(name string, updateInterval int64, log *slog.Logger, work func()) chan bool {
	ticker := time.NewTicker(time.Duration(updateInterval) * time.Second)
	stop := make(chan bool, 1)
	go func() {
		defer log.Debug(name + "_ticker:stopped")
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

// We are now in none or live mode. scopes holds normalized header values for configured scopes.
func handleNoStreamCache(bouncer *Bouncer, remoteIP string, scopes map[string]string) (string, error) {
	isLiveMode := bouncer.crowdsecMode == configuration.LiveMode
	chosen, parsedDuration, err := queryLiveDecisions(bouncer, fmt.Sprintf("ip=%v", remoteIP))
	if err != nil {
		return cache.BannedValue, err
	}
	for scope, identifier := range scopes {
		chosen, parsedDuration = mergeLiveScope(bouncer, chosen, parsedDuration, scope, identifier, isLiveMode)
	}
	if !isActiveRemediation(chosen) {
		if isLiveMode && bouncer.defaultDecisionTimeout > 0 {
			bouncer.cacheClient.Set(remoteIP, cache.NoBannedValue, bouncer.defaultDecisionTimeout)
		}
		return cache.NoBannedValue, nil
	}
	if isLiveMode && bouncer.defaultDecisionTimeout > 0 {
		bouncer.cacheClient.Set(remoteIP, chosen, liveCacheTTL(bouncer, parsedDuration))
	}
	return chosen, errors.New("handleNoStreamCache:banned")
}

func getToken(bouncer *Bouncer) error {
	loginURL := url.URL{
		Scheme: bouncer.crowdsecScheme,
		Host:   bouncer.crowdsecHost,
		Path:   crowdsecCapiLoginRoute,
	}

	// Move the login-specific payload here
	loginData := []byte(fmt.Sprintf(
		`{"machine_id": "%v","password": "%v","scenarios": ["%v"]}`,
		bouncer.crowdsecMachineID,
		bouncer.crowdsecPassword,
		strings.Join(bouncer.crowdsecScenarios, `","`),
	))

	body, err := crowdsecQuery(bouncer, loginURL.String(), loginData)
	if err != nil {
		return err
	}
	var login Login
	err = json.Unmarshal(body, &login)
	if err != nil {
		return fmt.Errorf("getToken:parsingBody %w", err)
	}
	if login.Code == http.StatusOK && len(login.Token) > 0 {
		bouncer.crowdsecKey = login.Token
		return nil
	}
	bouncer.log.Warn(fmt.Sprintf("getToken statusCode:%d", login.Code))
	return fmt.Errorf("getToken statusCode:%d", login.Code)
}

func handleStreamCache(bouncer *Bouncer) error {
	// TODO clean properly on exit.
	// Instead of blocking the goroutine interval for all the secondary node,
	// if the master service is shut down, other goroutine can take the lead
	// because updated routine information is in the cache
	_, err := bouncer.cacheClient.Get(cacheTimeoutKey)
	if err == nil {
		bouncer.log.Debug("handleStreamCache:alreadyUpdated")
		isCrowdsecStreamStartup = false
		return nil
	}
	if err.Error() != cache.CacheMiss {
		return err
	}
	// To avoid every instance trying to update the cache, set 1 second at least
	leaseDuration := bouncer.updateInterval - 1
	if leaseDuration < 1 {
		leaseDuration = 1
	}
	bouncer.cacheClient.Set(cacheTimeoutKey, cache.NoBannedValue, leaseDuration)
	streamRouteURL := url.URL{
		Scheme:   bouncer.crowdsecScheme,
		Host:     bouncer.crowdsecHost,
		Path:     bouncer.crowdsecPath + bouncer.crowdsecStreamRoute,
		RawQuery: streamQuery(bouncer),
	}
	body, err := crowdsecQuery(bouncer, streamRouteURL.String(), nil)
	if err != nil {
		return err
	}
	var stream Stream
	err = json.Unmarshal(body, &stream)
	if err != nil {
		return fmt.Errorf("handleStreamCache:parsingBody %w", err)
	}
	for _, item := range stream.New {
		parsedDuration, parseErr := time.ParseDuration(item.Duration)
		if parseErr != nil {
			continue
		}
		storeStreamDecision(bouncer, item, int64(parsedDuration.Seconds()))
	}
	for _, item := range stream.Deleted {
		deleteStreamDecision(bouncer, item)
	}
	bouncer.log.Debug("handleStreamCache:updated")
	isCrowdsecStreamStartup = false
	return nil
}

func isReverseProxyError(statusCode int) bool {
	return statusCode == http.StatusBadGateway ||
		statusCode == http.StatusServiceUnavailable ||
		statusCode == http.StatusGatewayTimeout
}

func crowdsecQuery(bouncer *Bouncer, stringURL string, data []byte) ([]byte, error) {
	var req *http.Request
	if len(data) > 0 {
		req, _ = http.NewRequest(http.MethodPost, stringURL, bytes.NewBuffer(data))
	} else {
		req, _ = http.NewRequest(http.MethodGet, stringURL, nil)
	}
	req.Header.Set(bouncer.crowdsecHeader, bouncer.crowdsecKey)
	req.Header.Set("User-Agent", "Crowdsec-Bouncer-Traefik-Plugin/"+pluginVersion)

	res, err := bouncer.httpClient.Do(req)
	if err != nil || isReverseProxyError(res.StatusCode) {
		return nil, fmt.Errorf("crowdsecQuery:unreachable url:%s %w", stringURL, err)
	}
	defer func() {
		if err = res.Body.Close(); err != nil {
			bouncer.log.Error("crowdsecQuery:closeBody " + err.Error())
		}
	}()
	if res.StatusCode == http.StatusUnauthorized && bouncer.crowdsecMode == configuration.AloneMode {
		if errToken := getToken(bouncer); errToken != nil {
			return nil, fmt.Errorf("crowdsecQuery:renewToken url:%s %w", stringURL, errToken)
		}
		return crowdsecQuery(bouncer, stringURL, nil)
	}

	// Check if the status code starts with 2
	statusStr := strconv.Itoa(res.StatusCode)
	if len(statusStr) < 1 || statusStr[0] != '2' {
		return nil, fmt.Errorf("crowdsecQuery method:%s url:%s, statusCode:%d (expected: 2xx)", req.Method, stringURL, res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("crowdsecQuery:readBody %w", err)
	}
	return body, nil
}

// isBodyUnreadable reports whether the request body cannot be buffered before
// forwarding it to the Appsec component. An HTTP/2 or HTTP/3 request without a
// Content-Length (typically a bidirectional gRPC stream) keeps its body open
// for the whole life of the stream and never reaches EOF, so reading it with
// io.ReadAll would block until the request times out and is wrongly turned into
// a 403. This mirrors the reference lua-cs-bouncer behavior, which refuses to
// read the body of an HTTP/2+ request that has no Content-Length.
func isBodyUnreadable(httpReq *http.Request) bool {
	return httpReq.Body != nil && httpReq.Body != http.NoBody && httpReq.ProtoMajor >= 2 && httpReq.ContentLength < 0
}

// isMethodWithBody used only when isBodyUnreadable returns true but the request method can't have body.
func isMethodWithBody(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	default:
		return false
	}
}

func appsecQuery(bouncer *Bouncer, ip string, httpReq *http.Request) error {
	routeURL := url.URL{
		Scheme: bouncer.appsecScheme,
		Host:   bouncer.appsecHost,
		Path:   bouncer.appsecPath,
	}
	var req *http.Request
	switch {
	case isBodyUnreadable(httpReq):
		if bouncer.appsecUnreadableBodyBlock && isMethodWithBody(httpReq.Method) {
			return errors.New("appsecQuery:unreadableBody dropped")
		}
		req, _ = http.NewRequest(http.MethodGet, routeURL.String(), nil)
	case bouncer.appsecBodyLimit > 0 && httpReq.Body != nil:
		var bodyBuffer bytes.Buffer
		limitedReader := io.LimitReader(httpReq.Body, bouncer.appsecBodyLimit)
		teeReader := io.TeeReader(limitedReader, &bodyBuffer)
		bodyBytes, err := io.ReadAll(teeReader)
		if err != nil {
			return fmt.Errorf("appsecQuery:GetBody %w", err)
		}
		// Conserve body intact after reading it for other middlewares and service
		httpReq.Body = io.NopCloser(io.MultiReader(&bodyBuffer, httpReq.Body))
		req, _ = http.NewRequest(http.MethodPost, routeURL.String(), bytes.NewBuffer(bodyBytes))
	default:
		req, _ = http.NewRequest(http.MethodGet, routeURL.String(), nil)
	}

	for key, headers := range httpReq.Header {
		for _, value := range headers {
			req.Header.Add(key, value)
		}
	}
	req.Header.Set(crowdsecAppsecHeader, bouncer.appsecKey)
	req.Header.Set(crowdsecAppsecIPHeader, ip)
	req.Header.Set(crowdsecAppsecVerbHeader, httpReq.Method)
	req.Header.Set(crowdsecAppsecHostHeader, httpReq.Host)
	req.Header.Set(crowdsecAppsecURIHeader, httpReq.URL.String())
	req.Header.Set(crowdsecAppsecUserAgent, httpReq.Header.Get("User-Agent"))
	req.Header.Set("User-Agent", "Crowdsec-Bouncer-Traefik-Plugin/"+pluginVersion)

	res, err := bouncer.httpAppsecClient.Do(req)
	if err != nil || isReverseProxyError(res.StatusCode) {
		bouncer.log.Error("appsecQuery:unreachable")
		if bouncer.appsecUnreachableBlock {
			return fmt.Errorf("appsecQuery:unreachable %w", err)
		}
		return nil
	}
	defer func() {
		// net/http returns a conn to the idle pool once its body has been read to EOF, closing early discards it.
		// Drain the body from the non-200 paths, which return earlier, keep their connections too.
		if _, errDrain := io.Copy(io.Discard, res.Body); errDrain != nil {
			bouncer.log.Debug("appsecQuery:drainBody " + errDrain.Error())
		}
		if err = res.Body.Close(); err != nil {
			bouncer.log.Error("appsecQuery:closeBody " + err.Error())
		}
	}()
	if res.StatusCode == http.StatusInternalServerError {
		bouncer.log.Info("appsecQuery:failure")
		if bouncer.appsecFailureBlock {
			return errors.New("appsecQuery statusCode:500")
		}
		return nil
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("appsecQuery statusCode:%d", res.StatusCode)
	}

	return nil
}

func reportMetrics(bouncer *Bouncer) error {
	now := time.Now()
	currentCount := atomic.LoadInt64(&blockedRequests)
	windowSizeSeconds := int(now.Sub(lastMetricsPush).Seconds())

	bouncer.log.Debug(fmt.Sprintf("reportMetrics: blocked_requests=%d window_size=%ds", currentCount, windowSizeSeconds))

	metrics := map[string]interface{}{
		"remediation_components": []map[string]interface{}{
			{
				"version": pluginVersion,
				"type":    "bouncer",
				"name":    "traefik_plugin",
				"metrics": []map[string]interface{}{
					{
						"items": []map[string]interface{}{
							{
								"name":  "dropped",
								"value": currentCount,
								"unit":  "request",
								"labels": map[string]string{
									"type": "traefik_plugin",
								},
							},
						},
						"meta": map[string]interface{}{
							"window_size_seconds": windowSizeSeconds,
							"utc_now_timestamp":   now.Unix(),
						},
					},
				},
				"utc_startup_timestamp": time.Now().Unix(),
				"feature_flags":         []string{},
				"os": map[string]string{
					"name":    "unknown",
					"version": "unknown",
				},
			},
		},
	}

	data, err := json.Marshal(metrics)
	if err != nil {
		return fmt.Errorf("reportMetrics:marshal %w", err)
	}

	metricsURL := url.URL{
		Scheme: bouncer.crowdsecScheme,
		Host:   bouncer.crowdsecHost,
		Path:   bouncer.crowdsecPath + crowdsecLapiMetricsRoute,
	}

	_, err = crowdsecQuery(bouncer, metricsURL.String(), data)
	if err != nil {
		return fmt.Errorf("reportMetrics:query %w", err)
	}

	atomic.StoreInt64(&blockedRequests, 0)
	lastMetricsPush = now
	return nil
}
