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
	isStartup               = true
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

	enabled                 bool
	appsecEnabled           bool
	appsecHost              string
	appsecPath              string
	appsecFailureBlock      bool
	appsecUnreachableBlock  bool
	appsecBodyLimit         int64
	crowdsecScheme          string
	crowdsecHost            string
	crowdsecPath            string
	crowdsecKey             string
	crowdsecMode            string
	crowdsecMachineID       string
	crowdsecPassword        string
	crowdsecScenarios       []string
	updateInterval          int64
	updateMaxFailure        int64
	defaultDecisionTimeout  int64
	remediationStatusCode   int
	remediationCustomHeader string
	forwardedCustomHeader   string
	crowdsecStreamRoute     string
	crowdsecHeader          string
	redisUnreachableBlock   bool
	banTemplateString       string
	clientPoolStrategy      *ip.PoolStrategy
	serverPoolStrategy      *ip.PoolStrategy
	httpClient              *http.Client
	cacheClient             *cache.Client
	captchaClient           *captcha.Client
	log                     *logger.Log
}

// New creates the crowdsec bouncer plugin.
//
//nolint:gocyclo
func New(_ context.Context, next http.Handler, config *configuration.Config, name string) (http.Handler, error) {
	config.LogLevel = strings.ToUpper(config.LogLevel)
	log := logger.New(config.LogLevel, config.LogFilePath)
	err := configuration.ValidateParams(config)
	if err != nil {
		log.Error("New:validateParams " + err.Error())
		return nil, err
	}

	serverChecker, _ := ip.NewChecker(log, config.ForwardedHeadersTrustedIPs)
	clientChecker, _ := ip.NewChecker(log, config.ClientTrustedIPs)

	var tlsConfig *tls.Config
	crowdsecStreamRoute := ""
	crowdsecHeader := ""
	if config.CrowdsecMode == configuration.AloneMode {
		config.CrowdsecCapiMachineID, _ = configuration.GetVariable(config, "CrowdsecCapiMachineID")
		config.CrowdsecCapiPassword, _ = configuration.GetVariable(config, "CrowdsecCapiPassword")
		config.CrowdsecLapiScheme = configuration.HTTPS
		config.CrowdsecLapiHost = crowdsecCapiHost
		config.CrowdsecLapiPath = "/"
		config.CrowdsecAppsecEnabled = false
		config.UpdateIntervalSeconds = 7200 // 2 hours
		crowdsecStreamRoute = crowdsecCapiStreamRoute
		crowdsecHeader = crowdsecCapiHeader
	} else {
		crowdsecStreamRoute = crowdsecLapiStreamRoute
		crowdsecHeader = crowdsecLapiHeader
		tlsConfig, err = configuration.GetTLSConfigCrowdsec(config, log)
		if err != nil {
			log.Error("New:getTLSConfigCrowdsec fail to get tlsConfig " + err.Error())
			return nil, err
		}
		apiKey, errAPIKey := configuration.GetVariable(config, "CrowdsecLapiKey")
		if errAPIKey != nil && len(tlsConfig.Certificates) == 0 {
			log.Error("New:crowdsecLapiKey fail to get CrowdsecLapiKey and no client certificate setup " + errAPIKey.Error())
			return nil, errAPIKey
		}
		config.CrowdsecLapiKey = apiKey
	}

	var banTemplateString string
	if config.BanHTMLFilePath != "" {
		var buf bytes.Buffer
		banTemplate, _ := configuration.GetHTMLTemplate(config.BanHTMLFilePath)
		err = banTemplate.Execute(&buf, nil)
		if err != nil {
			log.Error("New:banTemplate is bad formatted " + err.Error())
			return nil, err
		}
		banTemplateString = buf.String()
	}

	bouncer := &Bouncer{
		next:     next,
		name:     name,
		template: template.New("CrowdsecBouncer").Delims("[[", "]]"),

		enabled:                 config.Enabled,
		crowdsecMode:            config.CrowdsecMode,
		appsecEnabled:           config.CrowdsecAppsecEnabled,
		appsecHost:              config.CrowdsecAppsecHost,
		appsecPath:              config.CrowdsecAppsecPath,
		appsecFailureBlock:      config.CrowdsecAppsecFailureBlock,
		appsecUnreachableBlock:  config.CrowdsecAppsecUnreachableBlock,
		appsecBodyLimit:         config.CrowdsecAppsecBodyLimit,
		crowdsecScheme:          config.CrowdsecLapiScheme,
		crowdsecHost:            config.CrowdsecLapiHost,
		crowdsecPath:            config.CrowdsecLapiPath,
		crowdsecKey:             config.CrowdsecLapiKey,
		crowdsecMachineID:       config.CrowdsecCapiMachineID,
		crowdsecPassword:        config.CrowdsecCapiPassword,
		crowdsecScenarios:       config.CrowdsecCapiScenarios,
		updateInterval:          config.UpdateIntervalSeconds,
		updateMaxFailure:        config.UpdateMaxFailure,
		remediationCustomHeader: config.RemediationHeadersCustomName,
		forwardedCustomHeader:   config.ForwardedHeadersCustomName,
		defaultDecisionTimeout:  config.DefaultDecisionSeconds,
		remediationStatusCode:   config.RemediationStatusCode,
		redisUnreachableBlock:   config.RedisCacheUnreachableBlock,
		banTemplateString:       banTemplateString,
		crowdsecStreamRoute:     crowdsecStreamRoute,
		crowdsecHeader:          crowdsecHeader,
		log:                     log,
		serverPoolStrategy: &ip.PoolStrategy{
			Checker: serverChecker,
		},
		clientPoolStrategy: &ip.PoolStrategy{
			Checker: clientChecker,
		},
		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:    10,
				IdleConnTimeout: 30 * time.Second,
				TLSClientConfig: tlsConfig,
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
		config.RedisCachePassword,
		config.RedisCacheDatabase,
	)
	config.CaptchaSiteKey, _ = configuration.GetVariable(config, "CaptchaSiteKey")
	config.CaptchaSecretKey, _ = configuration.GetVariable(config, "CaptchaSecretKey")
	err = bouncer.captchaClient.New(
		log,
		bouncer.cacheClient,
		&http.Client{
			Transport: &http.Transport{MaxIdleConns: 10, IdleConnTimeout: 30 * time.Second},
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
		config.CaptchaHTMLFilePath,
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
		handleStreamTicker(bouncer)
		isStartup = false
		streamTicker = startTicker("stream", config.UpdateIntervalSeconds, log, func() {
			handleStreamTicker(bouncer)
		})
	}

	// Start metrics ticker if not already running
	if metricsTicker == nil && config.MetricsUpdateIntervalSeconds > 0 {
		lastMetricsPush = time.Now() // Initialize lastMetricsPush when starting the metrics ticker
		handleMetricsTicker(bouncer)
		metricsTicker = startTicker("metrics", config.MetricsUpdateIntervalSeconds, log, func() {
			handleMetricsTicker(bouncer)
		})
	}

	bouncer.log.Debug("New initialized mode:" + config.CrowdsecMode)

	return bouncer, nil
}

// ServeHTTP principal function of plugin.
//
//nolint:nestif,gocyclo
func (bouncer *Bouncer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if !bouncer.enabled {
		bouncer.next.ServeHTTP(rw, req)
		return
	}

	// Here we check for the trusted IPs in the forwardedCustomHeader
	remoteIP, err := ip.GetRemoteIP(req, bouncer.serverPoolStrategy, bouncer.forwardedCustomHeader)
	if err != nil {
		bouncer.log.Error(fmt.Sprintf("ServeHTTP:getRemoteIp ip:%s %s", remoteIP, err.Error()))
		handleBanServeHTTP(bouncer, rw)
		return
	}
	isTrusted, err := bouncer.clientPoolStrategy.Checker.Contains(remoteIP)
	if err != nil {
		bouncer.log.Error(fmt.Sprintf("ServeHTTP:checkerContains ip:%s %s", remoteIP, err.Error()))
		handleBanServeHTTP(bouncer, rw)
		return
	}
	// if our IP is in the trusted list we bypass the next checks
	bouncer.log.Debug(fmt.Sprintf("ServeHTTP ip:%s isTrusted:%v", remoteIP, isTrusted))
	if isTrusted {
		bouncer.next.ServeHTTP(rw, req)
		return
	}

	if bouncer.crowdsecMode == configuration.AppsecMode {
		handleNextServeHTTP(bouncer, remoteIP, rw, req)
		return
	}

	// TODO This should be simplified
	if bouncer.crowdsecMode != configuration.NoneMode {
		value, cacheErr := bouncer.cacheClient.Get(remoteIP)
		if cacheErr != nil {
			cacheErrString := cacheErr.Error()
			bouncer.log.Debug(fmt.Sprintf("ServeHTTP:Get ip:%s isBanned:false %s", remoteIP, cacheErrString))
			if !bouncer.redisUnreachableBlock && cacheErrString == cache.CacheUnreachable {
				bouncer.log.Error(fmt.Sprintf("ServeHTTP:Get ip:%s redisUnreachable=true", remoteIP))
				handleNextServeHTTP(bouncer, remoteIP, rw, req)
				return
			}
			if cacheErrString != cache.CacheMiss {
				bouncer.log.Error(fmt.Sprintf("ServeHTTP:Get ip:%s %s", remoteIP, cacheErrString))
				handleBanServeHTTP(bouncer, rw)
				return
			}
		} else {
			bouncer.log.Debug(fmt.Sprintf("ServeHTTP ip:%s cache:hit isBanned:%v", remoteIP, value))
			if value == cache.NoBannedValue {
				handleNextServeHTTP(bouncer, remoteIP, rw, req)
			} else {
				handleRemediationServeHTTP(bouncer, remoteIP, value, rw, req)
			}
			return
		}
	}

	// Right here if we cannot join the stream we forbid the request to go on.
	if bouncer.crowdsecMode == configuration.StreamMode || bouncer.crowdsecMode == configuration.AloneMode {
		if isCrowdsecStreamHealthy {
			handleNextServeHTTP(bouncer, remoteIP, rw, req)
		} else {
			bouncer.log.Debug(fmt.Sprintf("ServeHTTP isCrowdsecStreamHealthy:false ip:%s updateFailure:%d", remoteIP, updateFailure))
			handleBanServeHTTP(bouncer, rw)
		}
	} else {
		value, err := handleNoStreamCache(bouncer, remoteIP)
		if value == cache.NoBannedValue {
			handleNextServeHTTP(bouncer, remoteIP, rw, req)
		} else {
			bouncer.log.Debug(fmt.Sprintf("ServeHTTP:handleNoStreamCache ip:%s isBanned:%v %s", remoteIP, value, err.Error()))
			handleRemediationServeHTTP(bouncer, remoteIP, value, rw, req)
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
func handleBanServeHTTP(bouncer *Bouncer, rw http.ResponseWriter) {
	atomic.AddInt64(&blockedRequests, 1)

	if bouncer.remediationCustomHeader != "" {
		rw.Header().Set(bouncer.remediationCustomHeader, "ban")
	}
	if bouncer.banTemplateString == "" {
		rw.WriteHeader(bouncer.remediationStatusCode)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(bouncer.remediationStatusCode)
	_, err := fmt.Fprint(rw, bouncer.banTemplateString)
	if err != nil {
		bouncer.log.Error("handleBanServeHTTP could not write template to ResponseWriter")
	}
}

func handleRemediationServeHTTP(bouncer *Bouncer, remoteIP, remediation string, rw http.ResponseWriter, req *http.Request) {
	bouncer.log.Debug(fmt.Sprintf("handleRemediationServeHTTP ip:%s remediation:%s", remoteIP, remediation))
	if bouncer.captchaClient.Valid && remediation == cache.CaptchaValue {
		if bouncer.captchaClient.Check(remoteIP) {
			handleNextServeHTTP(bouncer, remoteIP, rw, req)
			return
		}
		atomic.AddInt64(&blockedRequests, 1) //  If we serve a captcha that should count as a dropped request.
		bouncer.captchaClient.ServeHTTP(rw, req, remoteIP)
		return
	}
	handleBanServeHTTP(bouncer, rw)
}

func handleNextServeHTTP(bouncer *Bouncer, remoteIP string, rw http.ResponseWriter, req *http.Request) {
	if bouncer.appsecEnabled {
		if err := appsecQuery(bouncer, remoteIP, req); err != nil {
			bouncer.log.Debug(fmt.Sprintf("handleNextServeHTTP ip:%s isWaf:true %s", remoteIP, err.Error()))
			handleBanServeHTTP(bouncer, rw)
			return
		}
	}
	bouncer.next.ServeHTTP(rw, req)
}

func handleStreamTicker(bouncer *Bouncer) {
	if err := handleStreamCache(bouncer); err != nil {
		bouncer.log.Debug(fmt.Sprintf("handleStreamTicker updateFailure:%d isCrowdsecStreamHealthy:%t %s", updateFailure, isCrowdsecStreamHealthy, err.Error()))
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

func startTicker(name string, updateInterval int64, log *logger.Log, work func()) chan bool {
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

// We are now in none or live mode.
func handleNoStreamCache(bouncer *Bouncer, remoteIP string) (string, error) {
	isLiveMode := bouncer.crowdsecMode == configuration.LiveMode
	routeURL := url.URL{
		Scheme:   bouncer.crowdsecScheme,
		Host:     bouncer.crowdsecHost,
		Path:     bouncer.crowdsecPath + crowdsecLapiRoute,
		RawQuery: fmt.Sprintf("ip=%v", remoteIP),
	}
	body, err := crowdsecQuery(bouncer, routeURL.String(), nil)
	if err != nil {
		return cache.BannedValue, err
	}

	if bytes.Equal(body, []byte("null")) {
		if isLiveMode {
			bouncer.cacheClient.Set(remoteIP, cache.NoBannedValue, bouncer.defaultDecisionTimeout)
		}
		return cache.NoBannedValue, nil
	}

	var decisions []Decision
	err = json.Unmarshal(body, &decisions)
	if err != nil {
		return cache.BannedValue, fmt.Errorf("handleNoStreamCache:parseBody %w", err)
	}
	if len(decisions) == 0 {
		if isLiveMode {
			bouncer.cacheClient.Set(remoteIP, cache.NoBannedValue, bouncer.defaultDecisionTimeout)
		}
		return cache.NoBannedValue, nil
	}
	var decision Decision
	for _, d := range decisions {
		decision = d
		if decision.Type == "ban" {
			break
		}
	}
	duration, err := time.ParseDuration(decision.Duration)
	if err != nil {
		return cache.BannedValue, fmt.Errorf("handleNoStreamCache:parseDuration %w", err)
	}
	var value string
	switch decision.Type {
	case "ban":
		value = cache.BannedValue
	case "captcha":
		value = cache.CaptchaValue
	default:
		bouncer.log.Debug("handleStreamCache:unknownType " + decision.Type)
	}
	if isLiveMode && bouncer.defaultDecisionTimeout > 0 {
		durationSecond := int64(duration.Seconds())
		if bouncer.defaultDecisionTimeout < durationSecond {
			durationSecond = bouncer.defaultDecisionTimeout
		}
		bouncer.cacheClient.Set(remoteIP, value, durationSecond)
	}
	return value, errors.New("handleNoStreamCache:banned")
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
	if login.Code == 200 && len(login.Token) > 0 {
		bouncer.crowdsecKey = login.Token
		bouncer.log.Debug(fmt.Sprintf("getToken statusCode:%d", login.Code))
		return nil
	}
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
		return nil
	}
	if err.Error() != cache.CacheMiss {
		return err
	}
	bouncer.cacheClient.Set(cacheTimeoutKey, cache.NoBannedValue, bouncer.updateInterval-1)
	streamRouteURL := url.URL{
		Scheme:   bouncer.crowdsecScheme,
		Host:     bouncer.crowdsecHost,
		Path:     bouncer.crowdsecPath + bouncer.crowdsecStreamRoute,
		RawQuery: fmt.Sprintf("startup=%t", !isCrowdsecStreamHealthy || isStartup),
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
	for _, decision := range stream.New {
		duration, err := time.ParseDuration(decision.Duration)
		if err == nil {
			var value string
			switch decision.Type {
			case "ban":
				value = cache.BannedValue
			case "captcha":
				value = cache.CaptchaValue
			default:
				bouncer.log.Debug("handleStreamCache:unknownType " + decision.Type)
			}
			bouncer.cacheClient.Set(decision.Value, value, int64(duration.Seconds()))
		}
	}
	for _, decision := range stream.Deleted {
		bouncer.cacheClient.Delete(decision.Value)
	}
	bouncer.log.Debug("handleStreamCache:updated")
	return nil
}

func crowdsecQuery(bouncer *Bouncer, stringURL string, data []byte) ([]byte, error) {
	var req *http.Request
	if len(data) > 0 {
		req, _ = http.NewRequest(http.MethodPost, stringURL, bytes.NewBuffer(data))
	} else {
		req, _ = http.NewRequest(http.MethodGet, stringURL, nil)
	}
	req.Header.Add(bouncer.crowdsecHeader, bouncer.crowdsecKey)
	req.Header.Add("User-Agent", "Crowdsec-Bouncer-Traefik-Plugin/1.X.X")

	res, err := bouncer.httpClient.Do(req)
	if err != nil {
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

func appsecQuery(bouncer *Bouncer, ip string, httpReq *http.Request) error {
	routeURL := url.URL{
		Scheme: bouncer.crowdsecScheme,
		Host:   bouncer.appsecHost,
		Path:   bouncer.appsecPath,
	}
	var req *http.Request
	if bouncer.appsecBodyLimit > 0 && httpReq.Body != nil && httpReq.ContentLength > 0 {
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
	} else {
		req, _ = http.NewRequest(http.MethodGet, routeURL.String(), nil)
	}

	for key, headers := range httpReq.Header {
		for _, value := range headers {
			req.Header.Add(key, value)
		}
	}
	req.Header.Set(crowdsecAppsecHeader, bouncer.crowdsecKey)
	req.Header.Set(crowdsecAppsecIPHeader, ip)
	req.Header.Set(crowdsecAppsecVerbHeader, httpReq.Method)
	req.Header.Set(crowdsecAppsecHostHeader, httpReq.Host)
	req.Header.Set(crowdsecAppsecURIHeader, httpReq.URL.String())
	req.Header.Set(crowdsecAppsecUserAgent, httpReq.Header.Get("User-Agent"))

	res, err := bouncer.httpClient.Do(req)
	if err != nil {
		bouncer.log.Error("appsecQuery:unreachable")
		if bouncer.appsecUnreachableBlock {
			return fmt.Errorf("appsecQuery:unreachable %w", err)
		}
		return nil
	}
	defer func() {
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

	if err != nil {
		return fmt.Errorf("appsecQuery:readBody %w", err)
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
				"version": "1.X.X",
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
