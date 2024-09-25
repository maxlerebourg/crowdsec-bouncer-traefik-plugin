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
	"strings"
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
	crowdsecCapiHost         = "api.crowdsec.net"
	crowdsecCapiHeader       = "Authorization"
	crowdsecCapiLoginRoute   = "v2/watchers/login"
	crowdsecCapiStreamRoute  = "v2/decisions/stream"
	cacheTimeoutKey          = "updated"
)

//nolint:gochecknoglobals
var (
	isStartup               = true
	isCrowdsecStreamHealthy = true
	updateFailure           = 0
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

	enabled                 bool
	appsecEnabled           bool
	appsecHost              string
	appsecFailureBlock      bool
	appsecUnreachableBlock  bool
	crowdsecScheme          string
	crowdsecHost            string
	crowdsecKey             string
	crowdsecMode            string
	crowdsecMachineID       string
	crowdsecPassword        string
	crowdsecScenarios       []string
	updateInterval          int64
	updateMaxFailure        int
	defaultDecisionTimeout  int64
	remediationCustomHeader string
	forwardedCustomHeader   string
	crowdsecStreamRoute     string
	crowdsecHeader          string
	banTemplateString       string
	clientPoolStrategy      *ip.PoolStrategy
	serverPoolStrategy      *ip.PoolStrategy
	httpClient              *http.Client
	cacheClient             *cache.Client
	captchaClient           *captcha.Client
	log                     *logger.Log
}

// New creates the crowdsec bouncer plugin.
func New(_ context.Context, next http.Handler, config *configuration.Config, name string) (http.Handler, error) {
	log := logger.New(config.LogLevel)
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
		config.CrowdsecLapiHost = crowdsecCapiHost
		config.CrowdsecLapiScheme = "https"
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
			return nil, err
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
		appsecFailureBlock:      config.CrowdsecAppsecFailureBlock,
		appsecUnreachableBlock:  config.CrowdsecAppsecUnreachableBlock,
		crowdsecScheme:          config.CrowdsecLapiScheme,
		crowdsecHost:            config.CrowdsecLapiHost,
		crowdsecKey:             config.CrowdsecLapiKey,
		crowdsecMachineID:       config.CrowdsecCapiMachineID,
		crowdsecPassword:        config.CrowdsecCapiPassword,
		crowdsecScenarios:       config.CrowdsecCapiScenarios,
		updateInterval:          config.UpdateIntervalSeconds,
		updateMaxFailure:        config.UpdateMaxFailure,
		remediationCustomHeader: config.RemediationHeadersCustomName,
		forwardedCustomHeader:   config.ForwardedHeadersCustomName,
		defaultDecisionTimeout:  config.DefaultDecisionSeconds,
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
		config.CaptchaSiteKey,
		config.CaptchaSecretKey,
		config.RemediationHeadersCustomName,
		config.CaptchaHTMLFilePath,
		config.CaptchaGracePeriodSeconds,
	)
	if err != nil {
		return nil, err
	}

	if (config.CrowdsecMode == configuration.StreamMode || config.CrowdsecMode == configuration.AloneMode) && ticker == nil {
		if config.CrowdsecMode == configuration.AloneMode {
			if err := getToken(bouncer); err != nil {
				bouncer.log.Error("New:getToken " + err.Error())
				return nil, err
			}
		}
		handleStreamTicker(bouncer)
		isStartup = false
		ticker = startTicker(config, log, func() {
			handleStreamTicker(bouncer)
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
	if bouncer.banTemplateString == "" {
		rw.WriteHeader(http.StatusForbidden)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	if bouncer.remediationCustomHeader != "" {
		rw.Header().Set(bouncer.remediationCustomHeader, "ban")
	}
	rw.WriteHeader(http.StatusForbidden)
	fmt.Fprint(rw, bouncer.banTemplateString)
}

func handleRemediationServeHTTP(bouncer *Bouncer, remoteIP, remediation string, rw http.ResponseWriter, req *http.Request) {
	bouncer.log.Debug(fmt.Sprintf("handleRemediationServeHTTP ip:%s remediation:%s", remoteIP, remediation))
	if bouncer.captchaClient.Valid && remediation == cache.CaptchaValue {
		if bouncer.captchaClient.Check(remoteIP) {
			handleNextServeHTTP(bouncer, remoteIP, rw, req)
			return
		}
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

func startTicker(config *configuration.Config, log *logger.Log, work func()) chan bool {
	ticker := time.NewTicker(time.Duration(config.UpdateIntervalSeconds) * time.Second)
	stop := make(chan bool, 1)
	go func() {
		defer log.Debug("ticker:stopped")
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
		Path:     crowdsecLapiRoute,
		RawQuery: fmt.Sprintf("ip=%v&banned=true", remoteIP),
	}
	body, err := crowdsecQuery(bouncer, routeURL.String(), false)
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
	if isLiveMode {
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
	body, err := crowdsecQuery(bouncer, loginURL.String(), true)
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
		Path:     bouncer.crowdsecStreamRoute,
		RawQuery: fmt.Sprintf("startup=%t", !isCrowdsecStreamHealthy || isStartup),
	}
	body, err := crowdsecQuery(bouncer, streamRouteURL.String(), false)
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

func crowdsecQuery(bouncer *Bouncer, stringURL string, isPost bool) ([]byte, error) {
	var req *http.Request
	if isPost {
		data := []byte(fmt.Sprintf(
			`{"machine_id": "%v","password": "%v","scenarios": ["%v"]}`,
			bouncer.crowdsecMachineID,
			bouncer.crowdsecPassword,
			strings.Join(bouncer.crowdsecScenarios, `","`),
		))
		req, _ = http.NewRequest(http.MethodPost, stringURL, bytes.NewBuffer(data))
	} else {
		req, _ = http.NewRequest(http.MethodGet, stringURL, nil)
	}
	req.Header.Add(bouncer.crowdsecHeader, bouncer.crowdsecKey)
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
		return crowdsecQuery(bouncer, stringURL, false)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crowdsecQuery url:%s, statusCode:%d", stringURL, res.StatusCode)
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
		Path:   "/",
	}
	var req *http.Request
	if httpReq.Body != nil && httpReq.ContentLength > 0 {
		bodyBytes, err := io.ReadAll(httpReq.Body)
		if err != nil {
			return fmt.Errorf("appsecQuery:GetBody %w", err)
		}
		httpReq.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
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
