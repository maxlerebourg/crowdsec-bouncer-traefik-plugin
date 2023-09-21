// Package crowdsec_bouncer_traefik_plugin implements a middleware that communicates with crowdsec.
// It can cache results to filesystem or redis, or even ask crowdsec for every requests.
package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/template"
	"time"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	ip "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/ip"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

const (
	crowdsecLapiHeader         = "X-Api-Key"
	crowdsecCapiHeader         = "Authorization"
	crowdsecLapiDecisionsRoute = "v1/decisions"
	crowdsecLapiStreamRoute    = "v1/decisions/stream"
	crowdsecLapiLoginRoute     = "v1/watchers/login"
	crowdsecCapiLoginRoute     = "v2/watchers/login"
	crowdsecCapiStreamRoute    = "v2/decisions/stream"
	cacheTimeoutKey            = "updated"
	captchaSiteVerifyURL       = "https://www.google.com/recaptcha/api/siteverify"
	decisionTypeBan            = "ban"
	decisionTypeCaptcha        = "captcha"
	decisionTypeThrottle       = "throttle"
)

//nolint:gochecknoglobals
var (
	isStartup               = true
	isCrowdsecStreamHealthy = true
	ticker                  chan bool
	captchaSecretKey        = ""
	captchaSiteKey          = ""
	captchaVerifyRoute      = ""
	jwtLapiToken            = ""
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
	crowdsecLapiMachineID  string
	crowdsecLapiPassword   string
	crowdsecMode           string
	crowdsecMachineID      string
	crowdsecPassword       string
	crowdsecScenarios      []string
	updateInterval         int64
	defaultDecisionTimeout int64
	customHeader           string
	crowdsecStreamRoute    string
	crowdsecHeader         string
	clientPoolStrategy     *ip.PoolStrategy
	serverPoolStrategy     *ip.PoolStrategy
	httpClient             *http.Client
	cacheClient            *cache.Client
	forbidOnFailure        bool
	captchaHtmlFilePath    string
	captchaSiteKey         string
	captchaSecretKey       string
	captchaVerifyRoute     string
}

// New creates the crowdsec bouncer plugin.
func New(ctx context.Context, next http.Handler, config *configuration.Config, name string) (http.Handler, error) {
	logger.Init(config.LogLevel)
	err := configuration.ValidateParams(config)
	if err != nil {
		logger.Error(fmt.Sprintf("New:validateParams %s", err.Error()))
		return nil, err
	}

	serverChecker, _ := ip.NewChecker(config.ForwardedHeadersTrustedIPs)
	clientChecker, _ := ip.NewChecker(config.ClientTrustedIPs)

	var tlsConfig *tls.Config
	crowdsecStreamRoute := ""
	crowdsecHeader := ""
	if config.CrowdsecMode == configuration.AloneMode {
		config.CrowdsecCapiMachineID, _ = configuration.GetVariable(config, "CrowdsecCapiMachineID")
		config.CrowdsecCapiPassword, _ = configuration.GetVariable(config, "CrowdsecCapiPassword")
		config.CrowdsecLapiHost = "api.crowdsec.net"
		config.CrowdsecLapiScheme = "https"
		config.UpdateIntervalSeconds = 7200
		crowdsecStreamRoute = crowdsecCapiStreamRoute
		crowdsecHeader = crowdsecCapiHeader
	} else {
		crowdsecStreamRoute = crowdsecLapiStreamRoute
		crowdsecHeader = crowdsecLapiHeader
		tlsConfig, err = configuration.GetTLSConfigCrowdsec(config)
		if err != nil {
			logger.Error(fmt.Sprintf("New:getTLSConfigCrowdsec fail to get tlsConfig %s", err.Error()))
			return nil, err
		}
		apiKey, errAPIKey := configuration.GetVariable(config, "CrowdsecLapiKey")
		if errAPIKey != nil && len(tlsConfig.Certificates) == 0 {
			logger.Error(fmt.Sprintf("New:crowdsecLapiKey fail to get CrowdsecLapiKey and no client certificate setup %s", errAPIKey.Error()))
			return nil, err
		}
		config.CrowdsecLapiKey = apiKey
	}

	bouncer := &Bouncer{
		next:     next,
		name:     name,
		template: template.New("CrowdsecBouncer").Delims("[[", "]]"),

		enabled:                config.Enabled,
		crowdsecMode:           config.CrowdsecMode,
		crowdsecScheme:         config.CrowdsecLapiScheme,
		crowdsecHost:           config.CrowdsecLapiHost,
		crowdsecKey:            config.CrowdsecLapiKey,
		crowdsecLapiMachineID:  config.CrowdsecLapiMachineID,
		crowdsecLapiPassword:   config.CrowdsecLapiPassword,
		crowdsecMachineID:      config.CrowdsecCapiMachineID,
		crowdsecPassword:       config.CrowdsecCapiPassword,
		crowdsecScenarios:      config.CrowdsecCapiScenarios,
		updateInterval:         config.UpdateIntervalSeconds,
		customHeader:           config.ForwardedHeadersCustomName,
		defaultDecisionTimeout: config.DefaultDecisionSeconds,
		crowdsecStreamRoute:    crowdsecStreamRoute,
		crowdsecHeader:         crowdsecHeader,
		forbidOnFailure:        config.ForbidOnFailure,
		captchaHtmlFilePath:    config.CaptchaHtmlFilePath,
		captchaSiteKey:         config.CaptchaSiteKey,
		captchaSecretKey:       config.CaptchaSecretKey,
		captchaVerifyRoute:     config.CaptchaVerifyRoute,
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
		cacheClient: &cache.Client{},
	}
	config.RedisCachePassword, _ = configuration.GetVariable(config, "RedisCachePassword")
	bouncer.cacheClient.New(
		config.RedisCacheEnabled,
		config.RedisCacheHost,
		config.RedisCachePassword,
		config.RedisCacheDatabase,
	)

	captchaSecretKey = bouncer.captchaSecretKey
	captchaSiteKey = bouncer.captchaSiteKey
	captchaVerifyRoute = bouncer.captchaVerifyRoute

	if (config.CrowdsecMode == configuration.StreamMode || config.CrowdsecMode == configuration.AloneMode) && ticker == nil {
		if config.CrowdsecMode == configuration.AloneMode {
			if err := getToken(bouncer); err != nil {
				logger.Error(fmt.Sprintf("New:getToken %s", err.Error()))
				return nil, err
			}
		}
		handleStreamTicker(bouncer)
		isStartup = false
		ticker = startTicker(config, func() {
			handleStreamTicker(bouncer)
		})
	}
	logger.Debug(fmt.Sprintf("New initialized mode:%s", config.CrowdsecMode))

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
		handleBanResponseSoft(bouncer, rw, req)
		return
	}

	if handleCaptchaValidation(bouncer, rw, req, remoteIP) {
		return
	}

	isTrusted, err := bouncer.clientPoolStrategy.Checker.Contains(remoteIP)
	if err != nil {
		logger.Error(fmt.Sprintf("ServeHTTP:checkerContains ip:%s %s", remoteIP, err.Error()))
		handleBanResponseSoft(bouncer, rw, req)
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
		isBanned, isCaptcha, cacheErr := bouncer.cacheClient.GetDecision(remoteIP)
		if cacheErr != nil {
			errString := cacheErr.Error()
			logger.Debug(fmt.Sprintf("ServeHTTP:getDecision ip:%s isBanned:false %s", remoteIP, errString))
			if errString != cache.CacheMiss {
				logger.Error(fmt.Sprintf("ServeHTTP:getDecision ip:%s %s", remoteIP, errString))
				handleBanResponseOrCaptcha(bouncer, rw, req, isCaptcha)
				return
			}
		} else {
			logger.Debug(fmt.Sprintf("ServeHTTP ip:%s cache:hit isBanned:%v", remoteIP, isBanned))
			if isBanned {
				handleBanResponseOrCaptcha(bouncer, rw, req, isCaptcha)
				return
			} else {
				bouncer.next.ServeHTTP(rw, req)
			}
			return
		}
	}

	// Right here if we cannot join the stream we forbid the request to go on.
	if bouncer.crowdsecMode == configuration.StreamMode || bouncer.crowdsecMode == configuration.AloneMode {
		if isCrowdsecStreamHealthy {
			logger.Debug(fmt.Sprintf("ServeHTTP:stream is healthy"))
			bouncer.next.ServeHTTP(rw, req)
		} else {
			logger.Debug(fmt.Sprintf("ServeHTTP isCrowdsecStreamHealthy:false ip:%s", remoteIP))
			if bouncer.forbidOnFailure {
				handleBanResponseForced(bouncer, rw, req)
				return
			} else {
				logger.Debug(fmt.Sprintf("ServeHTTP:stream isn't healthy. But the decision is to process the request."))
				bouncer.next.ServeHTTP(rw, req)
			}
		}
	} else {
		err = handleNoStreamCache(bouncer, remoteIP)
		if err != nil {
			logger.Debug(fmt.Sprintf("ServeHTTP:handleNoStreamCache ip:%s isBanned:true %s", remoteIP, err.Error()))
			handleBanResponseSoft(bouncer, rw, req)
			return
		} else {
			logger.Debug(fmt.Sprintf("ServeHTTP:handleNoStreamCache ip:%s isBanned:false", remoteIP))
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

// DecisionDeleted Deleted decision (in case if we verify captcha)
type DecisionDeleted struct {
	NbDeleted string `json:"nbDeleted"`
	Errors    bool   `json:"errors"`
	Message   string `json:"message"`
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

type SiteVerifyResponse struct {
	Success     bool      `json:"success"`
	Action      string    `json:"action"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	ErrorCodes  []string  `json:"error-codes"`
}

type ValidationResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func handleBanResponseSoft(bouncer *Bouncer, rw http.ResponseWriter, req *http.Request) {
	if bouncer.forbidOnFailure {
		rw.WriteHeader(http.StatusForbidden)
		return
	}
	bouncer.next.ServeHTTP(rw, req)
}

func handleBanResponseForced(bouncer *Bouncer, rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(http.StatusForbidden)
	return
}

func handleBanResponseOrCaptcha(bouncer *Bouncer, rw http.ResponseWriter, req *http.Request, isCaptcha bool) {
	logger.Debug(fmt.Sprintf("handleBanResponseOrCaptcha '%t'", isCaptcha))
	handleBanResponseForced(bouncer, rw, req)

	if !isCaptcha {
		return
	}

	logger.Debug(fmt.Sprintf("Must respond with captcha here.... Captcha file '%s'", bouncer.captchaHtmlFilePath))
	content, err := os.ReadFile(bouncer.captchaHtmlFilePath)
	content = bytes.Replace(content, []byte("{SITE_KEY}"), []byte(bouncer.captchaSiteKey), -1)
	content = bytes.Replace(content, []byte("{VERIFY_ROUTE}"), []byte(bouncer.captchaVerifyRoute), -1)
	if err != nil {
		logger.Debug(fmt.Sprintf("Error reading captcha HTML file '%s'", bouncer.captchaHtmlFilePath))
	}

	rw.Header().Add("Content-Type", "text/html")
	rw.WriteHeader(200)
	_, err = rw.Write(content)
}

func handleCaptchaValidation(bouncer *Bouncer, rw http.ResponseWriter, req *http.Request, remoteIP string) bool {
	if !(req.RequestURI == captchaVerifyRoute && req.Method == "POST") {
		return false
	}

	var response ValidationResponse
	response.Success = false

	err := req.ParseForm()
	if err != nil {
		response.Message = err.Error()
		respondJson(rw, response)
	}
	validationResponse := req.Form.Get("response")

	req, err = http.NewRequest(http.MethodPost, captchaSiteVerifyURL, nil)
	if err != nil {
		response.Message = err.Error()
		respondJson(rw, response)
		return false
	}

	// Add necessary request parameters.
	q := req.URL.Query()
	q.Add("secret", captchaSecretKey)
	q.Add("response", validationResponse)
	req.URL.RawQuery = q.Encode()

	// Make request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		response.Message = err.Error()
		respondJson(rw, response)
		return false
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			response.Message = err.Error()
			respondJson(rw, response)
		}
	}(resp.Body)

	// Decode response.
	var body SiteVerifyResponse
	if err = json.NewDecoder(resp.Body).Decode(&body); err != nil {
		response.Message = err.Error()
		respondJson(rw, response)
		return false
	}

	// Check recaptcha verification success.
	if !body.Success {
		response.Message = err.Error()
		respondJson(rw, response)
		return false
	}

	err = deleteIpDecisions(bouncer, remoteIP)
	if err != nil {
		response.Message = err.Error()
		respondJson(rw, response)
	}

	response.Success = true
	respondJson(rw, response)
	return true
}

func respondJson(rw http.ResponseWriter, response ValidationResponse) {
	rw.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(rw).Encode(response)
	if err != nil {
		logger.Error(fmt.Sprintf("respondJson:Error while sending JSON responce '%s", err.Error()))
	}
}

func deleteIpDecisions(bouncer *Bouncer, remoteIP string) error {
	refreshLapiToken(bouncer)

	deleteRouteURL := url.URL{
		Scheme:   bouncer.crowdsecScheme,
		Host:     bouncer.crowdsecHost,
		Path:     crowdsecLapiDecisionsRoute,
		RawQuery: fmt.Sprintf("ip=%s", remoteIP),
	}
	body, err := crowdsecQuery(bouncer, deleteRouteURL.String(), http.MethodDelete)
	if err != nil {
		return err
	}

	var result DecisionDeleted
	err = json.Unmarshal(body, &result)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	logger.Debug(fmt.Sprintf("deleteIpDecisions NbDeleted:%d", result.NbDeleted))
	logger.Debug(fmt.Sprintf("deleteIpDecisions Message:%d", result.Message))

	return nil
}

func handleStreamTicker(bouncer *Bouncer) {
	if err := handleStreamCache(bouncer); err != nil {
		isCrowdsecStreamHealthy = false
		logger.Error(err.Error())
	} else {
		isCrowdsecStreamHealthy = true
	}
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
		Path:     crowdsecLapiDecisionsRoute,
		RawQuery: fmt.Sprintf("ip=%v&banned=true", remoteIP),
	}
	body, err := crowdsecQuery(bouncer, routeURL.String(), http.MethodGet)
	if err != nil {
		return err
	}

	if bytes.Equal(body, []byte("null")) {
		if isLiveMode {
			bouncer.cacheClient.SetDecision(remoteIP, cache.cacheNoBannedValue, bouncer.defaultDecisionTimeout)
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
			bouncer.cacheClient.SetDecision(remoteIP, cache.cacheNoBannedValue, bouncer.defaultDecisionTimeout)
		}
		return nil
	}
	duration, err := time.ParseDuration(decisions[0].Duration)
	if err != nil {
		return fmt.Errorf("handleNoStreamCache:parseDuration %w", err)
	}
	if isLiveMode {
		durationSecond := int64(duration.Seconds())
		if bouncer.defaultDecisionTimeout < durationSecond {
			durationSecond = bouncer.defaultDecisionTimeout
		}
		bouncer.cacheClient.SetDecision(remoteIP, cache.cacheBannedValue, durationSecond)
	}
	return fmt.Errorf("handleNoStreamCache:banned")
}

func getToken(bouncer *Bouncer) error {
	loginURL := url.URL{
		Scheme: bouncer.crowdsecScheme,
		Host:   bouncer.crowdsecHost,
		Path:   crowdsecCapiLoginRoute,
	}
	body, err := crowdsecQuery(bouncer, loginURL.String(), http.MethodPost)
	if err != nil {
		return err
	}
	var login Login
	err = json.Unmarshal(body, &login)
	if err != nil {
		isCrowdsecStreamHealthy = false
		return fmt.Errorf("getToken:parsingBody %w", err)
	}
	if login.Code == 200 && len(login.Token) > 0 {
		bouncer.crowdsecKey = login.Token
		logger.Debug(fmt.Sprintf("getToken statusCode:%d", login.Code))
		return nil
	}
	return fmt.Errorf("getToken statusCode:%d", login.Code)
}

func refreshLapiToken(bouncer *Bouncer) {
	loginURL := url.URL{
		Scheme: bouncer.crowdsecScheme,
		Host:   bouncer.crowdsecHost,
		Path:   crowdsecLapiLoginRoute,
	}
	body, err := crowdsecQuery(bouncer, loginURL.String(), http.MethodPost)
	if err != nil {
		jwtLapiToken = ""
	}
	var login Login
	err = json.Unmarshal(body, &login)
	if err != nil {
		isCrowdsecStreamHealthy = false
		jwtLapiToken = ""
	}
	if login.Code == 200 && len(login.Token) > 0 {
		logger.Debug(fmt.Sprintf("New LAPI TOKEN: %s", login.Token))
		jwtLapiToken = login.Token
		return
	}
	jwtLapiToken = ""
}

func handleStreamCache(bouncer *Bouncer) error {
	// TODO clean properly on exit.
	// Instead of blocking the goroutine interval for all the secondary node,
	// if the master service is shut down, other goroutine can take the lead
	// because updated routine information is in the cache
	_, _, err := bouncer.cacheClient.GetDecision(cacheTimeoutKey)
	if err == nil {
		logger.Debug("handleStreamCache:alreadyUpdated")
		return nil
	}
	if err.Error() != cache.CacheMiss {
		return err
	}
	bouncer.cacheClient.SetDecision(cacheTimeoutKey, cache.cacheNoBannedValue, bouncer.updateInterval-1)
	streamRouteURL := url.URL{
		Scheme:   bouncer.crowdsecScheme,
		Host:     bouncer.crowdsecHost,
		Path:     bouncer.crowdsecStreamRoute,
		RawQuery: fmt.Sprintf("startup=%t", !isCrowdsecStreamHealthy || isStartup),
	}
	body, err := crowdsecQuery(bouncer, streamRouteURL.String(), http.MethodGet)

	if err != nil {
		return err
	}
	var stream Stream
	err = json.Unmarshal(body, &stream)
	if err != nil {
		return fmt.Errorf("handleStreamCache:parsingBody %w", err)
	}

	var decisionType string
	for _, decision := range stream.Deleted {
		bouncer.cacheClient.DeleteDecision(decision.Value)
	}
	for _, decision := range stream.New {
		duration, err := time.ParseDuration(decision.Duration)
		if decisionTypeCaptcha == decision.Type {
			decisionType = cache.cacheCaptchaValue
		} else {
			decisionType = cache.cacheBannedValue
		}
		if err == nil {
			bouncer.cacheClient.SetDecision(decision.Value, decisionType, int64(duration.Seconds()))
		}
	}

	logger.Debug("handleStreamCache:updated")
	isCrowdsecStreamHealthy = true
	return nil
}

func crowdsecQuery(bouncer *Bouncer, stringURL string, method string) ([]byte, error) {
	var req *http.Request
	var machineId string
	var password string

	if method == http.MethodPost {
		if bouncer.crowdsecMode == configuration.AloneMode {
			machineId = bouncer.crowdsecMachineID
			password = bouncer.crowdsecPassword
		} else {
			machineId = bouncer.crowdsecLapiMachineID
			password = bouncer.crowdsecLapiPassword
		}

		data := []byte(fmt.Sprintf(
			`{"machine_id": "%v","password": "%v","scenarios": ["%v"]}`,
			machineId,
			password,
			strings.Join(bouncer.crowdsecScenarios, `","`),
		))
		req, _ = http.NewRequest(http.MethodPost, stringURL, bytes.NewBuffer(data))
	} else {
		req, _ = http.NewRequest(method, stringURL, nil)
	}

	if method == http.MethodDelete {
		bearer := fmt.Sprintf("Bearer %s", jwtLapiToken)
		logger.Debug(fmt.Sprintf("BEARER: '%s'", bearer))
		req.Header.Add("Authorization", bearer)
	}

	req.Header.Add(bouncer.crowdsecHeader, bouncer.crowdsecKey)

	logger.Debug(fmt.Sprintf("crowdsecQuery:request | method: '%s', URL: '%s', Secret: '%s'",
		method, stringURL, bouncer.crowdsecKey))
	res, err := bouncer.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crowdsecQuery url:%s %w", stringURL, err)
	}
	if res.StatusCode == http.StatusUnauthorized && bouncer.crowdsecMode == configuration.AloneMode {
		if errToken := getToken(bouncer); errToken != nil {
			return nil, fmt.Errorf("crowdsecQuery:renewToken url:%s %w", stringURL, errToken)
		}
		return crowdsecQuery(bouncer, stringURL, http.MethodGet)
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
