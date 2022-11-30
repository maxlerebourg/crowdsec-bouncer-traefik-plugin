// Package crowdsec_bouncer_traefik_plugin implements a middleware that communicates with crowdsec.
// It can cache results to filesystem or redis, or even ask crowdsec for every requests.
package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
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
	isCrowdsecStreamHealthy = false
	ticker                  chan bool
)

// Config the plugin configuration.
type Config struct {
	Enabled                                  bool     `json:"enabled,omitempty"`
	LogLevel                                 string   `json:"logLevel,omitempty"`
	CrowdsecMode                             string   `json:"crowdsecMode,omitempty"`
	CrowdsecLapiScheme                       string   `json:"crowdsecLapiScheme,omitempty"`
	CrowdsecLapiHost                         string   `json:"crowdsecLapiHost,omitempty"`
	CrowdsecLapiKey                          string   `json:"crowdsecLapiKey,omitempty"`
	CrowdsecLapiKeyFile                      string   `json:"crowdsecLapiKeyFile,omitempty"`
	CrowdsecLapiTLSInsecureVerify            bool     `json:"crowdsecLapiTlsInsecureVerify,omitempty"`
	CrowdsecLapiTLSCertificateAuthority      string   `json:"crowdsecLapiTlsCertificateAuthority,omitempty"`
	CrowdsecLapiTLSCertificateAuthorityFile  string   `json:"crowdsecLapiTlsCertificateAuthorityFile,omitempty"`
	CrowdsecLapiTLSCertificateBouncer        string   `json:"crowdsecLapiTlsCertificateBouncer,omitempty"`
	CrowdsecLapiTLSCertificateBouncerFile    string   `json:"crowdsecLapiTlsCertificateBouncerFile,omitempty"`
	CrowdsecLapiTLSCertificateBouncerKey     string   `json:"crowdsecLapiTlsCertificateBouncerKey,omitempty"`
	CrowdsecLapiTLSCertificateBouncerKeyFile string   `json:"crowdsecLapiTlsCertificateBouncerKeyFile,omitempty"`
	UpdateIntervalSeconds                    int64    `json:"updateIntervalSeconds,omitempty"`
	DefaultDecisionSeconds                   int64    `json:"defaultDecisionSeconds,omitempty"`
	ForwardedHeadersCustomName               string   `json:"forwardedheaderscustomheader,omitempty"`
	ForwardedHeadersTrustedIPs               []string `json:"forwardedHeadersTrustedIps,omitempty"`
	ClientTrustedIPs                         []string `json:"clientTrustedIps,omitempty"`
	RedisCacheEnabled                        bool     `json:"redisCacheEnabled,omitempty"`
	RedisCacheHost                           string   `json:"redisCacheHost,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Enabled:                       false,
		LogLevel:                      "INFO",
		CrowdsecMode:                  liveMode,
		CrowdsecLapiScheme:            "http",
		CrowdsecLapiHost:              "crowdsec:8080",
		CrowdsecLapiKey:               "",
		CrowdsecLapiTLSInsecureVerify: false,
		UpdateIntervalSeconds:         60,
		DefaultDecisionSeconds:        60,
		ForwardedHeadersCustomName:    "X-Forwarded-For",
		ForwardedHeadersTrustedIPs:    []string{},
		ClientTrustedIPs:              []string{},
		RedisCacheEnabled:             false,
		RedisCacheHost:                "redis:6379",
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
		logger.Info(fmt.Sprintf("New:validateParams %s", err.Error()))
		return nil, err
	}

	serverChecker, _ := ip.NewChecker(config.ForwardedHeadersTrustedIPs)
	clientChecker, _ := ip.NewChecker(config.ClientTrustedIPs)

	tlsConfig, err := getTLSConfigCrowdsec(config)
	if err != nil {
		logger.Error(fmt.Sprintf("New:getTLSConfigCrowdsec fail to get tlsConfig %s", err.Error()))
		return nil, err
	}
	apiKey, err := getVariable(config, "CrowdsecLapiKey")
	if err != nil && len(tlsConfig.Certificates) == 0 {
		logger.Error(fmt.Sprintf("New:crowdsecLapiKey fail to get CrowdsecLapiKey and no client certificate setup %s", err.Error()))
		return nil, err
	}

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
			Timeout: 2 * time.Second,
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
	if bouncer.crowdsecMode != noneMode {
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
	if bouncer.crowdsecMode == streamMode {
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
func handleNoStreamCache(bouncer *Bouncer, remoteIP string) error {
	isLiveMode := bouncer.crowdsecMode == liveMode
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

func getTLSConfigCrowdsec(config *Config) (*tls.Config, error) {
	tlsConfig := new(tls.Config)
	tlsConfig.RootCAs = x509.NewCertPool()
	//nolint:gocritic
	if config.CrowdsecLapiScheme != "https" {
		logger.Debug("getTLSConfigCrowdsec:CrowdsecLapiScheme not https")
		return tlsConfig, nil
	} else if config.CrowdsecLapiTLSInsecureVerify {
		logger.Debug("getTLSConfigCrowdsec:CrowdsecLapiTLSInsecureVerify is true")
		tlsConfig.InsecureSkipVerify = true
		// If we return here and still want to use client auth this won't work
		// return tlsConfig, nil
	} else {
		certAuthority, err := getVariable(config, "CrowdsecLapiTLSCertificateAuthority")
		if err != nil {
			return nil, err
		}
		cert := []byte(certAuthority)
		if !tlsConfig.RootCAs.AppendCertsFromPEM(cert) {
			logger.Debug("getTLSConfigCrowdsec:CrowdsecLapiTLSCertificateAuthority read cert failed")
			// here we return because if CrowdsecLapiTLSInsecureVerify is false
			// and CA not load, we can't communicate with https
			return nil, errors.New("getTLSConfigCrowdsec:cannot load CA and verify cert is enabled")
		}
	}

	certBouncer, err := getVariable(config, "CrowdsecLapiTLSCertificateBouncer")
	if err != nil {
		return nil, err
	}
	certBouncerKey, err := getVariable(config, "CrowdsecLapiTLSCertificateBouncerKey")
	if err != nil {
		return nil, err
	}
	if certBouncer == "" || certBouncerKey == "" {
		return tlsConfig, nil
	}
	clientCert, err := tls.X509KeyPair([]byte(certBouncer), []byte(certBouncerKey))
	if err != nil {
		return nil, fmt.Errorf("getTLSClientConfigCrowdsec impossible to generate ClientCert %w", err)
	}
	tlsConfig.Certificates = append(tlsConfig.Certificates, clientCert)

	return tlsConfig, nil
}

func getVariable(config *Config, key string) (string, error) {
	value := ""
	object := reflect.Indirect(reflect.ValueOf(config))
	field := object.FieldByName(fmt.Sprintf("%sFile", key))
	// Here linter say you should simplify this code
	if field.IsValid() {
		fp := field.String()
		if fp != "" {
			file, err := os.Stat(fp)
			if err != nil {
				return value, fmt.Errorf("%s:%s invalid path %w", key, fp, err)
			}
			if file.IsDir() {
				return value, fmt.Errorf("%s:%s path must be a file", key, fp)
			}
			fileValue, err := os.ReadFile(filepath.Clean(fp))
			if err != nil {
				return value, fmt.Errorf("%s:%s read file path failed %w", key, fp, err)
			}
			value = string(fileValue)
			return value, nil
		}
	}
	field = object.FieldByName(key)
	if field.IsValid() {
		value = field.String()
		if value != "" {
			return value, nil
		}
	}
	return value, nil
}

func validateParams(config *Config) error {
	if err := validateParamsRequired(config); err != nil {
		return err
	}
	testURL := url.URL{
		Scheme: config.CrowdsecLapiScheme,
		Host:   config.CrowdsecLapiHost,
	}
	// This only check that the format of the URL scheme:// is correct and do not make requests

	if _, err := http.NewRequest(http.MethodGet, testURL.String(), nil); err != nil {
		return fmt.Errorf("CrowdsecLapiScheme://CrowdsecLapiHost: '%v://%v' must be an URL", config.CrowdsecLapiScheme, config.CrowdsecLapiHost)
	}

	if err := validateParamsIPs(config.ForwardedHeadersTrustedIPs, "ForwardedHeadersTrustedIPs"); err != nil {
		return err
	}
	if err := validateParamsIPs(config.ClientTrustedIPs, "ClientTrustedIPs"); err != nil {
		return err
	}

	lapiKey, err := getVariable(config, "CrowdsecLapiKey")
	if err != nil {
		return err
	}
	certBouncer, err := getVariable(config, "CrowdsecLapiTLSCertificateBouncer")
	if err != nil {
		return err
	}
	certBouncerKey, err := getVariable(config, "CrowdsecLapiTLSCertificateBouncerKey")
	if err != nil {
		return err
	}
	// We need to either have crowdsecLapiKey defined or the BouncerCert and Bouncerkey
	if lapiKey == "" && (certBouncer == "" || certBouncerKey == "") {
		return fmt.Errorf("CrowdsecLapiKey || (CrowdsecLapiTLSCertificateBouncer && CrowdsecLapiTLSCertificateBouncerKey): cannot be both empty")
	}

	// Case https to contact Crowdsec LAPI and certificate must be provided
	if config.CrowdsecLapiScheme == "https" && !config.CrowdsecLapiTLSInsecureVerify {
		err = validateParamsTLS(config)
		if err != nil {
			return err
		}
	}

	return nil
}

func validateParamsTLS(config *Config) error {
	certAuth, err := getVariable(config, "CrowdsecLapiTLSCertificateAuthority")
	if err != nil {
		return err
	}
	if certAuth == "" {
		return fmt.Errorf("CrowdsecLapiTLSCertificateAuthority must be specified when CrowdsecLapiScheme='https' and CrowdsecLapiTLSInsecureVerify=false")
	}
	tlsConfig := new(tls.Config)
	tlsConfig.RootCAs = x509.NewCertPool()
	if !tlsConfig.RootCAs.AppendCertsFromPEM([]byte(certAuth)) {
		return fmt.Errorf("failed parsing pem file")
	}
	return nil
}

func validateParamsIPs(listIP []string, key string) error {
	if len(listIP) > 0 {
		if _, err := ip.NewChecker(listIP); err != nil {
			return fmt.Errorf("%s must be a list of IP/CIDR :%w", key, err)
		}
	} else {
		logger.Debug(fmt.Sprintf("No IP provided for %s", key))
	}
	return nil
}

func validateParamsRequired(config *Config) error {
	requiredStrings := map[string]string{
		"CrowdsecLapiScheme": config.CrowdsecLapiScheme,
		"CrowdsecLapiHost":   config.CrowdsecLapiHost,
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
	return nil
}
