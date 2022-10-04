package crowdsec_bouncer_traefik_plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"text/template"
	"time"

	ttl_map "github.com/leprosus/golang-ttl-map"
)

const (
	aloneMode               = "alone"
	streamMode              = "stream"
	liveMode                = "live"
	noneMode                = "none"
	crowdsecLapiHeader      = "X-Api-Key"
	crowdsecCapiHeader      = "Authorization"
	crowdsecLapiRoute       = "v1/decisions"
	crowdsecLapiStreamRoute = "v1/decisions/stream"
	crowdsecCapiLogin       = "v2/watchers/login"
	crowdsecCapiDecisions   = "v2/decisions/stream"
	cacheBannedValue        = "t"
	cacheNoBannedValue      = "f"
)

// Config the plugin configuration.
type Config struct {
	Enabled                bool     `json:"enabled,omitempty"`
	CrowdsecMode           string   `json:"crowdsecMode,omitempty"`
	CrowdsecLapiScheme     string   `json:"crowdsecLapiScheme,omitempty"`
	CrowdsecLapiHost       string   `json:"crowdsecLapiHost,omitempty"`
	CrowdsecLapiKey        string   `json:"crowdsecLapiKey,omitempty"`
	CrowdsecCapiLogin      string   `json:"crowdsecCapiLogin,omitempty"`
	CrowdsecCapiPwd        string   `json:"crowdsecCapiPwd,omitempty"`
	CrowdsecCapiScenarios  []string `json:"crowdsecCapiScenarios,omitempty"`
	UpdateIntervalSeconds  int64    `json:"updateIntervalSeconds,omitempty"`
	DefaultDecisionSeconds int64    `json:"defaultDecisionSeconds,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Enabled:                false,
		CrowdsecMode:           streamMode,
		CrowdsecLapiScheme:     "http",
		CrowdsecLapiHost:       "crowdsec:8080",
		CrowdsecLapiKey:        "",
		CrowdsecCapiLogin:      "",
		CrowdsecCapiPwd:        "",
		CrowdsecCapiScenarios:  []string{},
		UpdateIntervalSeconds:  60,
		DefaultDecisionSeconds: 60,
	}
}

// Bouncer a Bouncer plugin.
type Bouncer struct {
	next     http.Handler
	name     string
	template *template.Template

	enabled                bool
	crowdsecStreamHealthy  bool
	crowdsecScheme         string
	crowdsecHost           string
	crowdsecKey            string
	crowdsecMode           string
	updateInterval         int64
	defaultDecisionTimeout int64
	crowdsecLogin          string
	crowdsecPwd            string
	crowdsecScenarios      []string
	client                 *http.Client
	cache                  *ttl_map.Heap
}

// New creates the crowdsec bouncer plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	err := validateParams(config)
	if err != nil {
		return nil, err
	}

	bouncer := &Bouncer{
		next:     next,
		name:     name,
		template: template.New("CrowdsecBouncer").Delims("[[", "]]"),

		enabled:                config.Enabled,
		crowdsecStreamHealthy:  false,
		crowdsecMode:           config.CrowdsecMode,
		crowdsecScheme:         config.CrowdsecLapiScheme,
		crowdsecHost:           config.CrowdsecLapiHost,
		crowdsecKey:            config.CrowdsecLapiKey,
		crowdsecLogin:          config.CrowdsecCapiLogin,
		crowdsecPwd:            config.CrowdsecCapiPwd,
		crowdsecScenarios:      config.CrowdsecCapiScenarios,
		updateInterval:         config.UpdateIntervalSeconds,
		defaultDecisionTimeout: config.DefaultDecisionSeconds,
		client: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:    10,
				IdleConnTimeout: 30 * time.Second,
			},
			Timeout: 5 * time.Second,
		},
		cache: ttl_map.New(),
	}
	if config.CrowdsecMode == streamMode || config.CrowdsecMode == aloneMode {
		go startBackgroundStream(bouncer, config)
	}
	return bouncer, nil
}

func startBackgroundStream(b *Bouncer, config *Config) {
	rand.Seed(time.Now().UnixNano())
	delay := rand.Int63n(30)
	logger(fmt.Sprintf("Wait: %v", delay))
	time.Sleep(time.Duration(delay) * time.Second)
	if config.CrowdsecMode == aloneMode {
		getToken(b)
	}
	go handleStreamCache(b)
	ticker := time.NewTicker(time.Duration(config.UpdateIntervalSeconds) * time.Second)
	for range ticker.C {
		go handleStreamCache(b)
	}
}

// ServeHTTP principal function of plugin.
func (b *Bouncer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if !b.enabled {
		b.next.ServeHTTP(rw, req)
		return
	}

	// TODO Make sur remote address does not include the port.
	remoteHost, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		logger(fmt.Sprintf("failed to extract ip from remote address: %v", err))
		b.next.ServeHTTP(rw, req)
		return
	}

	if b.crowdsecMode == streamMode || b.crowdsecMode == aloneMode || b.crowdsecMode == liveMode {
		isBanned, err := getDecision(b, remoteHost)
		if err == nil {
			if isBanned {
				rw.WriteHeader(http.StatusForbidden)
			} else {
				b.next.ServeHTTP(rw, req)
			}
			return
		}
	}

	// Right here if we cannot join the stream we forbid the request to go on.
	if b.crowdsecMode == streamMode || b.crowdsecMode == aloneMode {
		if b.crowdsecStreamHealthy {
			b.next.ServeHTTP(rw, req)
		} else {
			rw.WriteHeader(http.StatusForbidden)
		}
	} else {
		handleNoStreamCache(b, rw, req, remoteHost)
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

func logger(str string) {
	log.Printf("Crowdsec Bouncer Traefik Plugin - %s", str)
}

func contains(source []string, target string) bool {
	for _, a := range source {
		if a == target {
			return true
		}
	}
	return false
}

// Get Decision check in the cache if the IP has the banned / not banned value.
// Otherwise return with an error to add the IP in cache if we are on.
func getDecision(b *Bouncer, clientIP string) (bool, error) {
	banned, isCached := b.cache.Get(clientIP)
	bannedString, isValid := banned.(string)
	if isCached && isValid && len(bannedString) > 0 {
		return bannedString == cacheBannedValue, nil
	}
	return false, fmt.Errorf("no cache data")
}

func setDecision(b *Bouncer, clientIP string, isBanned bool, duration int64) {
	if b.crowdsecMode == noneMode {
		return
	}
	if isBanned {
		logger(fmt.Sprintf("%v banned", clientIP))
		b.cache.Set(clientIP, cacheBannedValue, duration)
	} else {
		b.cache.Set(clientIP, cacheNoBannedValue, duration)
	}
}

func handleNoStreamCache(b *Bouncer, rw http.ResponseWriter, req *http.Request, remoteHost string) {
	// We are now in none or live mode.
	routeURL := url.URL{
		Scheme:   b.crowdsecScheme,
		Host:     b.crowdsecHost,
		Path:     crowdsecLapiRoute,
		RawQuery: fmt.Sprintf("ip=%v&banned=true", remoteHost),
	}
	body := crowdsecQuery(b, routeURL.String(), false)

	if bytes.Equal(body, []byte("null")) {
		setDecision(b, remoteHost, false, b.defaultDecisionTimeout)
		b.next.ServeHTTP(rw, req)
		return
	}

	var decisions []Decision
	err := json.Unmarshal(body, &decisions)
	if err != nil {
		logger(fmt.Sprintf("failed to parse body: %s", err))
		rw.WriteHeader(http.StatusForbidden)
		return
	}
	if len(decisions) == 0 {
		setDecision(b, remoteHost, false, b.defaultDecisionTimeout)
		b.next.ServeHTTP(rw, req)
		return
	}
	rw.WriteHeader(http.StatusForbidden)
	duration, err := time.ParseDuration(decisions[0].Duration)
	if err != nil {
		logger(fmt.Sprintf("failed to parse duration: %s", err))
		return
	}
	setDecision(b, remoteHost, true, int64(duration.Seconds()))
}

func handleStreamCache(b *Bouncer) {
	// TODO clean properly on exit.
	var rawQuery string
	var path string
	if b.crowdsecMode == aloneMode {
		rawQuery = ""
		path = crowdsecCapiDecisions
	} else {
		rawQuery = fmt.Sprintf("startup=%t", !b.crowdsecStreamHealthy)
		path = crowdsecLapiStreamRoute
	}
	streamRouteURL := url.URL{
		Scheme:   b.crowdsecScheme,
		Host:     b.crowdsecHost,
		Path:     path,
		RawQuery: rawQuery,
	}
	body := crowdsecQuery(b, streamRouteURL.String(), false)
	var stream Stream
	err := json.Unmarshal(body, &stream)
	if err != nil {
		logger(fmt.Sprintf("error while parsing body: %s", err))
		b.crowdsecStreamHealthy = false
		return
	}
	for _, decision := range stream.New {
		duration, err := time.ParseDuration(decision.Duration)
		if err == nil {
			setDecision(b, decision.Value, true, int64(duration.Seconds()))
		}
	}
	for _, decision := range stream.Deleted {
		b.cache.Del(decision.Value)
	}
	b.crowdsecStreamHealthy = true
}

func getToken(b *Bouncer) {
	loginURL := url.URL{
		Scheme: b.crowdsecScheme,
		Host:   b.crowdsecHost,
		Path:   crowdsecCapiLogin,
	}
	body := crowdsecQuery(b, loginURL.String(), true)
	var login Login
	err := json.Unmarshal(body, &login)
	if err != nil {
		logger(fmt.Sprintf("error while parsing body: %s", err))
		b.crowdsecStreamHealthy = false
		return
	}
	if login.Code == 200 && len(login.Token) > 0 {
		b.crowdsecKey = login.Token
	}
}

func crowdsecQuery(b *Bouncer, stringURL string, isPost bool) []byte {
	var req *http.Request
	if isPost {
		data := []byte(fmt.Sprintf(
			`{"machine_id": "%v","password": "%v","scenarios": ["%v"]}`,
			b.crowdsecLogin,
			b.crowdsecPwd,
			strings.Join(b.crowdsecScenarios, `","`),
		))
		req, _ = http.NewRequest(http.MethodPost, stringURL, bytes.NewBuffer(data))
	} else {
		req, _ = http.NewRequest(http.MethodGet, stringURL, nil)
	}
	if b.crowdsecMode == aloneMode {
		req.Header.Add(crowdsecCapiHeader, b.crowdsecKey)
	} else {
		req.Header.Add(crowdsecLapiHeader, b.crowdsecKey)
	}
	res, err := b.client.Do(req)
	if err != nil {
		logger(fmt.Sprintf("error while fetching %v: %s", stringURL, err))
		b.crowdsecStreamHealthy = false
		return nil
	}
	if res.StatusCode == http.StatusUnauthorized && b.crowdsecMode == aloneMode {
		oldToken := b.crowdsecKey
		getToken(b)
		if oldToken == b.crowdsecKey {
			b.crowdsecStreamHealthy = false
			return nil
		}
		return crowdsecQuery(b, stringURL, false)
	}
	if res.StatusCode != http.StatusOK {
		logger(fmt.Sprintf("error while fetching %v, status code: %d", stringURL, res.StatusCode))
		b.crowdsecStreamHealthy = false
		return nil
	}
	defer func(body io.ReadCloser) {
		err = body.Close()
		if err != nil {
			logger(fmt.Sprintf("failed to close body reader: %s", err))
		}
	}(res.Body)
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		logger(fmt.Sprintf("error while reading body: %s", err))
		b.crowdsecStreamHealthy = false
		return nil
	}
	return body
}

func validateParams(config *Config) error {
	var requiredStrings map[string]string
	if config.CrowdsecMode == aloneMode {
		requiredStrings = map[string]string{
			"CrowdsecCapiLogin": config.CrowdsecLapiScheme,
			"CrowdsecCapiPwd":   config.CrowdsecLapiHost,
		}
		for _, val := range config.CrowdsecCapiScenarios {
			if len(val) == 0 {
				return fmt.Errorf("CrowdsecCapiScenarios: one or more scenario are empty")
			}
		}
		config.UpdateIntervalSeconds = 7200
		config.CrowdsecLapiKey = ""
		config.CrowdsecLapiScheme = "https"
		config.CrowdsecLapiHost = "api.crowdsec.net"
	} else {
		requiredStrings = map[string]string{
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
	}
	for key, val := range requiredStrings {
		if len(val) == 0 {
			return fmt.Errorf("%v: cannot be empty", key)
		}
	}
	if !contains([]string{noneMode, liveMode, streamMode, aloneMode}, config.CrowdsecMode) {
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
	return nil
}
