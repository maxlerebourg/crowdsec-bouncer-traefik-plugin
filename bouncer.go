package crowdsec_bouncer_traefik_plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
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
		CrowdsecMode:           aloneMode,
		CrowdsecLapiScheme:     "http",
		CrowdsecLapiHost:       "crowdsec:8080",
		CrowdsecLapiKey:        "",
		CrowdsecCapiLogin:      "",
		CrowdsecCapiPwd:        "",
		CrowdsecCapiScenarios:  []string{},
		UpdateIntervalSeconds:  10,
		DefaultDecisionSeconds: 10,
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
		if config.CrowdsecMode == aloneMode {
			getToken(bouncer)
		}
		ticker := time.NewTicker(time.Duration(config.UpdateIntervalSeconds) * time.Second)
		go func() {
			go handleStreamCache(bouncer)
			for range ticker.C {
				go handleStreamCache(bouncer)
			}
		}()
	}
	return bouncer, nil
}

// ServeHTTP principal function of plugin.
func (a *Bouncer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if !a.enabled {
		a.next.ServeHTTP(rw, req)
		return
	}

	// TODO Make sur remote address does not include the port.
	remoteHost, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		logger(fmt.Sprintf("failed to extract ip from remote address: %v", err))
		a.next.ServeHTTP(rw, req)
		return
	}

	if a.crowdsecMode == streamMode || a.crowdsecMode == aloneMode || a.crowdsecMode == liveMode {
		isBanned, err := getDecision(a, remoteHost)
		if err == nil {
			if isBanned {
				rw.WriteHeader(http.StatusForbidden)
			} else {
				a.next.ServeHTTP(rw, req)
			}
			return
		}
	}

	// Right here if we cannot join the stream we forbid the request to go on.
	if a.crowdsecMode == streamMode || a.crowdsecMode == aloneMode {
		if a.crowdsecStreamHealthy {
			a.next.ServeHTTP(rw, req)
		} else {
			rw.WriteHeader(http.StatusForbidden)
		}
	} else {
		handleNoStreamCache(a, rw, req, remoteHost)
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
func getDecision(a *Bouncer, clientIP string) (bool, error) {
	banned, isCached := a.cache.Get(clientIP)
	bannedString, isValid := banned.(string)
	if isCached && isValid && len(bannedString) > 0 {
		return bannedString == cacheBannedValue, nil
	}
	return false, fmt.Errorf("no cache data")
}

func setDecision(a *Bouncer, clientIP string, isBanned bool, duration int64) {
	if a.crowdsecMode == noneMode {
		return
	}
	if isBanned {
		logger(fmt.Sprintf("%v banned", clientIP))
		a.cache.Set(clientIP, cacheBannedValue, duration)
	} else {
		a.cache.Set(clientIP, cacheNoBannedValue, duration)
	}
}

func handleNoStreamCache(a *Bouncer, rw http.ResponseWriter, req *http.Request, remoteHost string) {
	// We are now in none or live mode.
	routeURL := url.URL{
		Scheme:   a.crowdsecScheme,
		Host:     a.crowdsecHost,
		Path:     crowdsecLapiRoute,
		RawQuery: fmt.Sprintf("ip=%v&banned=true", remoteHost),
	}
	body := crowdsecQuery(a, routeURL.String(), false)

	if bytes.Equal(body, []byte("null")) {
		setDecision(a, remoteHost, false, a.defaultDecisionTimeout)
		a.next.ServeHTTP(rw, req)
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
		setDecision(a, remoteHost, false, a.defaultDecisionTimeout)
		a.next.ServeHTTP(rw, req)
		return
	}
	rw.WriteHeader(http.StatusForbidden)
	duration, err := time.ParseDuration(decisions[0].Duration)
	if err != nil {
		logger(fmt.Sprintf("failed to parse duration: %s", err))
		return
	}
	setDecision(a, remoteHost, true, int64(duration.Seconds()))
}

func handleStreamCache(a *Bouncer) {
	logger(fmt.Sprintf("Start handleStreamCache with health=%v", a.crowdsecStreamHealthy))
	// TODO clean properly on exit.
	var rawQuery string
	var path string
	if a.crowdsecMode == aloneMode {
		rawQuery = ""
		path = crowdsecCapiDecisions
	} else {
		rawQuery = fmt.Sprintf("startup=%t", !a.crowdsecStreamHealthy)
		path = crowdsecLapiStreamRoute
	}
	streamRouteURL := url.URL{
		Scheme:   a.crowdsecScheme,
		Host:     a.crowdsecHost,
		Path:     path,
		RawQuery: rawQuery,
	}
	body := crowdsecQuery(a, streamRouteURL.String(), false)
	var stream Stream
	err := json.Unmarshal(body, &stream)
	if err != nil {
		logger(fmt.Sprintf("error while parsing body: %s", err))
		a.crowdsecStreamHealthy = false
		return
	}
	for _, decision := range stream.New {
		duration, err := time.ParseDuration(decision.Duration)
		if err == nil {
			setDecision(a, decision.Value, true, int64(duration.Seconds()))
		}
	}
	for _, decision := range stream.Deleted {
		a.cache.Del(decision.Value)
	}
	a.crowdsecStreamHealthy = true
}

func getToken(a *Bouncer) {
	loginURL := url.URL{
		Scheme: a.crowdsecScheme,
		Host:   a.crowdsecHost,
		Path:   crowdsecCapiLogin,
	}
	body := crowdsecQuery(a, loginURL.String(), true)
	var login Login
	err := json.Unmarshal(body, &login)
	if err != nil {
		logger(fmt.Sprintf("error while parsing body: %s", err))
		a.crowdsecStreamHealthy = false
		return
	}
	if login.Code == 200 && len(login.Token) > 0 {
		a.crowdsecKey = login.Token
	}
}

func crowdsecQuery(a *Bouncer, stringURL string, isPost bool) []byte {
	var req *http.Request
	if isPost {
		data := []byte(fmt.Sprintf(
			`{"machine_id": "%v","password": "%v","scenarios": ["%v"]}`,
			a.crowdsecLogin,
			a.crowdsecPwd,
			strings.Join(a.crowdsecScenarios, `","`),
		))
		req, _ = http.NewRequest(http.MethodPost, stringURL, bytes.NewBuffer(data))
	} else {
		req, _ = http.NewRequest(http.MethodGet, stringURL, nil)
	}
	if a.crowdsecMode == aloneMode {
		req.Header.Add(crowdsecCapiHeader, a.crowdsecKey)
	} else {
		req.Header.Add(crowdsecLapiHeader, a.crowdsecKey)
	}
	res, err := a.client.Do(req)
	if err != nil {
		logger(fmt.Sprintf("error while fetching %v: %s", stringURL, err))
		a.crowdsecStreamHealthy = false
		return nil
	}
	if res.StatusCode == http.StatusUnauthorized && a.crowdsecMode == aloneMode {
		oldToken := a.crowdsecKey
		getToken(a)
		if oldToken == a.crowdsecKey {
			a.crowdsecStreamHealthy = false
			return nil
		}
		return crowdsecQuery(a, stringURL, false)
	}
	if res.StatusCode != http.StatusOK {
		logger(fmt.Sprintf("error while fetching %v, status code: %d", stringURL, res.StatusCode))
		a.crowdsecStreamHealthy = false
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
		a.crowdsecStreamHealthy = false
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
