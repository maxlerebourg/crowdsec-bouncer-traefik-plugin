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
	"text/template"
	"time"

	ttl_map "github.com/leprosus/golang-ttl-map"
)

const (
	streamMode              = "stream"
	liveMode                = "live"
	noneMode                = "none"
	crowdsecLapiHeader      = "X-Api-Key"
	crowdsecCapiHeader      = "Authorization"
	crowdsecLapiRoute       = "v1/decisions"
	crowdsecLapiStreamRoute = "v1/decisions/stream"
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
	UpdateIntervalSeconds  int64    `json:"updateIntervalSeconds,omitempty"`
	DefaultDecisionSeconds int64    `json:"defaultDecisionSeconds,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Enabled:                false,
		CrowdsecMode:           noneMode,
		CrowdsecLapiScheme:     "http",
		CrowdsecLapiHost:       "crowdsec:8080",
		CrowdsecLapiKey:        "",
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
	if config.CrowdsecMode == streamMode {
		go func() {
			rand.Seed(time.Now().UnixNano())
			timeout := rand.Int63n(30)
			logger(fmt.Sprintf("Wait: %v", timeout))
			time.Sleep(time.Duration(timeout) * time.Second)
			go handleStreamCache(bouncer)
			ticker := time.NewTicker(time.Duration(config.UpdateIntervalSeconds) * time.Second)
			for range ticker.C {
				go handleStreamCache(bouncer)
			}
		}()
	}
	return bouncer, nil
}

// ServeHTTP principal function of plugin.
func (bouncer *Bouncer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if !bouncer.enabled {
		bouncer.next.ServeHTTP(rw, req)
		return
	}

	// TODO Make sur remote address does not include the port.
	remoteHost, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		logger(fmt.Sprintf("failed to extract ip from remote address: %v", err))
		bouncer.next.ServeHTTP(rw, req)
		return
	}

	if bouncer.crowdsecMode == streamMode || bouncer.crowdsecMode == liveMode {
		isBanned, err := getDecision(bouncer, remoteHost)
		if err == nil {
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
		if bouncer.crowdsecStreamHealthy {
			bouncer.next.ServeHTTP(rw, req)
		} else {
			rw.WriteHeader(http.StatusForbidden)
		}
	} else {
		handleNoStreamCache(bouncer, rw, req, remoteHost)
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
	for _, item := range source {
		if item == target {
			return true
		}
	}
	return false
}

// Get Decision check in the cache if the IP has the banned / not banned value.
// Otherwise return with an error to add the IP in cache if we are on.
func getDecision(bouncer *Bouncer, clientIP string) (bool, error) {
	banned, isCached := bouncer.cache.Get(clientIP)
	bannedString, isValid := banned.(string)
	if isCached && isValid && len(bannedString) > 0 {
		return bannedString == cacheBannedValue, nil
	}
	return false, fmt.Errorf("no cache data")
}

func setDecision(bouncer *Bouncer, clientIP string, isBanned bool, duration int64) {
	if bouncer.crowdsecMode == noneMode {
		return
	}
	if isBanned {
		logger(fmt.Sprintf("%v banned", clientIP))
		bouncer.cache.Set(clientIP, cacheBannedValue, duration)
	} else {
		bouncer.cache.Set(clientIP, cacheNoBannedValue, duration)
	}
}

func handleNoStreamCache(bouncer *Bouncer, rw http.ResponseWriter, req *http.Request, remoteHost string) {
	// We are now in none or live mode.
	routeURL := url.URL{
		Scheme:   bouncer.crowdsecScheme,
		Host:     bouncer.crowdsecHost,
		Path:     crowdsecLapiRoute,
		RawQuery: fmt.Sprintf("ip=%v&banned=true", remoteHost),
	}
	body := crowdsecQuery(bouncer, routeURL.String())

	if bytes.Equal(body, []byte("null")) {
		setDecision(bouncer, remoteHost, false, bouncer.defaultDecisionTimeout)
		bouncer.next.ServeHTTP(rw, req)
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
		setDecision(bouncer, remoteHost, false, bouncer.defaultDecisionTimeout)
		bouncer.next.ServeHTTP(rw, req)
		return
	}
	rw.WriteHeader(http.StatusForbidden)
	duration, err := time.ParseDuration(decisions[0].Duration)
	if err != nil {
		logger(fmt.Sprintf("failed to parse duration: %s", err))
		return
	}
	setDecision(bouncer, remoteHost, true, int64(duration.Seconds()))
}

func handleStreamCache(bouncer *Bouncer) {
	// TODO clean properly on exit.
	streamRouteURL := url.URL{
		Scheme:   bouncer.crowdsecScheme,
		Host:     bouncer.crowdsecHost,
		Path:     crowdsecLapiStreamRoute,
		RawQuery: fmt.Sprintf("startup=%t", !bouncer.crowdsecStreamHealthy),
	}
	body := crowdsecQuery(bouncer, streamRouteURL.String())
	var stream Stream
	err := json.Unmarshal(body, &stream)
	if err != nil {
		logger(fmt.Sprintf("error while parsing body: %s", err))
		bouncer.crowdsecStreamHealthy = false
		return
	}
	for _, decision := range stream.New {
		duration, err := time.ParseDuration(decision.Duration)
		if err == nil {
			setDecision(bouncer, decision.Value, true, int64(duration.Seconds()))
		}
	}
	for _, decision := range stream.Deleted {
		bouncer.cache.Del(decision.Value)
	}
	bouncer.crowdsecStreamHealthy = true
}

func crowdsecQuery(bouncer *Bouncer, stringURL string) []byte {
	var req *http.Request
	req, _ = http.NewRequest(http.MethodGet, stringURL, nil)
	req.Header.Add(crowdsecLapiHeader, bouncer.crowdsecKey)
	res, err := bouncer.client.Do(req)
	if err != nil {
		logger(fmt.Sprintf("error while fetching %v: %s", stringURL, err))
		bouncer.crowdsecStreamHealthy = false
		return nil
	}
	if res.StatusCode != http.StatusOK {
		logger(fmt.Sprintf("error while fetching %v, status code: %d", stringURL, res.StatusCode))
		bouncer.crowdsecStreamHealthy = false
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
		bouncer.crowdsecStreamHealthy = false
		return nil
	}
	return body
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
	return nil
}
