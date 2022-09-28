package crowdsec_bouncer_traefik_plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"text/template"
	"time"

	ttl_map "github.com/leprosus/golang-ttl-map"
)

const (
	crowdsecAuthHeader  = "X-Api-Key"
	crowdsecRoute       = "v1/decisions"
	crowdsecStreamRoute = "v1/decisions/stream"
	cacheBannedValue    = "t"
	cacheNoBannedValue  = "f"
)

var cache = ttl_map.New()

type Config struct {
	Enabled                bool   `json:"enabled,omitempty"`
	CrowdsecMode           string `json:"crowdsecMode,omitempty"`
	CrowdsecLapiScheme     string `json:"crowdsecLapiScheme,omitempty"`
	CrowdsecLapiHost       string `json:"crowdsecLapiHost,omitempty"`
	CrowdsecLapiKey        string `json:"crowdsecLapiKey,omitempty"`
	UpdateIntervalSeconds  int64  `json:"updateIntervalSeconds,omitempty"`
	DefaultDecisionSeconds int64  `json:"defaultDecisionSeconds,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		Enabled:                false,
		CrowdsecMode:           "none",
		CrowdsecLapiScheme:     "http",
		CrowdsecLapiHost:       "crowdsec:8080",
		CrowdsecLapiKey:        "",
		UpdateIntervalSeconds:  60,
		DefaultDecisionSeconds: 60,
	}
}

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
}

// New creates the crowdsec bouncer plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	requiredStrings := map[string]string{
		"CrowdsecLapiScheme": config.CrowdsecLapiScheme,
		"CrowdsecLapiHost":   config.CrowdsecLapiHost,
		"CrowdsecLapiKey":    config.CrowdsecLapiKey,
		"CrowdsecMode":       config.CrowdsecMode,
	}
	for key, val := range requiredStrings {
		if len(val) == 0 {
			return nil, fmt.Errorf("%v cannot be empty", key)
		}
	}
	requiredInt := map[string]int64{
		"UpdateIntervalSeconds":  config.UpdateIntervalSeconds,
		"DefaultDecisionSeconds": config.DefaultDecisionSeconds,
	}
	for key, val := range requiredInt {
		if val < 1 {
			return nil, fmt.Errorf("%v cannot be less than 1", key)
		}
	}
	// none -> If the client IP is on ban list, it will get a http code 403 response.
	//         Otherwise, request will continue as usual. All request call the Crowdsec LAPI
	// live ->  If the client IP is on ban list, it will get a http code 403 response.
	//          Otherwise, request will continue as usual.
	//          The bouncer can leverage use of a local cache in order to reduce the number
	//          of requests made to the Crowdsec LAPI. It will keep in cache the status for
	//          each IP that makes queries.
	// stream -> Stream Streaming mode allows you to keep in the local cache only the Banned IPs,
	// 			every requests that does not hit the cache is authorized.
	// 			Every minute, the cache is updated with news from the Crowdsec LAPI.
	if !contains([]string{"none", "live", "stream"}, config.CrowdsecMode) {
		return nil, fmt.Errorf("CrowdsecMode must be one of: none, live or stream")
	}
	if !contains([]string{"http", "https"}, config.CrowdsecLapiScheme) {
		return nil, fmt.Errorf("CrowdsecLapiScheme must be one of: http, https")
	}
	testUrl := url.URL{
		Scheme: config.CrowdsecLapiScheme,
		Host:   config.CrowdsecLapiHost,
		Path:   crowdsecRoute,
	}
	_, err := http.NewRequest(http.MethodGet, testUrl.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("CrowdsecLapiScheme://CrowdsecLapiHost: '%v://%v' must be an URL", config.CrowdsecLapiScheme, config.CrowdsecLapiHost)
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
	}
	// if we are on a stream mode, we fetch in a go routine every minute the new decisions
	if config.CrowdsecMode == "stream" {
		go handleStreamCache(bouncer, true)
	}
	return bouncer, nil
}

func (a *Bouncer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if !a.enabled {
		log.Printf("Crowdsec Bouncer not enabled")
		a.next.ServeHTTP(rw, req)
		return
	}

	// TODO Make sur remote address does not include the port
	remoteHost, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		log.Printf("failed to extract ip from remote address: %v", err)
		a.next.ServeHTTP(rw, req)
		return
	}

	if a.crowdsecMode == "stream" || a.crowdsecMode == "live" {
		isBanned, err := getDecision(remoteHost)
		if err == nil {
			if isBanned {
				rw.WriteHeader(http.StatusForbidden)
			} else {
				a.next.ServeHTTP(rw, req)
			}
			return
		}
	}

	// Right here if we cannot join the stream we forbid the request to go on
	if a.crowdsecMode == "stream" {
		if a.crowdsecStreamHealthy {
			a.next.ServeHTTP(rw, req)
		} else {
			rw.WriteHeader(http.StatusForbidden)
		}
		return
	}

	// We are now in none or live mode
	noneUrl := url.URL{
		Scheme:   a.crowdsecScheme,
		Host:     a.crowdsecHost,
		Path:     crowdsecRoute,
		RawQuery: fmt.Sprintf("ip=%v&banned=true", remoteHost),
	}
	request, _ := http.NewRequest(http.MethodGet, noneUrl.String(), nil)
	request.Header.Add(crowdsecAuthHeader, a.crowdsecKey)
	res, err := a.client.Do(request)
	if err != nil {
		log.Printf("failed to get decision: %s", err)
		rw.WriteHeader(http.StatusForbidden)
		return
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		log.Printf("failed to get decision, status code: %d", res.StatusCode)
		rw.WriteHeader(http.StatusForbidden)
		return
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("failed to read body: %s", err)
		rw.WriteHeader(http.StatusForbidden)
		return
	}
	if !bytes.Equal(body, []byte("null")) {
		var decisions []Decision
		err = json.Unmarshal(body, &decisions)
		if err != nil {
			log.Printf("failed to parse body: %s", err)
			rw.WriteHeader(http.StatusForbidden)
			return
		}
		if len(decisions) == 0 {
			if a.crowdsecMode == "live" {
				setDecision(remoteHost, false, a.defaultDecisionTimeout)
			}
			a.next.ServeHTTP(rw, req)
			return
		}
		duration, err := time.ParseDuration(decisions[0].Duration)
		if err != nil {
			log.Printf("failed to parse duration: %s", err)
			rw.WriteHeader(http.StatusForbidden)
			return
		}
		rw.WriteHeader(http.StatusForbidden)
		setDecision(remoteHost, true, int64(duration.Seconds()))
		return
	}
	if a.crowdsecMode == "live" {
		setDecision(remoteHost, false, a.defaultDecisionTimeout)
	}
	a.next.ServeHTTP(rw, req)
}

// CUSTOM CODE
// TODO place in another file
type Decision struct {
	Id        int    `json:"id"`
	Origin    string `json:"origin"`
	Type      string `json:"type"`
	Scope     string `json:"scope"`
	Value     string `json:"value"`
	Duration  string `json:"duration"`
	Scenario  string `json:"scenario"`
	Simulated bool   `json:"simulated"`
}

type Stream struct {
	Deleted []Decision `json:"deleted"`
	New     []Decision `json:"new"`
}

func contains(source []string, target string) bool {
	for _, a := range source {
		if a == target {
			return true
		}
	}
	return false
}

// Get Decision check in the cache if the IP has the banned / not banned value
// Otherwise return with an error to add the IP in cache if we are on
func getDecision(clientIP string) (bool, error) {
	isBanned, ok := cache.Get(clientIP)
	if ok && len(isBanned.(string)) > 0 {
		if isBanned == cacheNoBannedValue {
			return false, nil
		} else {
			return true, nil
		}
	}
	return false, fmt.Errorf("no data")
}

func setDecision(clientIP string, isBanned bool, duration int64) {
	if isBanned {
		cache.Set(clientIP, cacheBannedValue, duration)
	} else {
		cache.Set(clientIP, cacheNoBannedValue, duration)
	}
}

func handleStreamCache(a *Bouncer, initialized bool) {
	// TODO clean properly on exit
	time.AfterFunc(time.Duration(a.updateInterval)*time.Second, func() {
		handleStreamCache(a, false)
	})
	streamUrl := url.URL{
		Scheme:   a.crowdsecScheme,
		Host:     a.crowdsecHost,
		Path:     crowdsecStreamRoute,
		RawQuery: fmt.Sprintf("startup=%t", initialized),
	}
	req, _ := http.NewRequest(http.MethodGet, streamUrl.String(), nil)
	req.Header.Add(crowdsecAuthHeader, a.crowdsecKey)
	res, err := a.client.Do(req)
	if err != nil || res.StatusCode == http.StatusForbidden {
		log.Printf("error while fetching decisions: %s", err)
		a.crowdsecStreamHealthy = false
		return
	}
	if res.StatusCode == http.StatusForbidden {
		log.Printf("error while fetching decisions, status code: %d", res.StatusCode)
		a.crowdsecStreamHealthy = false
		return
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("error while reading body: %s", err)
		a.crowdsecStreamHealthy = false
		return
	}
	var stream Stream
	err = json.Unmarshal(body, &stream)
	if err != nil {
		log.Printf("error while parsing body: %s", err)
		a.crowdsecStreamHealthy = false
		return
	}
	for _, decision := range stream.New {
		duration, err := time.ParseDuration(decision.Duration)
		if err == nil {
			setDecision(decision.Value, true, int64(duration.Seconds()))
		}
	}
	for _, decision := range stream.Deleted {
		cache.Del(decision.Value)
	}
	a.crowdsecStreamHealthy = true
}
