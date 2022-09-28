// Package plugindemo a demo plugin.
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
	"regexp"
	"text/template"
	"time"

	ttl_map "github.com/leprosus/golang-ttl-map"
)

const (
	realIpHeader                = "X-Real-Ip"
	forwardHeader               = "X-Forwarded-For"
	crowdsecAuthHeader          = "X-Api-Key"
	crowdsecBouncerRoute        = "v1/decisions"
	crowdsecBouncerStreamRoute  = "v1/decisions/stream"
	cacheBannedValue            = "t"
	cacheNoBannedValue          = "f"
)

var ipRegex = regexp.MustCompile(`\b\d+\.\d+\.\d+\.\d+\b`)
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
		CrowdsecMode:           "live",
		CrowdsecLapiScheme:     "http",
		CrowdsecLapiHost:       "crowdsec:8080",
		CrowdsecLapiKey:        "",
		UpdateIntervalSeconds:  10,
		DefaultDecisionSeconds: 10,
	}
}

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
	client                 *http.Client
}

// New created a new Demo plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	required := map[string]string{
		"CrowdsecLapiScheme": config.CrowdsecLapiScheme,
	  "CrowdsecLapiHost": config.CrowdsecLapiHost,
		"CrowdsecLapiKey": config.CrowdsecLapiKey,
		"CrowdsecMode": config.CrowdsecMode,
	}
	for val, key := range required {
		if len(val) == 0 {
			return nil, fmt.Errorf("%v cannot be empty", key)
		}
	}
	if !contains([]string{"none", "live", "stream"}, config.CrowdsecMode) {
		return nil, fmt.Errorf("CrowdsecMode must be one of: none, live or stream")
	}
	if !contains([]string{"http", "https"}, config.CrowdsecLapiScheme) {
		return nil, fmt.Errorf("CrowdsecLapiScheme must be one of: http, https")
	}
	testUrl := url.URL{
		Scheme:   config.CrowdsecLapiScheme,
		Host:     config.CrowdsecLapiHost,
		Path:     crowdsecBouncerRoute,
	}
	_, err := http.NewRequest(http.MethodGet, testUrl.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("CrowdsecLapiScheme://CrowdsecLapiHost: '%v://%v' must be an URL", config.CrowdsecLapiScheme, config.CrowdsecLapiHost) 
	}

	return &Bouncer{
		next:     next,
		name:     name,
		template: template.New("CrowdsecBouncer").Delims("[[", "]]"),

		enabled: config.Enabled,
		crowdsecMode: config.CrowdsecMode,
		crowdsecScheme: config.CrowdsecLapiScheme,
		crowdsecHost: config.CrowdsecLapiHost,
		crowdsecKey: config.CrowdsecLapiKey,
		updateInterval: config.UpdateIntervalSeconds,
		defaultDecisionTimeout: config.DefaultDecisionSeconds,
		client: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:    10,
				IdleConnTimeout: 30 * time.Second,
			},
			Timeout: 5 * time.Second,
		},
	}, nil
}

func (a *Bouncer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if !a.enabled {
		log.Printf("not enabled")
		a.next.ServeHTTP(rw, req)
		return
	}

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

	if a.crowdsecMode == "stream" {
		a.next.ServeHTTP(rw, req)
		return
	}

	if a.crowdsecMode == "none" || a.crowdsecMode == "live" {
		noneUrl := url.URL{
			Scheme:   a.crowdsecScheme,
			Host:     a.crowdsecHost,
			Path:     crowdsecBouncerRoute,
			RawQuery: fmt.Sprintf("ip=%v&banned=true", remoteHost),
		}
		req, _ := http.NewRequest(http.MethodGet, noneUrl.String(), nil)
		req.Header.Add(crowdsecAuthHeader, a.crowdsecKey)
		res, err := a.client.Do(req)
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
			log.Printf("ip banned: %v", remoteHost)
			rw.WriteHeader(http.StatusForbidden)
			setDecision(remoteHost, true, int64(duration.Seconds()))
			return
		}
		if a.crowdsecMode == "live" {
			setDecision(remoteHost, false, a.defaultDecisionTimeout)
		}
		a.next.ServeHTTP(rw, req)
		return
	}

	a.next.ServeHTTP(rw, req)
}

// CUSTOM CODE

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
	Deleted []Decision 	`json:"deleted"`
	New     []Decision 	`json:"new"`
}

func contains(source []string, target string) bool {
	for _, a := range source {
		if a == target {
			return true
		}
	}
	return false
}

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