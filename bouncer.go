// Package plugindemo a demo plugin.
package crowdsec_bouncer_traefik_plugin

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"text/template"
	"time"
)

const (
	realIpHeader                = "X-Real-Ip"
	forwardHeader               = "X-Forwarded-For"
	crowdsecAuthHeader          = "X-Api-Key"
	crowdsecBouncerRoute        = "v1/decisions"
	crowdsecBouncerStreamRoute  = "v1/decisions/stream"
)

var ipRegex = regexp.MustCompile(`\b\d+\.\d+\.\d+\.\d+\b`)

// Config the plugin configuration.
// type Config struct {
// 	Headers map[string]string `json:"headers,omitempty"`
// }
// // CreateConfig creates the default plugin configuration.
// func CreateConfig() *Config {
// 	return &Config{
// 		Headers: make(map[string]string),
// 	}
// }

type Config struct {
	Enabled               bool   `json:"enabled,omitempty"`
	CrowdsecMode          string `json:"crowdsecMode,omitempty"`
	CrowdsecLapiScheme       string `json:"crowdsecLapiScheme,omitempty"`
	CrowdsecLapiHost       string `json:"crowdsecLapiHost,omitempty"`
	CrowdsecLapiKey       string `json:"crowdsecLapiKey,omitempty"`
	UpdateIntervalSeconds int    `json:"updateIntervalSeconds,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		Enabled:               false,
		CrowdsecMode:          "none",
		CrowdsecLapiScheme:    "http",
		CrowdsecLapiHost:      "crowdsec:8080",
		CrowdsecLapiKey:       "",
		UpdateIntervalSeconds: 300,
	}
}

// Demo a Demo plugin.
type Bouncer struct {
	next     http.Handler
	name     string
	template *template.Template

	enabled               bool
	crowdsecScheme        string
	crowdsecHost          string
	crowdsecMode          string
	crowdsecKey           string
	updateInterval        time.Duration
	client                *http.Client
}

func contains(source []string, target string) bool {
	for _, a := range source {
		if a == target {
			return true
		}
	}
	return false
}

// New created a new Demo plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	required := map[string]string{
		config.CrowdsecLapiScheme: "CrowdsecLapiScheme",
		config.CrowdsecLapiHost: "CrowdsecLapiHost",
		config.CrowdsecLapiKey: "CrowdsecLapiKey",
		config.CrowdsecMode: "CrowdsecMode",
	}
	for key, val := range required {
		if len(val) != 0 {
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

		crowdsecMode: config.CrowdsecMode,
		crowdsecScheme: config.CrowdsecLapiScheme,
		crowdsecHost: config.CrowdsecLapiHost,
		crowdsecKey: config.CrowdsecLapiKey,
		updateInterval: time.Duration(config.UpdateIntervalSeconds) * time.Second,
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
		a.next.ServeHTTP(rw, req)
		return
	}

	remoteHost, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		log.Printf("failed to extract ip from remote address: %v", err)
		a.next.ServeHTTP(rw, req)
		return
	}

	if a.crowdsecMode == "none" {
		noneUrl := url.URL{
			Scheme:   a.crowdsecScheme,
			Host:     a.crowdsecHost,
			Path:     crowdsecBouncerRoute,
			RawQuery: fmt.Sprintf("ip=%v&banned=true", remoteHost),
		}
		res, err := a.client.Get(noneUrl.String())
		if err != nil {
			log.Printf("failed to get decision: %s", err)
			rw.WriteHeader(http.StatusForbidden)
			return
		}
		if res.StatusCode != 200 {
			log.Printf("failed to get decision, status code: %d", res.StatusCode)
			rw.WriteHeader(http.StatusForbidden)
			return
		}
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Printf("failed to read body from crowdsec: %s", err)
			rw.WriteHeader(http.StatusForbidden)
			return
		}
		if !bytes.Equal(body, []byte("null")) {
			log.Printf("ip banned: %v", remoteHost)
			rw.WriteHeader(http.StatusForbidden)
			return
		}
		a.next.ServeHTTP(rw, req)
	}

	a.next.ServeHTTP(rw, req)
}