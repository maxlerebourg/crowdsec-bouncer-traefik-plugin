// Package plugindemo a demo plugin.
package crowdsec_bouncer_traefik_plugin

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"text/template"
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
	CrowdsecURL           string `json:"crowdsecUrl,omitempty"`
	CrowdsecMode          string `json:"crowdsecMode,omitempty"`
	CrowdsecLapiKey       string `json:"crowdsecLapiKey,omitempty"`
	UpdateIntervalSeconds int    `json:"updateIntervalSeconds,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		Enabled:               false,
		CrowdsecURL:           "http://crowdsec:8080",
		CrowdsecMode:          "none",
		CrowdsecLapiKey:       "",
		UpdateIntervalSeconds: 300,
	}
}

// Demo a Demo plugin.
type Demo struct {
	next     http.Handler
	headers  map[string]string
	name     string
	template *template.Template
}

// New created a new Demo plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.Headers) == 0 {
		return nil, fmt.Errorf("headers cannot be empty")
	}

	return &Demo{
		headers:  config.Headers,
		next:     next,
		name:     name,
		template: template.New("demo").Delims("[[", "]]"),
	}, nil
}

func (a *Demo) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	for key, value := range a.headers {
		tmpl, err := a.template.Parse(value)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		writer := &bytes.Buffer{}

		err = tmpl.Execute(writer, req)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		req.Header.Set(key, writer.String())
	}

	a.next.ServeHTTP(rw, req)
}
