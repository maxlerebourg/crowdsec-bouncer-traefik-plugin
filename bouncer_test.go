package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreation(t *testing.T) {
	cfg := CreateConfig()
	cfg.CrowdsecLapiKey = "test"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := New(ctx, next, cfg, "demo-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)
}

func TestValidateParamsCrowdsecLapiKey(t *testing.T) {
	cfg := CreateConfig()
	err := validateParams(cfg)
	fmt.Println(err.Error())
	if err == nil {
		t.Errorf("Need error here %s", err.Error())
	}
}

func TestValidateParamsCrowdsecLapiScheme(t *testing.T) {
	cfg := CreateConfig()
	cfg.CrowdsecLapiKey = "test"
	cfg.CrowdsecLapiScheme = "bad"
	err := validateParams(cfg)
	fmt.Println(err.Error())
	if err == nil {
		t.Errorf("Need error here %s", err.Error())
	}
}

func TestValidateParamsCrowdsecMode(t *testing.T) {
	cfg := CreateConfig()
	cfg.CrowdsecLapiKey = "test"
	cfg.CrowdsecMode = "bad"
	err := validateParams(cfg)
	fmt.Println(err.Error())
	if err == nil {
		t.Errorf("Need error here %s", err.Error())
	}
}

func TestValidateParamsUpdateIntervalSeconds(t *testing.T) {
	cfg := CreateConfig()
	cfg.CrowdsecLapiKey = "test"
	cfg.UpdateIntervalSeconds = 0
	err := validateParams(cfg)
	fmt.Println(err.Error())
	if err == nil {
		t.Errorf("Need error here %s", err.Error())
	}
}

func TestServeHTTP(t *testing.T) {
	cfg := CreateConfig()
	cfg.CrowdsecLapiKey = "test"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := New(ctx, next, cfg, "demo-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)
}
