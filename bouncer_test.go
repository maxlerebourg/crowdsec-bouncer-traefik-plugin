package crowdsec_bouncer_traefik_plugin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	crowdsec_bouncer_traefik_plugin "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin"
)

// this does not test anything yet
func TestCrowdSec(t *testing.T) {
	cfg := crowdsec_bouncer_traefik_plugin.CreateConfig()
	cfg.CrowdsecLapiKey = "test"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := crowdsec_bouncer_traefik_plugin.New(ctx, next, cfg, "demo-plugin")
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
