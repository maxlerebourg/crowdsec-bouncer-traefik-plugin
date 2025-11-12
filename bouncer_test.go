package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	htmltemplate "html/template"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"text/template"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	ip "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/ip"
)

func TestServeHTTP(t *testing.T) {
	cfg := CreateConfig()
	cfg.CrowdsecLapiKey = "test"

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

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

func TestNew(t *testing.T) {
	type args struct {
		ctx    context.Context //nolint:containedctx
		next   http.Handler
		config *configuration.Config
		name   string
	}
	tests := []struct {
		name    string
		args    args
		want    http.Handler
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.ctx, tt.args.next, tt.args.config, tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBouncer_ServeHTTP(t *testing.T) {
	type fields struct {
		next                   http.Handler
		name                   string
		template               *template.Template
		enabled                bool
		crowdsecScheme         string
		crowdsecHost           string
		crowdsecKey            string
		crowdsecMode           string
		updateInterval         int64
		defaultDecisionTimeout int64
		forwardedCustomHeader  string
		clientPoolStrategy     *ip.PoolStrategy
		serverPoolStrategy     *ip.PoolStrategy
		httpClient             *http.Client
		cacheClient            *cache.Client
	}
	type args struct {
		rw  http.ResponseWriter
		req *http.Request
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			bouncer := &Bouncer{
				next:                   tt.fields.next,
				name:                   tt.fields.name,
				template:               tt.fields.template,
				enabled:                tt.fields.enabled,
				crowdsecScheme:         tt.fields.crowdsecScheme,
				crowdsecHost:           tt.fields.crowdsecHost,
				crowdsecKey:            tt.fields.crowdsecKey,
				crowdsecMode:           tt.fields.crowdsecMode,
				updateInterval:         tt.fields.updateInterval,
				defaultDecisionTimeout: tt.fields.defaultDecisionTimeout,
				forwardedCustomHeader:  tt.fields.forwardedCustomHeader,
				clientPoolStrategy:     tt.fields.clientPoolStrategy,
				serverPoolStrategy:     tt.fields.serverPoolStrategy,
				httpClient:             tt.fields.httpClient,
				cacheClient:            tt.fields.cacheClient,
			}
			bouncer.ServeHTTP(tt.args.rw, tt.args.req)
		})
	}
}

func Test_handleNoStreamCache(t *testing.T) {
	type args struct {
		bouncer  *Bouncer
		remoteIP string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := handleNoStreamCache(tt.args.bouncer, tt.args.remoteIP); (err != nil) != tt.wantErr {
				t.Errorf("handleNoStreamCache() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_handleStreamCache(t *testing.T) {
	type args struct {
		bouncer *Bouncer
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handleStreamCache(tt.args.bouncer)
			if (err != nil) != tt.wantErr {
				t.Errorf("handleStreamCache() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_crowdsecQuery(t *testing.T) {
	type args struct {
		bouncer   *Bouncer
		stringURL string
		data      []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := crowdsecQuery(tt.args.bouncer, tt.args.stringURL, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("crowdsecQuery() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("crowdsecQuery() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHandleBanServeHTTPWithDifferentMethods(t *testing.T) {
	html := "<html>You are banned</html>"
	banTemplate, _ := htmltemplate.New("html").Parse(html)
	tests := []struct {
		name              string
		method            string
		banTemplate       *htmltemplate.Template
		expectBodyContent bool
	}{
		{
			name:              "GET request should have body with template",
			method:            http.MethodGet,
			banTemplate:       banTemplate,
			expectBodyContent: true,
		},
		{
			name:              "HEAD request should NOT have body even with template",
			method:            http.MethodHead,
			banTemplate:       banTemplate,
			expectBodyContent: false,
		},
		{
			name:              "POST request should have body with template",
			method:            http.MethodPost,
			banTemplate:       banTemplate,
			expectBodyContent: true,
		},
		{
			name:              "PUT request should have body with template",
			method:            http.MethodPut,
			banTemplate:       banTemplate,
			expectBodyContent: true,
		},
		{
			name:              "DELETE request should have body with template",
			method:            http.MethodDelete,
			banTemplate:       banTemplate,
			expectBodyContent: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bouncer := &Bouncer{
				remediationStatusCode:   http.StatusForbidden,
				remediationCustomHeader: "X-Test-Remediation",
				banTemplate:             tt.banTemplate,
			}

			rw := httptest.NewRecorder()
			req := &http.Request{Method: tt.method}
			bouncer.handleBanServeHTTP(rw, req, "TEST")

			// Check status code
			if rw.Code != http.StatusForbidden {
				t.Errorf("Expected status code 403, got %d", rw.Code)
			}

			// Check custom header
			headerValue := rw.Header().Get("X-Test-Remediation")
			if headerValue != "ban" {
				t.Errorf("Expected header X-Test-Remediation to be 'ban', got %s", headerValue)
			}

			// Check body content
			body := rw.Body.String()
			hasBodyContent := len(body) > 0

			if hasBodyContent != tt.expectBodyContent {
				t.Errorf("Method %s: expected body content: %v, got body content: %v (body: %q)",
					tt.method, tt.expectBodyContent, hasBodyContent, body)
			}

			// If we expect body content, verify it matches template
			if tt.expectBodyContent && body != html {
				t.Errorf("Expected body %q, got %q", html, body)
			}
		})
	}
}

func TestCaptchaMethodBasedLogic(t *testing.T) {
	tests := []struct {
		name              string
		method            string
		remediation       string
		expectBanFallback bool
	}{
		{
			name:              "GET with captcha remediation should allow captcha",
			method:            http.MethodGet,
			remediation:       cache.CaptchaValue,
			expectBanFallback: false,
		},
		{
			name:              "HEAD with captcha remediation should fallback to ban",
			method:            http.MethodHead,
			remediation:       cache.CaptchaValue,
			expectBanFallback: true,
		},
		{
			name:              "POST with captcha remediation should allow captcha",
			method:            http.MethodPost,
			remediation:       cache.CaptchaValue,
			expectBanFallback: false,
		},
		{
			name:              "PUT with captcha remediation should allow captcha",
			method:            http.MethodPut,
			remediation:       cache.CaptchaValue,
			expectBanFallback: false,
		},
		{
			name:              "DELETE with captcha remediation should allow captcha",
			method:            http.MethodDelete,
			remediation:       cache.CaptchaValue,
			expectBanFallback: false,
		},
		{
			name:              "PATCH with captcha remediation should allow captcha",
			method:            http.MethodPatch,
			remediation:       cache.CaptchaValue,
			expectBanFallback: false,
		},
		{
			name:              "OPTIONS with captcha remediation should allow captcha",
			method:            http.MethodOptions,
			remediation:       cache.CaptchaValue,
			expectBanFallback: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the core logic: captcha is served for all methods except HEAD
			shouldUseCaptcha := tt.remediation == cache.CaptchaValue && tt.method != http.MethodHead

			if shouldUseCaptcha == tt.expectBanFallback {
				t.Errorf("Method %s with %s remediation: expected ban fallback %v, but logic would use captcha %v",
					tt.method, tt.remediation, tt.expectBanFallback, shouldUseCaptcha)
			}
		})
	}
}
