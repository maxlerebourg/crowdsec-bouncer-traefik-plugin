package captcha

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func makeReq(host, path string, useTLS bool) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
	req.Host = host
	if useTLS {
		req.TLS = &tls.ConnectionState{}
	}
	return req
}

func clientWith(rawURLs ...string) *Client {
	return &Client{captchaResources: parseCaptchaResourceURLs(rawURLs...)}
}

func Test_parseCaptchaResourceURLs(t *testing.T) {
	tests := []struct {
		name      string
		rawURLs   []string
		wantLen   int
		wantFirst *captchaResource // nil when wantLen == 0
	}{
		{
			name:      "valid http URL with non-default port",
			rawURLs:   []string{"http://example.com:8080/fast.js"},
			wantLen:   1,
			wantFirst: &captchaResource{host: "example.com:8080", path: "/fast.js"},
		},
		{
			name:      "default http port 80 is stripped",
			rawURLs:   []string{"http://example.com:80/fast.js"},
			wantLen:   1,
			wantFirst: &captchaResource{host: "example.com", path: "/fast.js"},
		},
		{
			name:      "default https port 443 is stripped",
			rawURLs:   []string{"https://example.com:443/fast.js"},
			wantLen:   1,
			wantFirst: &captchaResource{host: "example.com", path: "/fast.js"},
		},
		{
			name:      "URL with no port",
			rawURLs:   []string{"http://example.com/fast.js"},
			wantLen:   1,
			wantFirst: &captchaResource{host: "example.com", path: "/fast.js"},
		},
		{
			name:    "empty string is skipped",
			rawURLs: []string{""},
			wantLen: 0,
		},
		{
			name:    "multiple valid URLs all parsed",
			rawURLs: []string{"http://example.com/fast.js", "http://example.com/v0/challenge"},
			wantLen: 2,
		},
		{
			name:      "mix of valid and empty: empty is skipped, valid is kept",
			rawURLs:   []string{"http://example.com/fast.js", ""},
			wantLen:   1,
			wantFirst: &captchaResource{host: "example.com", path: "/fast.js"},
		},
		{
			name:    "nil / no arguments",
			rawURLs: []string{},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCaptchaResourceURLs(tt.rawURLs...)
			if len(got) != tt.wantLen {
				t.Fatalf("len = %d, want %d (got %+v)", len(got), tt.wantLen, got)
			}
			if tt.wantFirst != nil {
				if got[0].host != tt.wantFirst.host {
					t.Errorf("host = %q, want %q", got[0].host, tt.wantFirst.host)
				}
				if got[0].path != tt.wantFirst.path {
					t.Errorf("path = %q, want %q", got[0].path, tt.wantFirst.path)
				}
			}
		})
	}
}

func Test_IsCaptchaResource(t *testing.T) {
	tests := []struct {
		name       string
		configURLs []string
		reqHost    string
		reqPath    string
		reqTLS     bool
		want       bool
	}{
		// port normalization
		{
			name:       "config :80, browser omits default http port",
			configURLs: []string{"http://example.com:80/fast.js"},
			reqHost:    "example.com",
			reqPath:    "/fast.js",
			want:       true,
		},
		{
			name:       "config has no port, browser sends :80",
			configURLs: []string{"http://example.com/fast.js"},
			reqHost:    "example.com:80",
			reqPath:    "/fast.js",
			want:       true,
		},
		{
			name:       "config :443, HTTPS browser omits default port",
			configURLs: []string{"https://example.com:443/fast.js"},
			reqHost:    "example.com",
			reqPath:    "/fast.js",
			reqTLS:     true,
			want:       true,
		},
		{
			name:       "config no port, HTTPS browser sends :443",
			configURLs: []string{"https://example.com/fast.js"},
			reqHost:    "example.com:443",
			reqPath:    "/fast.js",
			reqTLS:     true,
			want:       true,
		},
		{
			name:       "non-default port must be present in request",
			configURLs: []string{"http://example.com:8080/fast.js"},
			reqHost:    "example.com", // missing :8080
			reqPath:    "/fast.js",
			want:       false,
		},
		{
			name:       "non-default port matches exactly",
			configURLs: []string{"http://example.com:8080/fast.js"},
			reqHost:    "example.com:8080",
			reqPath:    "/fast.js",
			want:       true,
		},
		// host isolation
		{
			name:       "correct path, wrong host is rejected",
			configURLs: []string{"http://captcha.example.com/fast.js"},
			reqHost:    "other.example.com",
			reqPath:    "/fast.js",
			want:       false,
		},
		{
			name:       "host is case-insensitive",
			configURLs: []string{"http://Example.COM/fast.js"},
			reqHost:    "example.com",
			reqPath:    "/fast.js",
			want:       true,
		},
		// path matching
		{
			name:       "correct host, wrong path",
			configURLs: []string{"http://example.com/fast.js"},
			reqHost:    "example.com",
			reqPath:    "/slow.js",
			want:       false,
		},
		{
			name:       "path prefix does not satisfy exact match",
			configURLs: []string{"http://example.com/fast.js"},
			reqHost:    "example.com",
			reqPath:    "/fast.js/extra",
			want:       false,
		},
		{
			name:       "path suffix does not satisfy exact match",
			configURLs: []string{"http://example.com/v0/challenge"},
			reqHost:    "example.com",
			reqPath:    "/v0",
			want:       false,
		},
		// multiple configured resources
		{
			name:       "matches first of two resources",
			configURLs: []string{"http://example.com/fast.js", "http://example.com/v0/challenge"},
			reqHost:    "example.com",
			reqPath:    "/fast.js",
			want:       true,
		},
		{
			name:       "matches second of two resources",
			configURLs: []string{"http://example.com/fast.js", "http://example.com/v0/challenge"},
			reqHost:    "example.com",
			reqPath:    "/v0/challenge",
			want:       true,
		},
		// edge: nothing configured
		{
			name:       "no resources configured, always false",
			configURLs: []string{},
			reqHost:    "example.com",
			reqPath:    "/fast.js",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := clientWith(tt.configURLs...)
			req := makeReq(tt.reqHost, tt.reqPath, tt.reqTLS)
			if got := c.IsCaptchaResource(req); got != tt.want {
				t.Errorf("IsCaptchaResource() = %v, want %v", got, tt.want)
			}
		})
	}
}
