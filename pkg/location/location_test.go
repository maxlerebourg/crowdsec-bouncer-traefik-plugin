package location

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMatcher_Contains(t *testing.T) {
	matcher, err := NewMatcher([]string{" /healthz ", "Registry.Example.com./v2/"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		host   string
		target string
		want   bool
	}{
		{host: "app.example.com", target: "/healthz", want: true},
		{host: "app.example.com", target: "/healthz/live?probe=1", want: true},
		{host: "registry.example.com", target: "/v2/", want: true},
		{host: "registry.example.com", target: "/v2/library/nginx/manifests/sha256:0a1b", want: true},
		{host: "REGISTRY.example.com:8443", target: "/v2/x", want: true},
		{host: "registry.example.com.", target: "/v2/x", want: true},
		{host: "app.example.com", target: "/healthzfoo"},
		{host: "app.example.com", target: "/Healthz"},
		{host: "app.example.com", target: "/admin?next=/healthz"},
		{host: "app.example.com", target: "/v2/x"},
		{host: "registry.example.com", target: "/v2"},
		{host: "registry.example.com.evil.com", target: "/v2/x"},
		{host: "app.example.com", target: "//healthz"},
		{host: "app.example.com", target: "/healthz/../admin"},
		{host: "app.example.com", target: "/healthz/./live"},
		{host: "app.example.com", target: "/healthz/.../admin"},
		{host: "app.example.com", target: "/healthz/%2e%2e/admin"},
		{host: "app.example.com", target: "/healthz%2F..%2Fadmin"},
		{host: "app.example.com", target: "/healthz/%252e%252e/admin"},
		{host: "app.example.com", target: "/healthz/..;/admin"},
		{host: "app.example.com", target: "/healthz/..%3B/admin"},
		{host: "app.example.com", target: "/healthz/..%5Cadmin"},
		{host: "app.example.com", target: "/healthz/%00"},
		{host: "app.example.com", target: "/healthz/%EF%BC%8E%EF%BC%8E%EF%BC%8Fadmin"},
		{host: "app.example.com", target: "/healthz/%6Cive"},
	}
	for _, tt := range tests {
		t.Run(tt.host+tt.target, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.target, nil)
			req.Host = tt.host
			if got := matcher.Contains(req); got != tt.want {
				t.Errorf("Contains() = %v, want %v (path %q, escaped %q)", got, tt.want, req.URL.Path, req.URL.EscapedPath())
			}
		})
	}
}

func TestNewMatcher_rejects(t *testing.T) {
	for _, location := range []string{
		"",
		"/",
		"healthz",
		"registry.example.com",
		"registry.example.com:443/v2/",
		"*.example.com/v2/",
		"https://registry.example.com/v2/",
		"/healthz/../admin",
		"//healthz",
		"/v2/*",
		"/a;b",
		"/a%2Fb",
	} {
		if _, err := NewMatcher([]string{location}); err == nil {
			t.Errorf("NewMatcher(%q) must fail", location)
		}
	}
}
