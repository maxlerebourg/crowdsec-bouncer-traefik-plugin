package location

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMatcher_Contains(t *testing.T) {
	matcher, err := NewMatcher([]string{
		" /path ",
		"only-host.com.",
		"host-port-path.com:8000/v2/",
		"host-port.com:8000",
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		host   string
		target string
		want   bool
	}{
		{host: "only-host.com", target: "/", want: true},
		{host: "evil.only-host.com", target: "/"},
		{host: "only-host.com.evil", target: "/"},
		{host: "host-port-path.com:8000", target: "/v2/x", want: true},
		{host: "HOST-PORT-PATH.com:8000", target: "/v2/x", want: true},
		{host: "host-port-path.com", target: "/v2/x"},
		{host: "host-port-path.com:9000", target: "/v2/x"},
		{host: "host-port-path.com:8000", target: "/v2"},
		{host: "host-port-path.com:8000", target: "/v3/x"},
		{host: "other.com", target: "/"},
		{host: "app.com", target: "/path", want: true},
		{host: "app.com", target: "/path/live?probe=1", want: true},
		{host: "app.com", target: "/pathfoo"},
		{host: "app.com", target: "/Path"},
		{host: "app.com", target: "/admin?next=/path"},
		{host: "app.com", target: "/v2/x"},
		{host: "app.com", target: "//path"},
		{host: "app.com", target: "/path/../admin"},
		{host: "app.com", target: "/path/./live"},
		{host: "app.com", target: "/path/.../admin"},
		{host: "app.com", target: "/path/%2e%2e/admin"},
		{host: "app.com", target: "/path%2F..%2Fadmin"},
		{host: "app.com", target: "/path/%252e%252e/admin"},
		{host: "app.com", target: "/path/..;/admin"},
		{host: "app.com", target: "/path/..%3B/admin"},
		{host: "app.com", target: "/path/..%5Cadmin"},
		{host: "app.com", target: "/path/%00"},
		{host: "app.com", target: "/path/%EF%BC%8E%EF%BC%8E%EF%BC%8Fadmin"},
		{host: "app.com", target: "/path/%6Cive"},
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
	for _, loc := range []string{
		"",
		"/",
		"app.com:0",
		"app.com:",
		"app.com:abc",
		"app.com:99999",
		"app.com//",
		"*.app.com/v2/",
		"https://app.com/v2/",
		"/path/../admin",
		"//path",
		"/v2/*",
		"/a;b",
		"/a%2Fb",
	} {
		if _, err := NewMatcher([]string{loc}); err == nil {
			t.Errorf("NewMatcher(%q) must fail", loc)
		}
	}
}
