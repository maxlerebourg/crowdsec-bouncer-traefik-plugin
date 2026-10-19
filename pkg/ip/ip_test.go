package ip

import (
	"net/http"
	"net/http/httptest"
	"testing"

	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func Test_GetRemoteIP(t *testing.T) {
	proxies, err := NewChecker(logger.New("INFO", ""), []string{"10.0.0.0/24", "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		remoteAddr string
		header     string
		want       string
	}{
		{name: "Use the peer when the header is missing", remoteAddr: "10.0.0.5:4444", want: "10.0.0.5"},
		{name: "Read the header from a trusted peer", remoteAddr: "10.0.0.5:4444", header: "203.0.113.10", want: "203.0.113.10"},
		{name: "Skip trusted hops in the header", remoteAddr: "10.0.0.5:4444", header: "203.0.113.10, 192.0.2.1, 10.0.0.9", want: "203.0.113.10"},
		{name: "Use the peer when every hop is trusted", remoteAddr: "10.0.0.5:4444", header: "192.0.2.1", want: "10.0.0.5"},
		{name: "Strip the zone from a link-local peer", remoteAddr: "[fe80::1%eth0]:4444", want: "fe80::1"},
		{name: "Strip the zone from a link-local header entry", remoteAddr: "10.0.0.5:4444", header: "fe80::2%eth0", want: "fe80::2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.header != "" {
				req.Header.Set("Cf-Connecting-Ip", tt.header)
			}
			got, err := GetRemoteIP(req, &PoolStrategy{Checker: proxies}, "Cf-Connecting-Ip")
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("GetRemoteIP() = %v, want %v", got, tt.want)
			}
		})
	}
}
