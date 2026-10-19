package ip

import (
	"net/http"
	"net/http/httptest"
	"testing"

	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func Test_GetRemoteIP(t *testing.T) {
	log := logger.New("INFO", "")
	proxies, err := NewChecker(log, []string{"10.0.0.0/24", "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	nobody, err := NewChecker(log, []string{})
	if err != nil {
		t.Fatal(err)
	}
	linkLocal, err := NewChecker(log, []string{"fe80::/10"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		checker    *Checker
		remoteAddr string
		header     string
		want       string
		wantErr    bool
	}{
		{name: "Ignore the header from an untrusted peer", checker: proxies, remoteAddr: "198.51.100.7:4444", header: "203.0.113.10", want: "198.51.100.7"},
		{name: "Ignore a header list from an untrusted peer", checker: proxies, remoteAddr: "198.51.100.7:4444", header: "203.0.113.10, 10.0.0.9", want: "198.51.100.7"},
		{name: "Read the header from a trusted peer", checker: proxies, remoteAddr: "10.0.0.5:4444", header: "203.0.113.10", want: "203.0.113.10"},
		{name: "Read the header from a trusted single IP peer", checker: proxies, remoteAddr: "192.0.2.1:4444", header: "203.0.113.10", want: "203.0.113.10"},
		{name: "Skip trusted hops in the header", checker: proxies, remoteAddr: "10.0.0.5:4444", header: "203.0.113.10, 192.0.2.1, 10.0.0.9", want: "203.0.113.10"},
		{name: "Use the peer when every hop is trusted", checker: proxies, remoteAddr: "10.0.0.5:4444", header: "192.0.2.1", want: "10.0.0.5"},
		{name: "Use the peer when the header is missing", checker: proxies, remoteAddr: "10.0.0.5:4444", want: "10.0.0.5"},
		{name: "Ignore the header from an untrusted IPv6 peer", checker: proxies, remoteAddr: "[2001:db8::1]:4444", header: "203.0.113.10", want: "2001:db8::1"},
		{name: "Read the header from any peer without trusted IPs", checker: nobody, remoteAddr: "198.51.100.7:4444", header: "203.0.113.10", want: "203.0.113.10"},
		{name: "Use the peer without trusted IPs and header", checker: nobody, remoteAddr: "198.51.100.7:4444", want: "198.51.100.7"},
		{name: "Ignore the header without checker", checker: nil, remoteAddr: "198.51.100.7:4444", header: "203.0.113.10", want: "198.51.100.7"},
		{name: "Fail on a remote address without port", checker: proxies, remoteAddr: "10.0.0.5", header: "203.0.113.10", wantErr: true},
		{name: "Strip the zone from a link-local peer", checker: proxies, remoteAddr: "[fe80::1%eth0]:4444", want: "fe80::1"},
		{name: "Strip the zone from a link-local header entry", checker: proxies, remoteAddr: "10.0.0.5:4444", header: "fe80::2%eth0", want: "fe80::2"},
		{name: "Read the header from a trusted link-local peer", checker: linkLocal, remoteAddr: "[fe80::1%eth0]:4444", header: "203.0.113.10", want: "203.0.113.10"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.header != "" {
				req.Header.Set("Cf-Connecting-Ip", tt.header)
			}
			got, err := GetRemoteIP(req, &PoolStrategy{Checker: tt.checker}, "Cf-Connecting-Ip")
			if (err != nil) != tt.wantErr {
				t.Fatalf("GetRemoteIP() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("GetRemoteIP() = %v, want %v", got, tt.want)
			}
		})
	}
}
