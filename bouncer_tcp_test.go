package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	ip "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/ip"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }

func (a fakeAddr) String() string { return string(a) }

type fakeConn struct {
	remote string
	closed bool
}

func (c *fakeConn) Read([]byte) (int, error) { return 0, nil }

func (c *fakeConn) Write(b []byte) (int, error) { return len(b), nil }

func (c *fakeConn) LocalAddr() net.Addr { return fakeAddr("127.0.0.1:80") }

func (c *fakeConn) RemoteAddr() net.Addr { return fakeAddr(c.remote) }

func (c *fakeConn) SetDeadline(time.Time) error { return nil }

func (c *fakeConn) SetReadDeadline(time.Time) error { return nil }

func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

func (c *fakeConn) Close() error {
	c.closed = true
	return nil
}

func TestBouncer_allowConn(t *testing.T) {
	healthy := isCrowdsecStreamHealthy
	t.Cleanup(func() { isCrowdsecStreamHealthy = healthy })

	log := logger.New("ERROR", "")
	cacheClient := &cache.Client{}
	cacheClient.New(log, false, "", nil, "", "")
	cacheClient.Set("192.0.2.1", cache.BannedValue, 60)
	cacheClient.Set("192.0.2.2", cache.CaptchaValue, 60)
	clientChecker, _ := ip.NewChecker(log, []string{"192.0.2.3"})

	tests := []struct {
		name          string
		enabled       bool
		remote        string
		streamHealthy bool
		want          bool
	}{
		{name: "disabled", remote: "192.0.2.1:1234", want: true},
		{name: "no decision", enabled: true, remote: "192.0.2.9:1234", streamHealthy: true, want: true},
		{name: "ban", enabled: true, remote: "192.0.2.1:1234", streamHealthy: true},
		{name: "captcha", enabled: true, remote: "192.0.2.2:1234", streamHealthy: true},
		{name: "trusted client", enabled: true, remote: "192.0.2.3:1234", want: true},
		{name: "stream unreachable", enabled: true, remote: "192.0.2.9:1234"},
		{name: "invalid address", enabled: true, remote: "pipe", streamHealthy: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isCrowdsecStreamHealthy = tt.streamHealthy
			bouncer := &Bouncer{
				enabled:            tt.enabled,
				crowdsecMode:       configuration.StreamMode,
				cacheClient:        cacheClient,
				clientPoolStrategy: &ip.PoolStrategy{Checker: clientChecker},
				log:                log,
			}
			if got := bouncer.allowConn(&fakeConn{remote: tt.remote}); got != tt.want {
				t.Errorf("allowConn() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewTCP(t *testing.T) {
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Query().Get("ip") == "192.0.2.1" {
			_, _ = rw.Write([]byte(`[{"type":"ban","scope":"Ip","value":"192.0.2.1","duration":"1h"}]`))
			return
		}
		_, _ = rw.Write([]byte("null"))
	}))
	defer lapi.Close()

	config := CreateConfig()
	config.Enabled = true
	config.CrowdsecMode = configuration.NoneMode
	config.CrowdsecLapiKey = "test"
	config.CrowdsecLapiScheme = configuration.HTTP
	config.CrowdsecLapiHost = strings.TrimPrefix(lapi.URL, "http://")
	config.MetricsUpdateIntervalSeconds = 0

	var passed []string
	next := func(_ context.Context, conn net.Conn, _ func() error) {
		passed = append(passed, conn.RemoteAddr().String())
	}
	handle, err := NewTCP(context.Background(), next, config, "tcp")
	if err != nil {
		t.Fatal(err)
	}

	allowed := &fakeConn{remote: "192.0.2.9:1234"}
	banned := &fakeConn{remote: "192.0.2.1:1234"}
	handle(context.Background(), allowed, nil)
	handle(context.Background(), banned, nil)

	if len(passed) != 1 || passed[0] != "192.0.2.9:1234" || allowed.closed {
		t.Errorf("allowed connection: passed=%v closed=%v", passed, allowed.closed)
	}
	if !banned.closed {
		t.Error("banned connection was not closed")
	}

	config.CrowdsecMode = configuration.AppsecMode
	if _, err := NewTCP(context.Background(), next, config, "tcp"); err == nil {
		t.Error("NewTCP() accepted crowdsecMode appsec")
	}
}
