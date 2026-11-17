package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	captcha "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	ip "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/ip"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func Test_retryAfterSeconds(t *testing.T) {
	tests := []struct {
		left time.Duration
		want string
	}{
		{left: -5 * time.Second, want: "1"},
		{left: 0, want: "1"},
		{left: time.Nanosecond, want: "1"},
		{left: time.Second, want: "1"},
		{left: time.Second + time.Millisecond, want: "2"},
		{left: time.Hour + 2*time.Minute + 3500*time.Millisecond, want: "3724"},
	}
	for _, tt := range tests {
		if got := retryAfterSeconds(tt.left); got != tt.want {
			t.Errorf("retryAfterSeconds(%v) = %q, want %q", tt.left, got, tt.want)
		}
	}
}

func newLapiBouncer(t *testing.T, mode, body string) (*Bouncer, *int64) {
	t.Helper()
	var queries int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&queries, 1)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	log := logger.New("ERROR", "")
	cacheClient := &cache.Client{}
	cacheClient.New(log, false, "", nil, "", "")
	checker, err := ip.NewChecker(log, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &Bouncer{
		next: http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			rw.WriteHeader(http.StatusOK)
		}),
		enabled:                 true,
		crowdsecMode:            mode,
		crowdsecScheme:          serverURL.Scheme,
		crowdsecHost:            serverURL.Host,
		crowdsecPath:            "/",
		crowdsecHeader:          crowdsecLapiHeader,
		crowdsecStreamRoute:     crowdsecLapiStreamRoute,
		updateInterval:          60,
		defaultDecisionTimeout:  60,
		remediationStatusCode:   http.StatusTooManyRequests,
		remediationCustomHeader: "cs-remediation",
		forwardedCustomHeader:   "X-Forwarded-For",
		serverPoolStrategy:      &ip.PoolStrategy{Checker: checker},
		clientPoolStrategy:      &ip.PoolStrategy{Checker: checker},
		httpClient:              server.Client(),
		cacheClient:             cacheClient,
		captchaClient:           &captcha.Client{},
		log:                     log,
	}, &queries
}

func serveFrom(bouncer *Bouncer, remoteIP string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = remoteIP + ":40000"
	recorder := httptest.NewRecorder()
	bouncer.ServeHTTP(recorder, req)
	return recorder
}

func assertBanned(t *testing.T, recorder *httptest.ResponseRecorder, retryAfter string) {
	t.Helper()
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("expected status 429, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Cs-Remediation"); got != "ban" {
		t.Errorf("expected remediation header ban, got %q", got)
	}
	if got := recorder.Header().Get("Retry-After"); got != retryAfter {
		t.Errorf("expected Retry-After %q, got %q", retryAfter, got)
	}
}

func TestServeHTTPStreamBanRetryAfter(t *testing.T) {
	bouncer, _ := newLapiBouncer(t, configuration.StreamMode, `{
		"deleted": [],
		"new": [
			{"type": "ban", "scope": "Ip", "value": "192.0.2.41", "duration": "1h30m0.5s"},
			{"type": "captcha", "scope": "Ip", "value": "192.0.2.42", "duration": "10m"}
		]
	}`)
	bouncer.cacheClient.Delete(cacheTimeoutKey)
	t.Cleanup(func() { bouncer.cacheClient.Delete(cacheTimeoutKey) })

	if err := handleStreamCache(bouncer); err != nil {
		t.Fatalf("handleStreamCache() error = %v", err)
	}
	assertBanned(t, serveFrom(bouncer, "192.0.2.41"), "5401")
	assertBanned(t, serveFrom(bouncer, "192.0.2.42"), "")

	recorder := serveFrom(bouncer, "192.0.2.43")
	if recorder.Code != http.StatusOK || recorder.Header().Get("Retry-After") != "" {
		t.Errorf("expected an address without a decision through without Retry-After, got %d %q", recorder.Code, recorder.Header().Get("Retry-After"))
	}
}

func TestServeHTTPLiveBanRetryAfter(t *testing.T) {
	bouncer, queries := newLapiBouncer(t, configuration.LiveMode,
		`[{"type": "ban", "scope": "Ip", "value": "192.0.2.44", "duration": "1h2m3.5s"}]`)

	assertBanned(t, serveFrom(bouncer, "192.0.2.44"), "3724")
	assertBanned(t, serveFrom(bouncer, "192.0.2.44"), "3724")
	if got := atomic.LoadInt64(queries); got != 1 {
		t.Errorf("expected the second ban to come from the cache, LAPI was queried %d times", got)
	}
}

func TestServeHTTPNoneBanRetryAfter(t *testing.T) {
	bouncer, queries := newLapiBouncer(t, configuration.NoneMode,
		`[{"type": "ban", "scope": "Ip", "value": "192.0.2.45", "duration": "59.2s"}]`)

	assertBanned(t, serveFrom(bouncer, "192.0.2.45"), "60")
	assertBanned(t, serveFrom(bouncer, "192.0.2.45"), "60")
	if got := atomic.LoadInt64(queries); got != 2 {
		t.Errorf("expected none mode to query LAPI for every request, got %d queries", got)
	}
}

func TestServeHTTPBanRetryAfterOnlyWith429(t *testing.T) {
	bouncer, _ := newLapiBouncer(t, configuration.NoneMode,
		`[{"type": "ban", "scope": "Ip", "value": "192.0.2.46", "duration": "1h"}]`)
	bouncer.remediationStatusCode = http.StatusForbidden

	recorder := serveFrom(bouncer, "192.0.2.46")
	if recorder.Code != http.StatusForbidden || recorder.Header().Get("Retry-After") != "" {
		t.Errorf("expected 403 without Retry-After, got %d %q", recorder.Code, recorder.Header().Get("Retry-After"))
	}
}

func TestServeHTTPBanRetryAfterLatestBlockingDecision(t *testing.T) {
	tests := []struct {
		name string
		mode string
		ip   string
		body string
		want string
	}{
		{
			name: "live mode, shorter ban first",
			mode: configuration.LiveMode,
			ip:   "192.0.2.47",
			body: `[{"type": "ban", "scope": "Ip", "value": "192.0.2.47", "duration": "4h"},
				{"type": "ban", "scope": "Range", "value": "192.0.2.0/24", "duration": "168h"}]`,
			want: "604800",
		},
		{
			name: "none mode, captcha without a provider outlasting the ban",
			mode: configuration.NoneMode,
			ip:   "192.0.2.48",
			body: `[{"type": "captcha", "scope": "Ip", "value": "192.0.2.48", "duration": "168h"},
				{"type": "ban", "scope": "Ip", "value": "192.0.2.48", "duration": "1h"}]`,
			want: "604800",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bouncer, _ := newLapiBouncer(t, tt.mode, tt.body)
			assertBanned(t, serveFrom(bouncer, tt.ip), tt.want)
		})
	}
}

func Test_blockingDecisionsEnd(t *testing.T) {
	decisions := []Decision{
		{Type: "ban", Duration: "1h"},
		{Type: "captcha", Duration: "3h"},
		{Type: "ban", Duration: "not a duration"},
	}
	tests := []struct {
		name         string
		captchaValid bool
		want         time.Duration
	}{
		{name: "captcha served as a ban", captchaValid: false, want: 3 * time.Hour},
		{name: "captcha served as a captcha", captchaValid: true, want: time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			left := time.Until(blockingDecisionsEnd(decisions, tt.captchaValid))
			if left <= tt.want-time.Minute || left > tt.want {
				t.Errorf("blockingDecisionsEnd() is %v away, want %v", left, tt.want)
			}
		})
	}
	if end := blockingDecisionsEnd([]Decision{{Type: "captcha", Duration: "1h"}}, true); !end.IsZero() {
		t.Errorf("blockingDecisionsEnd() of a served captcha = %v, want zero", end)
	}
}
