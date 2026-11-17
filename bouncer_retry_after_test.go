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

// newLapiBouncer is a bouncer in mode that answers bans with 429, whose LAPI
// answers every query with body and counts them.
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
	if got := recorder.Header().Get("cs-remediation"); got != "ban" {
		t.Errorf("expected remediation header ban, got %q", got)
	}
	if got := recorder.Header().Get("Retry-After"); got != retryAfter {
		t.Errorf("expected Retry-After %q, got %q", retryAfter, got)
	}
}

// In stream mode the decision's end is cached with it, so every ban answers
// the seconds left on the decision, not on the cache entry.
func TestServeHTTPStreamBanRetryAfter(t *testing.T) {
	bouncer, _ := newLapiBouncer(t, configuration.StreamMode, `{
		"deleted": [],
		"new": [
			{"type": "ban", "scope": "Ip", "value": "192.0.2.41", "duration": "1h30m0.5s"},
			{"type": "captcha", "scope": "Ip", "value": "192.0.2.42", "duration": "10m"}
		]
	}`)
	// The stream lease is shared by every bouncer through the global cache.
	bouncer.cacheClient.Delete(cacheTimeoutKey)
	t.Cleanup(func() { bouncer.cacheClient.Delete(cacheTimeoutKey) })

	if err := handleStreamCache(bouncer); err != nil {
		t.Fatalf("handleStreamCache() error = %v", err)
	}
	assertBanned(t, serveFrom(bouncer, "192.0.2.41"), "5401")
	// Without a captcha provider a captcha decision is a ban, for as long.
	assertBanned(t, serveFrom(bouncer, "192.0.2.42"), "600")

	recorder := serveFrom(bouncer, "192.0.2.43")
	if recorder.Code != http.StatusOK || recorder.Header().Get("Retry-After") != "" {
		t.Errorf("expected an address without a decision through without Retry-After, got %d %q", recorder.Code, recorder.Header().Get("Retry-After"))
	}
}

// In live mode a ban is cached for at most defaultDecisionSeconds, which must
// not shorten the Retry-After of the decision it stands for.
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

// AppSec gives no time with a 429, so it is the one configured.
func TestHandleNextServeHTTPAppsecRetryAfter(t *testing.T) {
	tests := []struct {
		name     string
		envelope string
		seconds  int64
		want     string
	}{
		{name: "rate limit", envelope: `{"action":"ban","http_status":429}`, seconds: 6, want: "6"},
		{name: "rate limit without a configured time", envelope: `{"action":"ban","http_status":429}`, seconds: 0, want: ""},
		{name: "ban that is not a 429", envelope: `{"action":"ban","http_status":403}`, seconds: 6, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			appsecServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, tt.envelope)
			}))
			defer appsecServer.Close()
			appsecURL, err := url.Parse(appsecServer.URL)
			if err != nil {
				t.Fatal(err)
			}
			bouncer := &Bouncer{
				next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					t.Error("next handler should not be called for an appsec ban")
				}),
				appsecEnabled:           true,
				appsecScheme:            appsecURL.Scheme,
				appsecHost:              appsecURL.Host,
				appsecPath:              "/",
				appsecRetryAfterSeconds: tt.seconds,
				httpAppsecClient:        appsecServer.Client(),
				remediationStatusCode:   http.StatusForbidden,
				log:                     logger.New("ERROR", ""),
			}
			recorder := httptest.NewRecorder()
			bouncer.handleNextServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "http://example.com/auth/login", nil), "192.0.2.46")
			if got := recorder.Header().Get("Retry-After"); got != tt.want {
				t.Errorf("expected Retry-After %q, got %q", tt.want, got)
			}
		})
	}
}
