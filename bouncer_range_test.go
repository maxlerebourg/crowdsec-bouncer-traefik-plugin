package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	captcha "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	ip "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/ip"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

const rangeStreamBody = `{
	"deleted": [{"type": "ban", "scope": "Range", "value": "198.51.100.0/24", "duration": "-1s"}],
	"new": [
		{"type": "ban", "scope": "Range", "value": "203.0.113.0/24", "duration": "1h"},
		{"type": "ban", "scope": "Ip", "value": "192.0.2.10", "duration": "1h"}
	]
}`

// newRangeStreamBouncer returns a stream-mode bouncer against a mock LAPI
// that serves body and records the query string of each stream request.
func newRangeStreamBouncer(t *testing.T, ranges bool, body string, gotQuery *atomic.Value) *Bouncer {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery.Store(r.URL.RawQuery)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	serverURL, _ := url.Parse(server.URL)
	log := logger.New("ERROR", "")
	cacheClient := &cache.Client{}
	cacheClient.New(log, false, "", nil, "", "")
	// The local cache is process-wide and test order is not fixed (yaegi
	// randomizes it): drop the stream lease and every key these tests use.
	keys := []string{
		cacheTimeoutKey, "192.0.2.10", "192.0.2.20", "192.0.2.30", "192.0.2.40",
		"203.0.113.0/24", "198.51.100.0/24",
	}
	clearKeys := func() {
		for _, key := range keys {
			cacheClient.Delete(key)
		}
	}
	clearKeys()
	t.Cleanup(clearKeys)
	rangeDecisions.Replace(ip.NewRangeSet())
	allowDecisions.Replace(ip.NewAllowSet())
	t.Cleanup(func() {
		rangeDecisions.Replace(ip.NewRangeSet())
		allowDecisions.Replace(ip.NewAllowSet())
	})
	return &Bouncer{
		crowdsecScheme:      serverURL.Scheme,
		crowdsecHost:        serverURL.Host,
		crowdsecHeader:      "X-Api-Key",
		crowdsecStreamRoute: "/v1/decisions/stream",
		crowdsecMode:        configuration.StreamMode,
		updateInterval:      60,
		httpClient:          server.Client(),
		cacheClient:         cacheClient,
		log:                 log,
		streamRanges:        ranges,
	}
}

func TestHandleStreamCacheRanges(t *testing.T) {
	var q atomic.Value
	bouncer := newRangeStreamBouncer(t, true, rangeStreamBody, &q)
	_ = rangeDecisions.Add("198.51.100.0/24", cache.BannedValue, time.Hour)
	isCrowdsecStreamStartup = false
	t.Cleanup(func() { isCrowdsecStreamStartup = true })

	if err := handleStreamCache(bouncer); err != nil {
		t.Fatalf("handleStreamCache: %v", err)
	}
	if got, _ := q.Load().(string); !strings.Contains(got, "scopes=ip%2Crange") && !strings.Contains(got, "scopes=ip,range") {
		t.Fatalf("stream query = %q, want scopes=ip,range", got)
	}
	if v, ok := rangeDecisions.Get("203.0.113.9"); !ok || v != cache.BannedValue {
		t.Fatalf("new range not stored: %q %v", v, ok)
	}
	if _, ok := rangeDecisions.Get("198.51.100.9"); ok {
		t.Fatal("deleted range still matches")
	}
	if got, err := bouncer.cacheClient.Get("192.0.2.10"); err != nil || got != cache.BannedValue {
		t.Fatalf("ip decision not cached: %q %v", got, err)
	}
	if _, err := bouncer.cacheClient.Get("203.0.113.0/24"); err == nil {
		t.Fatal("range decision leaked into the IP cache")
	}
}

// TestHandleStreamCacheRangesOff: without the option the stream query and
// the cache behave as before (no scopes parameter, no range set).
func TestHandleStreamCacheRangesOff(t *testing.T) {
	var q atomic.Value
	bouncer := newRangeStreamBouncer(t, false, rangeStreamBody, &q)
	if err := handleStreamCache(bouncer); err != nil {
		t.Fatalf("handleStreamCache: %v", err)
	}
	if got, _ := q.Load().(string); strings.Contains(got, "scopes") {
		t.Fatalf("stream query = %q, want no scopes", got)
	}
	if rangeDecisions.Len() != 0 {
		t.Fatalf("range set has %d entries with ranges disabled", rangeDecisions.Len())
	}
}

// TestHandleStreamCacheRangesStartupResync: a startup pull is a full list,
// so ranges deleted while the stream was down must not survive it.
func TestHandleStreamCacheRangesStartupResync(t *testing.T) {
	var q atomic.Value
	bouncer := newRangeStreamBouncer(t, true, `{"deleted": [], "new": [
		{"type": "ban", "scope": "Range", "value": "203.0.113.0/24", "duration": "1h"}]}`, &q)
	_ = rangeDecisions.Add("192.0.2.0/24", cache.BannedValue, time.Hour)
	isCrowdsecStreamStartup = true

	if err := handleStreamCache(bouncer); err != nil {
		t.Fatalf("handleStreamCache: %v", err)
	}
	if got, _ := q.Load().(string); !strings.Contains(got, "startup=true") {
		t.Fatalf("stream query = %q, want startup=true", got)
	}
	if _, ok := rangeDecisions.Get("192.0.2.1"); ok {
		t.Fatal("stale range survived the startup resync")
	}
	if _, ok := rangeDecisions.Get("203.0.113.1"); !ok {
		t.Fatal("range from the startup pull missing")
	}
}

// TestServeHTTPBlocksRangeDecision: a client inside a banned range is
// blocked even though its own IP has no decision; others pass.
func TestServeHTTPBlocksRangeDecision(t *testing.T) {
	log := logger.New("ERROR", "")
	cacheClient := &cache.Client{}
	cacheClient.New(log, false, "", nil, "", "")
	rangeDecisions.Replace(ip.NewRangeSet())
	t.Cleanup(func() { rangeDecisions.Replace(ip.NewRangeSet()) })
	_ = rangeDecisions.Add("203.0.113.0/24", cache.BannedValue, time.Hour)

	checker, err := ip.NewChecker(log, []string{})
	if err != nil {
		t.Fatal(err)
	}
	var passed int
	bouncer := &Bouncer{
		next:                   http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { passed++ }),
		enabled:                true,
		crowdsecMode:           configuration.StreamMode,
		cacheClient:            cacheClient,
		log:                    log,
		streamRanges:           true,
		serverPoolStrategy:     &ip.PoolStrategy{Checker: checker},
		clientPoolStrategy:     &ip.PoolStrategy{Checker: checker},
		captchaClient:          &captcha.Client{},
		remediationStatusCode:  http.StatusForbidden,
		banTemplateContentType: "text/html",
	}

	for _, c := range []struct {
		remote string
		want   int
	}{
		{"203.0.113.77:4000", http.StatusForbidden},
		{"198.51.100.1:4000", http.StatusOK},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
		req.RemoteAddr = c.remote
		bouncer.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s: status %d, want %d", c.remote, rec.Code, c.want)
		}
	}
	if passed != 1 {
		t.Fatalf("next called %d times, want 1", passed)
	}
}

func TestValidateStreamRanges(t *testing.T) {
	log := logger.New("ERROR", "")
	cfg := configuration.New()
	cfg.CrowdsecLapiKey = "test"
	cfg.CrowdsecMode = configuration.StreamMode
	cfg.CrowdsecStreamRanges = true
	if err := configuration.ValidateParams(cfg, log); err != nil {
		t.Fatalf("stream + ranges: %v", err)
	}
	cfg.CrowdsecMode = configuration.LiveMode
	if err := configuration.ValidateParams(cfg, log); err == nil {
		t.Fatal("want an error: ranges outside stream mode")
	}
	cfg.CrowdsecMode = configuration.StreamMode
	cfg.RedisCacheEnabled = true
	cfg.RedisCacheHost = "redis:6379"
	if err := configuration.ValidateParams(cfg, log); err == nil {
		t.Fatal("want an error: ranges with the redis cache")
	}
}
