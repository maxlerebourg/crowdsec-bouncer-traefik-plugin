package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
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

// TestHandleStreamCacheWhitelistIsNotABan: a decision of type whitelist is an
// allow, not an unknown remediation. It must not be cached as a ban, and its
// deletion must not clear a ban another decision holds on the same IP.
func TestHandleStreamCacheWhitelistIsNotABan(t *testing.T) {
	var q atomic.Value
	bouncer := newRangeStreamBouncer(t, true, `{
		"deleted": [{"type": "whitelist", "scope": "Ip", "value": "192.0.2.20", "duration": "-1s"}],
		"new": [
			{"type": "whitelist", "scope": "Ip", "value": "192.0.2.30", "duration": "6h"},
			{"type": "whitelist", "scope": "Range", "value": "198.51.100.0/24", "duration": "6h"},
			{"type": "challenge", "scope": "Ip", "value": "192.0.2.40", "duration": "1h"}
		]
	}`, &q)
	bouncer.cacheClient.Set("192.0.2.20", cache.BannedValue, 3600)
	isCrowdsecStreamStartup = false
	t.Cleanup(func() { isCrowdsecStreamStartup = true })

	if err := handleStreamCache(bouncer); err != nil {
		t.Fatalf("handleStreamCache: %v", err)
	}
	if got, err := bouncer.cacheClient.Get("192.0.2.30"); err == nil {
		t.Fatalf("whitelist cached as %q", got)
	}
	if _, ok := rangeDecisions.Get("198.51.100.7"); ok {
		t.Fatal("whitelist range stored as a remediation")
	}
	if got, err := bouncer.cacheClient.Get("192.0.2.20"); err != nil || got != cache.BannedValue {
		t.Fatalf("whitelist deletion cleared the ban: %q %v", got, err)
	}
	// Other unknown types still fail closed (upstream #403).
	if got, err := bouncer.cacheClient.Get("192.0.2.40"); err != nil || got != cache.BannedValue {
		t.Fatalf("unknown type not banned: %q %v", got, err)
	}
}

// TestHandleNoStreamCacheWhitelist: in live mode an IP whose only decisions
// are whitelists is not banned; a ban next to a whitelist still bans.
func TestHandleNoStreamCacheWhitelist(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"whitelist only", `[{"type": "whitelist", "scope": "Ip", "value": "192.0.2.50", "duration": "6h"}]`, cache.NoBannedValue},
		{"whitelist and ban", `[{"type": "whitelist", "scope": "Ip", "value": "192.0.2.50", "duration": "6h"},
			{"type": "ban", "scope": "Ip", "value": "192.0.2.50", "duration": "1h"}]`, cache.BannedValue},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(c.body))
			}))
			defer server.Close()
			serverURL, _ := url.Parse(server.URL)
			log := logger.New("ERROR", "")
			cacheClient := &cache.Client{}
			cacheClient.New(log, false, "", nil, "", "")
			cacheClient.Delete("192.0.2.50")
			bouncer := &Bouncer{
				crowdsecScheme:         serverURL.Scheme,
				crowdsecHost:           serverURL.Host,
				crowdsecHeader:         "X-Api-Key",
				crowdsecMode:           configuration.LiveMode,
				defaultDecisionTimeout: 60,
				httpClient:             &http.Client{Timeout: time.Second},
				cacheClient:            cacheClient,
				log:                    log,
			}
			got, _ := handleNoStreamCache(bouncer, "192.0.2.50")
			if got != c.want {
				t.Fatalf("value = %q, want %q", got, c.want)
			}
		})
	}
}

// TestStreamWhitelistOverridesRange: a verified crawler whose IP sits in a
// banned range is allowed by its own Ip-scope whitelist decision, while an
// Ip ban next to a whitelist still bans and other range members stay blocked.
// A whitelist deletion is ignored: the entry lapses at its own expiry.
func TestStreamWhitelistOverridesRange(t *testing.T) {
	var q atomic.Value
	bouncer := newRangeStreamBouncer(t, true, `{
		"deleted": [{"type": "whitelist", "scope": "Ip", "value": "203.0.113.11", "duration": "-1s"}],
		"new": [
			{"type": "ban", "scope": "Range", "value": "203.0.113.0/24", "duration": "1h"},
			{"type": "whitelist", "scope": "Ip", "value": "203.0.113.9", "duration": "6h"},
			{"type": "whitelist", "scope": "Ip", "value": "203.0.113.11", "duration": "6h"},
			{"type": "whitelist", "scope": "Ip", "value": "203.0.113.10", "duration": "6h"},
			{"type": "ban", "scope": "Ip", "value": "203.0.113.10", "duration": "1h"}
		]
	}`, &q)
	for _, k := range []string{"203.0.113.9", "203.0.113.10", "203.0.113.11", "203.0.113.12"} {
		bouncer.cacheClient.Delete(k)
	}
	t.Cleanup(func() {
		for _, k := range []string{"203.0.113.9", "203.0.113.10", "203.0.113.11", "203.0.113.12"} {
			bouncer.cacheClient.Delete(k)
		}
	})
	isCrowdsecStreamStartup = false
	t.Cleanup(func() { isCrowdsecStreamStartup = true })
	if err := handleStreamCache(bouncer); err != nil {
		t.Fatalf("handleStreamCache: %v", err)
	}

	checker, err := ip.NewChecker(bouncer.log, []string{})
	if err != nil {
		t.Fatal(err)
	}
	bouncer.next = http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
	bouncer.enabled = true
	bouncer.serverPoolStrategy = &ip.PoolStrategy{Checker: checker}
	bouncer.clientPoolStrategy = &ip.PoolStrategy{Checker: checker}
	bouncer.captchaClient = &captcha.Client{}
	bouncer.remediationStatusCode = http.StatusForbidden
	bouncer.banTemplateContentType = "text/html"

	for _, c := range []struct {
		remote string
		want   int
	}{
		{"203.0.113.9:4000", http.StatusOK},         // whitelisted inside the range
		{"203.0.113.11:4000", http.StatusOK},        // deletion ignored until expiry
		{"203.0.113.10:4000", http.StatusForbidden}, // its own Ip ban still bans
		{"203.0.113.12:4000", http.StatusForbidden}, // rest of the range blocked
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
		req.RemoteAddr = c.remote
		bouncer.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s: status %d, want %d", c.remote, rec.Code, c.want)
		}
	}
}

// TestStreamWhitelistStartupResync: a startup pull is the full list, so a
// whitelist that is gone from it no longer overrides a range.
func TestStreamWhitelistStartupResync(t *testing.T) {
	var q atomic.Value
	bouncer := newRangeStreamBouncer(t, true, `{"deleted": [], "new": [
		{"type": "ban", "scope": "Range", "value": "203.0.113.0/24", "duration": "1h"}]}`, &q)
	allowDecisions.Add("203.0.113.9", time.Hour)
	isCrowdsecStreamStartup = true
	if err := handleStreamCache(bouncer); err != nil {
		t.Fatalf("handleStreamCache: %v", err)
	}
	if allowDecisions.Has("203.0.113.9") {
		t.Fatal("stale whitelist survived the startup resync")
	}
}
