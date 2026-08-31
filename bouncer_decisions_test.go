package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	captcha "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	ip "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/ip"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func newTestMatchBouncer(t *testing.T) *Bouncer {
	t.Helper()
	cache.ResetLocalForTest()
	log := logger.New("ERROR", "")
	checker, err := ip.NewChecker(log, []string{})
	if err != nil {
		t.Fatal(err)
	}
	cacheClient := &cache.Client{}
	cacheClient.New(log, false, "", nil, "", "")
	return &Bouncer{
		next: http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			rw.WriteHeader(http.StatusOK)
		}),
		enabled:               true,
		crowdsecMode:          configuration.StreamMode,
		forwardedCustomHeader: "X-Forwarded-For",
		decisionScopeHeaders: map[string]string{
			scopeCountry: "CF-IPCountry",
			scopeAS:      "CF-ASN",
		},
		remediationStatusCode: http.StatusForbidden,
		serverPoolStrategy:    &ip.PoolStrategy{Checker: checker},
		clientPoolStrategy:    &ip.PoolStrategy{Checker: checker},
		cacheClient:           cacheClient,
		captchaClient:         &captcha.Client{},
		log:                   log,
	}
}

func TestStreamScopeList(t *testing.T) {
	bouncer := &Bouncer{}
	if got := streamScopeList(bouncer); got != "ip,range" {
		t.Fatalf("default scopes %q", got)
	}
	bouncer.decisionScopeHeaders = map[string]string{
		scopeCountry: "CF-IPCountry",
		scopeAS:      "CF-ASN",
		"username":   "X-User",
	}
	if got := streamScopeList(bouncer); got != "ip,range,AS,country,username" {
		t.Fatalf("configured scopes %q", got)
	}
}

func TestStreamQueryLAPIIncludesScopes(t *testing.T) {
	bouncer := &Bouncer{
		crowdsecStreamRoute:  crowdsecLapiStreamRoute,
		decisionScopeHeaders: map[string]string{scopeCountry: "CF-IPCountry"},
	}
	query := streamQuery(bouncer)
	if query != "startup=true&scopes=ip,range,country" && query != "startup=false&scopes=ip,range,country" {
		t.Fatalf("LAPI query %q", query)
	}
}

func TestStreamQueryCAPIOmitsScopes(t *testing.T) {
	bouncer := &Bouncer{crowdsecStreamRoute: crowdsecCapiStreamRoute}
	query := streamQuery(bouncer)
	if query != "startup=true" && query != "startup=false" {
		t.Fatalf("CAPI query %q", query)
	}
}

func TestServeHTTPRangeDecision(t *testing.T) {
	isCrowdsecStreamHealthy = true
	bouncer := newTestMatchBouncer(t)
	addRange(bouncer.cacheClient, "10.0.0.0/8", cache.BannedValue, 60)
	req := httptest.NewRequest(http.MethodGet, "http://app.localhost/", nil)
	req.RemoteAddr = "10.1.2.3:1234"
	recorder := httptest.NewRecorder()
	bouncer.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("range match status %d", recorder.Code)
	}
}

func TestServeHTTPCountryDecision(t *testing.T) {
	isCrowdsecStreamHealthy = true
	bouncer := newTestMatchBouncer(t)
	bouncer.cacheClient.Set(headerScopeKey(scopeCountry, "FR"), cache.BannedValue, 60)
	req := httptest.NewRequest(http.MethodGet, "http://app.localhost/", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("Cf-Ipcountry", "fr")
	recorder := httptest.NewRecorder()
	bouncer.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("country match status %d", recorder.Code)
	}
}

func TestServeHTTPCountryPlaceholderDoesNotMatch(t *testing.T) {
	isCrowdsecStreamHealthy = true
	bouncer := newTestMatchBouncer(t)
	bouncer.cacheClient.Set(headerScopeKey(scopeCountry, "FR"), cache.BannedValue, 60)
	req := httptest.NewRequest(http.MethodGet, "http://app.localhost/", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("Cf-Ipcountry", "XX")
	recorder := httptest.NewRecorder()
	bouncer.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("XX should skip country, status %d", recorder.Code)
	}
}

func TestServeHTTPASNDecision(t *testing.T) {
	isCrowdsecStreamHealthy = true
	bouncer := newTestMatchBouncer(t)
	bouncer.cacheClient.Set(headerScopeKey(scopeAS, "13335"), cache.BannedValue, 60)
	req := httptest.NewRequest(http.MethodGet, "http://app.localhost/", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("Cf-Asn", "AS13335")
	recorder := httptest.NewRecorder()
	bouncer.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("ASN match status %d", recorder.Code)
	}
}

func TestStoreStreamDecisionIgnoresUsername(t *testing.T) {
	bouncer := newTestMatchBouncer(t)
	storeStreamDecision(bouncer, Decision{Type: "ban", Scope: "username", Value: "alice"}, 60)
	if _, err := bouncer.cacheClient.Get("alice"); err == nil {
		t.Fatal("username scope must not be cached as a key")
	}
	if _, err := bouncer.cacheClient.Get(headerScopeKey("username", "alice")); err == nil {
		t.Fatal("unmapped username scope must not be cached")
	}
}

func TestServeHTTPCustomScopeDecision(t *testing.T) {
	isCrowdsecStreamHealthy = true
	bouncer := newTestMatchBouncer(t)
	bouncer.decisionScopeHeaders["username"] = "X-User"
	storeStreamDecision(bouncer, Decision{Type: "ban", Scope: "username", Value: "alice"}, 60)
	req := httptest.NewRequest(http.MethodGet, "http://app.localhost/", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("X-User", "alice")
	recorder := httptest.NewRecorder()
	bouncer.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("username match status %d", recorder.Code)
	}
}

func TestServeHTTPCustomScopeMissingHeaderSkips(t *testing.T) {
	isCrowdsecStreamHealthy = true
	bouncer := newTestMatchBouncer(t)
	bouncer.decisionScopeHeaders["username"] = "X-User"
	storeStreamDecision(bouncer, Decision{Type: "ban", Scope: "username", Value: "alice"}, 60)
	req := httptest.NewRequest(http.MethodGet, "http://app.localhost/", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	recorder := httptest.NewRecorder()
	bouncer.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("missing custom header should skip, status %d", recorder.Code)
	}
}

func TestRequestScopeValues(t *testing.T) {
	bouncer := &Bouncer{decisionScopeHeaders: map[string]string{
		scopeCountry: "CF-IPCountry",
		scopeAS:      "CF-ASN",
		"username":   "X-User",
	}}
	req := httptest.NewRequest(http.MethodGet, "http://app.localhost/", nil)
	req.Header.Set("Cf-Ipcountry", "fr")
	req.Header.Set("Cf-Asn", "AS13335")
	req.Header.Set("X-User", "  alice  ")
	got := requestScopeValues(bouncer, req)
	if got[scopeCountry] != "FR" || got[scopeAS] != "13335" || got["username"] != "alice" {
		t.Fatalf("normalized values: %+v", got)
	}

	skip := httptest.NewRequest(http.MethodGet, "http://app.localhost/", nil)
	skip.Header.Set("Cf-Ipcountry", "T1")
	skip.Header.Set("Cf-Asn", "AS-1")
	got = requestScopeValues(bouncer, skip)
	if _, ok := got[scopeCountry]; ok {
		t.Fatal("T1 must skip Country")
	}
	if _, ok := got[scopeAS]; ok {
		t.Fatal("invalid ASN must skip AS")
	}
	if requestScopeValues(&Bouncer{}, req) != nil {
		t.Fatal("empty decisionScopeHeaders must return nil")
	}
}

func TestStoreAndDeleteStreamDecisions(t *testing.T) {
	bouncer := newTestMatchBouncer(t)
	bouncer.decisionScopeHeaders["username"] = "X-User"

	storeStreamDecision(bouncer, Decision{Type: "throttle", Scope: "Ip", Value: "1.2.3.4"}, 60)
	if _, err := bouncer.cacheClient.Get("1.2.3.4"); err == nil {
		t.Fatal("unknown type must not be cached")
	}

	storeStreamDecision(bouncer, Decision{Type: "ban", Scope: "Ip", Value: "10.0.0.1/32"}, 60)
	if _, err := bouncer.cacheClient.Get("10.0.0.1"); err != nil {
		t.Fatal("/32 must be stored as host")
	}

	storeStreamDecision(bouncer, Decision{Type: "ban", Scope: "country", Value: "fr"}, 60)
	if _, err := bouncer.cacheClient.Get(headerScopeKey(scopeCountry, "FR")); err != nil {
		t.Fatal("country fr must normalize to FR")
	}
	storeStreamDecision(bouncer, Decision{Type: "ban", Scope: "Country", Value: "XX"}, 60)
	if _, err := bouncer.cacheClient.Get(headerScopeKey(scopeCountry, "XX")); err == nil {
		t.Fatal("Country XX must not be stored")
	}

	storeStreamDecision(bouncer, Decision{Type: "captcha", Scope: "AS", Value: "AS13335"}, 60)
	if got, err := bouncer.cacheClient.Get(headerScopeKey(scopeAS, "13335")); err != nil || got != cache.CaptchaValue {
		t.Fatalf("AS prefix strip: %q %v", got, err)
	}

	storeStreamDecision(bouncer, Decision{Type: "ban", Scope: "Range", Value: "192.168.0.0/16"}, 60)
	if matchRange(bouncer.cacheClient, "192.168.1.9") != cache.BannedValue {
		t.Fatal("range must match")
	}

	storeStreamDecision(bouncer, Decision{Type: "ban", Scope: "username", Value: "  alice  "}, 60)
	if _, err := bouncer.cacheClient.Get(headerScopeKey("username", "alice")); err != nil {
		t.Fatal("mapped username must be cached trimmed")
	}
	storeStreamDecision(bouncer, Decision{Type: "ban", Scope: "session", Value: "abc"}, 60)
	if _, err := bouncer.cacheClient.Get(headerScopeKey("session", "abc")); err == nil {
		t.Fatal("unmapped session must be ignored")
	}
	storeStreamDecision(bouncer, Decision{Type: "ban", Scope: "username", Value: "   "}, 60)

	deleteStreamDecision(bouncer, Decision{Scope: "Ip", Value: "10.0.0.1/32"})
	if _, err := bouncer.cacheClient.Get("10.0.0.1"); err == nil {
		t.Fatal("deleted /32 host")
	}
	deleteStreamDecision(bouncer, Decision{Scope: "Country", Value: "fr"})
	if _, err := bouncer.cacheClient.Get(headerScopeKey(scopeCountry, "FR")); err == nil {
		t.Fatal("deleted country")
	}
	deleteStreamDecision(bouncer, Decision{Scope: "AS", Value: "AS13335"})
	if _, err := bouncer.cacheClient.Get(headerScopeKey(scopeAS, "13335")); err == nil {
		t.Fatal("deleted AS")
	}
	deleteStreamDecision(bouncer, Decision{Scope: "Range", Value: "192.168.0.0/16"})
	if matchRange(bouncer.cacheClient, "192.168.1.9") != "" {
		t.Fatal("deleted range")
	}
	deleteStreamDecision(bouncer, Decision{Scope: "username", Value: "alice"})
	if _, err := bouncer.cacheClient.Get(headerScopeKey("username", "alice")); err == nil {
		t.Fatal("deleted username")
	}
}

func TestLookupCacheMissWhenEmpty(t *testing.T) {
	bouncer := newTestMatchBouncer(t)
	got, err := lookupCachedRemediation(bouncer, "198.51.100.99", nil)
	if err == nil || err.Error() != cache.CacheMiss || got != "" {
		t.Fatalf("empty cache must be CacheMiss: %q %v", got, err)
	}
}

func TestLookupOrderIPBeatsCountry(t *testing.T) {
	bouncer := newTestMatchBouncer(t)
	bouncer.cacheClient.Set("198.51.100.10", cache.CaptchaValue, 60)
	bouncer.cacheClient.Set(headerScopeKey(scopeCountry, "FR"), cache.BannedValue, 60)
	got, err := lookupCachedRemediation(bouncer, "198.51.100.10", map[string]string{scopeCountry: "FR"})
	if err != nil || got != cache.CaptchaValue {
		t.Fatalf("Ip is checked before Country: %q %v", got, err)
	}
}

func TestLookupHeaderScopesBanWins(t *testing.T) {
	bouncer := newTestMatchBouncer(t)
	bouncer.cacheClient.Set(headerScopeKey(scopeCountry, "FR"), cache.CaptchaValue, 60)
	bouncer.cacheClient.Set(headerScopeKey("username", "alice"), cache.BannedValue, 60)
	got, err := lookupCachedRemediation(bouncer, "198.51.100.20", map[string]string{
		scopeCountry: "FR",
		"username":   "alice",
	})
	if err != nil || got != cache.BannedValue {
		t.Fatalf("ban on any header scope wins: %q %v", got, err)
	}
}

func TestServeHTTPCountryT1AndMissingHeader(t *testing.T) {
	isCrowdsecStreamHealthy = true
	bouncer := newTestMatchBouncer(t)
	bouncer.cacheClient.Set(headerScopeKey(scopeCountry, "FR"), cache.BannedValue, 60)
	req := httptest.NewRequest(http.MethodGet, "http://app.localhost/", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("Cf-Ipcountry", "T1")
	recorder := httptest.NewRecorder()
	bouncer.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("T1 should skip country, status %d", recorder.Code)
	}
	req2 := httptest.NewRequest(http.MethodGet, "http://app.localhost/", nil)
	req2.RemoteAddr = "203.0.113.10:1234"
	recorder2 := httptest.NewRecorder()
	bouncer.ServeHTTP(recorder2, req2)
	if recorder2.Code != http.StatusOK {
		t.Fatalf("missing country header should skip, status %d", recorder2.Code)
	}
}

func TestServeHTTPCustomScopeWhitespace(t *testing.T) {
	isCrowdsecStreamHealthy = true
	bouncer := newTestMatchBouncer(t)
	bouncer.decisionScopeHeaders["username"] = "X-User"
	storeStreamDecision(bouncer, Decision{Type: "ban", Scope: "username", Value: "alice"}, 60)
	req := httptest.NewRequest(http.MethodGet, "http://app.localhost/", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("X-User", "  alice  ")
	recorder := httptest.NewRecorder()
	bouncer.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("trimmed custom header status %d", recorder.Code)
	}
}

func TestPreferRemediationAndPickDecision(t *testing.T) {
	if preferRemediation(cache.CaptchaValue, cache.BannedValue) != cache.BannedValue {
		t.Fatal("ban wins")
	}
	if preferRemediation(cache.CaptchaValue, "") != cache.CaptchaValue {
		t.Fatal("keep captcha")
	}
	if remediationValue("ban") != cache.BannedValue || remediationValue("captcha") != cache.CaptchaValue || remediationValue("throttle") != "" {
		t.Fatal("remediationValue")
	}
	items := []Decision{{Type: "captcha"}, {Type: "ban"}, {Type: "captcha"}}
	if pickDecision(items).Type != "ban" {
		t.Fatal("first ban")
	}
	if pickDecision([]Decision{{Type: "captcha"}}).Type != "captcha" {
		t.Fatal("captcha fallback")
	}
	if pickDecision([]Decision{{Type: "throttle"}}) != nil {
		t.Fatal("unknown type")
	}
}

func TestStreamScopeListCustomOnly(t *testing.T) {
	bouncer := &Bouncer{decisionScopeHeaders: map[string]string{"username": "X-User", "session": "X-Session"}}
	if got := streamScopeList(bouncer); got != "ip,range,session,username" {
		t.Fatalf("sorted extras %q", got)
	}
}

func TestLiveCacheTTL(t *testing.T) {
	bouncer := &Bouncer{defaultDecisionTimeout: 30}
	if liveCacheTTL(bouncer, time.Minute) != 30 {
		t.Fatal("cap at default")
	}
	if liveCacheTTL(bouncer, 10*time.Second) != 10 {
		t.Fatal("use decision duration")
	}
	if liveCacheTTL(bouncer, 0) != 30 {
		t.Fatal("zero duration uses default")
	}
}
