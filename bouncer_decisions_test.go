package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"net/http"
	"net/http/httptest"
	"testing"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	captcha "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	decision "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/decision"
	ip "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/ip"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func newTestMatchBouncer(t *testing.T) *Bouncer {
	t.Helper()
	log := logger.New("ERROR", "")
	checker, err := ip.NewChecker(log, []string{})
	if err != nil {
		t.Fatal(err)
	}
	cacheClient := &cache.Client{}
	cacheClient.New(log, false, "", "", "")
	return &Bouncer{
		next: http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			rw.WriteHeader(http.StatusOK)
		}),
		enabled:               true,
		crowdsecMode:          configuration.StreamMode,
		forwardedCustomHeader: "X-Forwarded-For",
		countryHeader:         "CF-IPCountry",
		asnHeader:             "CF-ASN",
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
	bouncer.countryHeader = "CF-IPCountry"
	bouncer.asnHeader = "CF-ASN"
	if got := streamScopeList(bouncer); got != "ip,range,country,AS" {
		t.Fatalf("configured scopes %q", got)
	}
}

func TestStreamQueryLAPIIncludesScopes(t *testing.T) {
	bouncer := &Bouncer{
		crowdsecStreamRoute: crowdsecLapiStreamRoute,
		countryHeader:       "CF-IPCountry",
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
	decision.AddRange(bouncer.cacheClient, "10.0.0.0/8", cache.BannedValue, 60)
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
	bouncer.cacheClient.Set(decision.CountryKey("FR"), cache.BannedValue, 60)
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
	bouncer.cacheClient.Set(decision.CountryKey("FR"), cache.BannedValue, 60)
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
	bouncer.cacheClient.Set(decision.ASKey("13335"), cache.BannedValue, 60)
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
}
