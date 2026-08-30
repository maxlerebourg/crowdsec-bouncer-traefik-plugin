package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import "testing"

func TestNormalizeScope(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"ip", scopeIP},
		{"IP", scopeIP},
		{"range", scopeRange},
		{"country", scopeCountry},
		{"as", scopeAS},
		{"AS", scopeAS},
		{"username", "username"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := normalizeScope(tt.in); got != tt.want {
			t.Errorf("normalizeScope(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNormalizeCountry(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"fr", "FR"},
		{"FR", "FR"},
		{" XX ", ""},
		{"T1", ""},
		{"USA", ""},
		{"12", ""},
		{"", ""},
		{"F", ""},
	}
	for _, tt := range tests {
		if got := normalizeCountry(tt.in); got != tt.want {
			t.Errorf("normalizeCountry(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNormalizeASN(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"13335", "13335"},
		{"AS13335", "13335"},
		{"as13335", "13335"},
		{"AS 13335", "13335"},
		{" 13335 ", "13335"},
		{"", ""},
		{"AS", ""},
		{"AS-1", ""},
	}
	for _, tt := range tests {
		if got := normalizeASN(tt.in); got != tt.want {
			t.Errorf("normalizeASN(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNormalizeDecisionScopeHeaders(t *testing.T) {
	got := normalizeDecisionScopeHeaders(map[string]string{
		"country":  "CF-IPCountry",
		"AS":       "CF-ASN",
		"username": "X-User",
		"ip":       "X-Real-IP",
		"range":    "X-Range",
		"":         "X-Empty",
		"session":  "  ",
	})
	if got[scopeCountry] != "CF-IPCountry" || got[scopeAS] != "CF-ASN" || got["username"] != "X-User" {
		t.Fatalf("kept scopes: %+v", got)
	}
	if _, ok := got[scopeIP]; ok {
		t.Fatal("ip must be dropped")
	}
	if _, ok := got[scopeRange]; ok {
		t.Fatal("range must be dropped")
	}
	if _, ok := got[""]; ok {
		t.Fatal("empty scope must be dropped")
	}
	if _, ok := got["session"]; ok {
		t.Fatal("empty header must be dropped")
	}
}

func TestHeaderScopeKey(t *testing.T) {
	if got := headerScopeKey(scopeCountry, "FR"); got != countryKey("FR") {
		t.Fatalf("country key %q", got)
	}
	if got := headerScopeKey(scopeAS, "13335"); got != asKey("13335") {
		t.Fatalf("as key %q", got)
	}
	if got := headerScopeKey("username", "alice"); got != "username:alice" {
		t.Fatalf("username key %q", got)
	}
}

func TestIPCacheKey(t *testing.T) {
	if got := ipCacheKey("10.0.0.1"); got != "10.0.0.1" {
		t.Errorf("bare IP: %s", got)
	}
	if got := ipCacheKey("10.0.0.1/32"); got != "10.0.0.1" {
		t.Errorf("/32: %s", got)
	}
	if got := ipCacheKey("10.0.0.0/24"); got != "10.0.0.0/24" {
		t.Errorf("non-host CIDR should stay: %s", got)
	}
	if got := ipCacheKey("2001:db8::1/128"); got != "2001:db8::1" {
		t.Errorf("/128: %s", got)
	}
}

func TestNormalizeDecisionScopeHeadersNil(t *testing.T) {
	if got := normalizeDecisionScopeHeaders(nil); got != nil {
		t.Fatalf("nil input: %+v", got)
	}
	if got := normalizeDecisionScopeHeaders(map[string]string{}); got != nil {
		t.Fatalf("empty input: %+v", got)
	}
}
