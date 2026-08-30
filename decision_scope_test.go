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
}
