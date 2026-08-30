package decision

import "testing"

func TestNormalizeScope(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"ip", ScopeIP},
		{"IP", ScopeIP},
		{"range", ScopeRange},
		{"country", ScopeCountry},
		{"as", ScopeAS},
		{"AS", ScopeAS},
		{"username", "username"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := NormalizeScope(tt.in); got != tt.want {
			t.Errorf("NormalizeScope(%q) = %q, want %q", tt.in, got, tt.want)
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
		if got := NormalizeCountry(tt.in); got != tt.want {
			t.Errorf("NormalizeCountry(%q) = %q, want %q", tt.in, got, tt.want)
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
		if got := NormalizeASN(tt.in); got != tt.want {
			t.Errorf("NormalizeASN(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestIPCacheKey(t *testing.T) {
	if got := IPCacheKey("10.0.0.1"); got != "10.0.0.1" {
		t.Errorf("bare IP: %s", got)
	}
	if got := IPCacheKey("10.0.0.1/32"); got != "10.0.0.1" {
		t.Errorf("/32: %s", got)
	}
	if got := IPCacheKey("10.0.0.0/24"); got != "10.0.0.0/24" {
		t.Errorf("non-host CIDR should stay: %s", got)
	}
}
