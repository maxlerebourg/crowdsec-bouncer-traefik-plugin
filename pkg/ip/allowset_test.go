package ip

import (
	"testing"
	"time"
)

func newTestAllowSet(now *time.Time) *AllowSet {
	as := NewAllowSet()
	as.now = func() time.Time { return *now }
	return as
}

func TestAllowSetExpiry(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	as := newTestAllowSet(&now)
	as.Add("192.0.2.7", time.Hour)
	if !as.Has("192.0.2.7") {
		t.Fatal("allowed IP not found")
	}
	if as.Has("192.0.2.8") {
		t.Fatal("other IP allowed")
	}
	now = now.Add(2 * time.Hour)
	if as.Has("192.0.2.7") {
		t.Fatal("expired entry still allows")
	}
}

// TestAllowSetKeepsLongestExpiry: CrowdSec keeps stacked decisions with
// independent expiries; a shorter one must not cut a longer one short.
func TestAllowSetKeepsLongestExpiry(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	as := newTestAllowSet(&now)
	as.Add("192.0.2.7", 6*time.Hour)
	as.Add("192.0.2.7", time.Hour)
	now = now.Add(3 * time.Hour)
	if !as.Has("192.0.2.7") {
		t.Fatal("shorter decision shortened the allow")
	}
}

// TestAllowSetNormalisesAddresses: the stream value and the client IP may
// spell the same address differently.
func TestAllowSetNormalisesAddresses(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	as := newTestAllowSet(&now)
	as.Add("2001:DB8:0:0::1", time.Hour)
	as.Add("198.51.100.4", time.Hour)
	if !as.Has("2001:db8::1") {
		t.Fatal("IPv6 spelling mismatch")
	}
	if !as.Has("::ffff:198.51.100.4") {
		t.Fatal("v4-mapped address not matched")
	}
	as.Add("not-an-ip", time.Hour)
	as.Add("192.0.2.9", 0)
	if as.Len() != 2 {
		t.Fatalf("len = %d, want 2 (bad IP and zero duration ignored)", as.Len())
	}
}

func TestAllowSetReplace(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	as := newTestAllowSet(&now)
	as.Add("192.0.2.7", time.Hour)
	next := newTestAllowSet(&now)
	next.Add("192.0.2.8", time.Hour)
	as.Replace(next)
	if as.Has("192.0.2.7") || !as.Has("192.0.2.8") {
		t.Fatal("Replace did not swap the contents")
	}
}
