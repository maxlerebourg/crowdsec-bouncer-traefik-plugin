package ip

import (
	"testing"
	"time"
)

func newTestSet(now *time.Time) *RangeSet {
	rs := NewRangeSet()
	rs.now = func() time.Time { return *now }
	return rs
}

func TestRangeSetIPv4(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	rs := newTestSet(&now)
	if err := rs.Add("203.0.113.0/24", "t", time.Hour); err != nil {
		t.Fatalf("add: %v", err)
	}
	if v, ok := rs.Get("203.0.113.77"); !ok || v != "t" {
		t.Fatalf("inside = %q %v, want t true", v, ok)
	}
	if _, ok := rs.Get("203.0.114.1"); ok {
		t.Fatal("outside matched")
	}
	// An IPv4-mapped IPv6 address is the same client.
	if _, ok := rs.Get("::ffff:203.0.113.5"); !ok {
		t.Fatal("v4-mapped address did not match")
	}
	if rs.Len() != 1 {
		t.Fatalf("len = %d", rs.Len())
	}
}

func TestRangeSetIPv6(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	rs := newTestSet(&now)
	if err := rs.Add("2001:db8::/32", "t", time.Hour); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, ok := rs.Get("2001:db8:1234::1"); !ok {
		t.Fatal("inside did not match")
	}
	if _, ok := rs.Get("2001:db9::1"); ok {
		t.Fatal("outside matched")
	}
	if _, ok := rs.Get("203.0.113.5"); ok {
		t.Fatal("v4 matched a v6 range")
	}
}

// TestRangeSetBanBeatsCaptcha: an IP inside both a captcha range and a ban
// range gets the ban, whichever prefix is longer.
func TestRangeSetBanBeatsCaptcha(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	rs := newTestSet(&now)
	_ = rs.Add("198.51.100.0/24", "c", time.Hour)
	_ = rs.Add("198.51.0.0/16", "t", time.Hour)
	if v, _ := rs.Get("198.51.100.9"); v != "t" {
		t.Fatalf("value = %q, want t", v)
	}
	if v, _ := rs.Get("198.51.7.9"); v != "t" {
		t.Fatalf("value = %q, want t", v)
	}
	rs2 := newTestSet(&now)
	_ = rs2.Add("198.51.100.0/24", "c", time.Hour)
	if v, _ := rs2.Get("198.51.100.9"); v != "c" {
		t.Fatalf("captcha only = %q, want c", v)
	}
}

func TestRangeSetExpiryAndDelete(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	rs := newTestSet(&now)
	_ = rs.Add("192.0.2.0/24", "t", time.Minute)
	_ = rs.Add("2001:db8::/48", "t", time.Hour)
	now = now.Add(2 * time.Minute)
	if _, ok := rs.Get("192.0.2.1"); ok {
		t.Fatal("expired range matched")
	}
	rs.Delete("2001:db8::/48")
	if _, ok := rs.Get("2001:db8::1"); ok {
		t.Fatal("deleted range matched")
	}
	// Deleting an unknown or malformed value is a no-op.
	rs.Delete("not-a-cidr")
	rs.Delete("10.0.0.0/8")
}

// TestRangeSetNormalisesHostBits: CrowdSec sends the range as stored; host
// bits set in the value must not hide the range, and Delete must find it.
func TestRangeSetNormalisesHostBits(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	rs := newTestSet(&now)
	_ = rs.Add("192.0.2.17/24", "t", time.Hour)
	if _, ok := rs.Get("192.0.2.200"); !ok {
		t.Fatal("range with host bits did not match")
	}
	rs.Delete("192.0.2.0/24")
	if _, ok := rs.Get("192.0.2.200"); ok {
		t.Fatal("delete by canonical form missed the range")
	}
}

func TestRangeSetRejectsBadInput(t *testing.T) {
	rs := NewRangeSet()
	if err := rs.Add("1.2.3.4", "t", time.Hour); err == nil {
		t.Fatal("want an error for a bare IP")
	}
	if err := rs.Add("1.2.3.0/24", "t", 0); err == nil {
		t.Fatal("want an error for a zero duration")
	}
	if _, ok := rs.Get("not-an-ip"); ok {
		t.Fatal("garbage IP matched")
	}
}

// TestRangeSetReplace: a stream startup (full resync) swaps the whole set,
// so ranges deleted while the stream was down do not linger.
func TestRangeSetReplace(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	rs := newTestSet(&now)
	_ = rs.Add("192.0.2.0/24", "t", time.Hour)
	next := newTestSet(&now)
	_ = next.Add("198.51.100.0/24", "t", time.Hour)
	rs.Replace(next)
	if _, ok := rs.Get("192.0.2.1"); ok {
		t.Fatal("old range survived Replace")
	}
	if _, ok := rs.Get("198.51.100.1"); !ok {
		t.Fatal("new range missing after Replace")
	}
}
