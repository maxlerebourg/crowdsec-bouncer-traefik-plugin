package ip

import (
	"net"
	"sync"
	"time"
)

// AllowSet holds Ip-scope whitelist decisions for stream mode, so a single
// allowed IP (a verified crawler, say) can sit inside a banned range.
// It is safe for concurrent use.
type AllowSet struct {
	mu      sync.RWMutex
	expires map[string]time.Time
	now     func() time.Time
}

// NewAllowSet returns an empty set.
func NewAllowSet() *AllowSet {
	return &AllowSet{expires: map[string]time.Time{}, now: time.Now}
}

// normaliseIP returns the canonical form of an address ("" when invalid), so
// "::ffff:192.0.2.1" and "192.0.2.1", or two IPv6 spellings, are one key.
func normaliseIP(s string) string {
	parsed := net.ParseIP(s)
	if parsed == nil {
		return ""
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	return parsed.String()
}

// Add allows ip for duration. With stacked decisions the longest expiry wins.
// Invalid addresses and non-positive durations are ignored.
func (as *AllowSet) Add(ipStr string, duration time.Duration) {
	key := normaliseIP(ipStr)
	if key == "" || duration <= 0 {
		return
	}
	until := as.now().Add(duration)
	as.mu.Lock()
	defer as.mu.Unlock()
	if cur, ok := as.expires[key]; !ok || until.After(cur) {
		as.expires[key] = until
	}
}

// Has reports whether ip holds an unexpired allow. Expired entries are
// removed on the way.
func (as *AllowSet) Has(ipStr string) bool {
	key := normaliseIP(ipStr)
	if key == "" {
		return false
	}
	as.mu.RLock()
	until, ok := as.expires[key]
	as.mu.RUnlock()
	if !ok {
		return false
	}
	if as.now().Before(until) {
		return true
	}
	as.mu.Lock()
	if cur, still := as.expires[key]; still && !as.now().Before(cur) {
		delete(as.expires, key)
	}
	as.mu.Unlock()
	return false
}

// Len is the number of stored entries, expired ones not yet seen included.
func (as *AllowSet) Len() int {
	as.mu.RLock()
	defer as.mu.RUnlock()
	return len(as.expires)
}

// Replace swaps in the contents of next (used on a full stream resync).
func (as *AllowSet) Replace(next *AllowSet) {
	next.mu.RLock()
	m := next.expires
	next.mu.RUnlock()
	as.mu.Lock()
	as.expires = m
	as.mu.Unlock()
}
