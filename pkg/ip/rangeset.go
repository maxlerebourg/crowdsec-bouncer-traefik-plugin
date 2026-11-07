package ip

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

const (
	bitsIPv4 = 32
	bitsIPv6 = 128
	// banValue mirrors cache.BannedValue: a ban beats a captcha when an IP
	// falls inside ranges with both remediations.
	banValue = "t"
)

type rangeEntry struct {
	value   string
	expires time.Time
}

// rangeFamily indexes one address family by prefix length, then by the
// masked network bytes, so a lookup costs one map read per prefix length in
// use instead of one comparison per range.
type rangeFamily struct {
	byLen map[int]map[string]rangeEntry
	lens  []int // prefix lengths in use, longest first
}

func newRangeFamily() *rangeFamily {
	return &rangeFamily{byLen: map[int]map[string]rangeEntry{}}
}

func (f *rangeFamily) refreshLens() {
	f.lens = f.lens[:0]
	for l := range f.byLen {
		f.lens = append(f.lens, l)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(f.lens)))
}

// RangeSet holds CrowdSec Range-scope decisions (CIDR blocks) for stream
// mode, where decisions are cached locally and looked up by client IP.
// It is safe for concurrent use.
type RangeSet struct {
	mu  sync.RWMutex
	v4  *rangeFamily
	v6  *rangeFamily
	n   int
	now func() time.Time
}

// NewRangeSet returns an empty set.
func NewRangeSet() *RangeSet {
	return &RangeSet{v4: newRangeFamily(), v6: newRangeFamily(), now: time.Now}
}

// parseRange returns the family, prefix length and masked network key of a
// CIDR. Host bits in the value are cleared.
func (rs *RangeSet) parseRange(cidr string) (*rangeFamily, int, string, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, 0, "", fmt.Errorf("invalid range %q: %w", cidr, err)
	}
	ones, bits := network.Mask.Size()
	if bits == bitsIPv4 {
		return rs.v4, ones, string(network.IP.To4()), nil
	}
	return rs.v6, ones, string(network.IP.To16()), nil
}

// Add stores a range decision with its remediation value for duration.
func (rs *RangeSet) Add(cidr, value string, duration time.Duration) error {
	if duration <= 0 {
		return errors.New("range decision needs a positive duration")
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	fam, ones, key, err := rs.parseRange(cidr)
	if err != nil {
		return err
	}
	m, ok := fam.byLen[ones]
	if !ok {
		m = map[string]rangeEntry{}
		fam.byLen[ones] = m
		fam.refreshLens()
	}
	if _, exists := m[key]; !exists {
		rs.n++
	}
	m[key] = rangeEntry{value: value, expires: rs.now().Add(duration)}
	return nil
}

// Delete removes a range decision. Unknown or malformed values are ignored.
func (rs *RangeSet) Delete(cidr string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	fam, ones, key, err := rs.parseRange(cidr)
	if err != nil {
		return
	}
	m, ok := fam.byLen[ones]
	if !ok {
		return
	}
	if _, exists := m[key]; !exists {
		return
	}
	delete(m, key)
	rs.n--
	if len(m) == 0 {
		delete(fam.byLen, ones)
		fam.refreshLens()
	}
}

// Get returns the remediation value of the ranges containing ip ("t" when
// any of them is a ban), or false when no live range contains it.
func (rs *RangeSet) Get(ipStr string) (string, bool) {
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return "", false
	}
	fam, addr, bits := rs.v6, parsed.To16(), bitsIPv6
	if v4 := parsed.To4(); v4 != nil {
		fam, addr, bits = rs.v4, v4, bitsIPv4
	}
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	now := rs.now()
	found := ""
	for _, l := range fam.lens {
		e, ok := fam.byLen[l][string(addr.Mask(net.CIDRMask(l, bits)))]
		if !ok || !now.Before(e.expires) {
			continue
		}
		if e.value == banValue {
			return banValue, true
		}
		found = e.value
	}
	return found, found != ""
}

// Len is the number of stored ranges, expired ones included.
func (rs *RangeSet) Len() int {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.n
}

// Replace swaps in the contents of next (used on a full stream resync).
func (rs *RangeSet) Replace(next *RangeSet) {
	next.mu.RLock()
	v4, v6, n := next.v4, next.v6, next.n
	next.mu.RUnlock()
	rs.mu.Lock()
	rs.v4, rs.v6, rs.n = v4, v6, n
	rs.mu.Unlock()
}
