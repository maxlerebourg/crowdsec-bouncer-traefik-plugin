package ip

import (
	"strconv"
	"strings"
	"testing"
)

func TestCIDRKeys(t *testing.T) {
	tests := []struct {
		ip       string
		wantKeys int
		checks   map[int]string
	}{
		{
			ip:       "10.0.0.1",
			wantKeys: 33,
			checks:   map[int]string{0: "10.0.0.1/32", 8: "10.0.0.0/24", 32: "0.0.0.0/0"},
		},
		{
			ip:       "2001:db8::1",
			wantKeys: 129,
			checks:   map[int]string{0: "2001:db8::1/128", 32: "2001:db8::/96", 128: "::/0"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			keys := CIDRKeys(tt.ip)
			if keys == nil {
				t.Fatal("CIDRKeys returned nil")
			}
			if len(keys) != tt.wantKeys {
				t.Fatalf("expected %d keys, got %d", tt.wantKeys, len(keys))
			}
			for idx, want := range tt.checks {
				if keys[idx] != want {
					t.Errorf("keys[%d] should be %s, got %s", idx, want, keys[idx])
				}
			}
		})
	}
}

func TestCIDRKeys_MostToLeastSpecific(t *testing.T) {
	ips := []string{"10.0.0.1", "2001:db8::1"}
	for _, ip := range ips {
		t.Run(ip, func(t *testing.T) {
			keys := CIDRKeys(ip)
			for i := 1; i < len(keys); i++ {
				prevBits := strings.Split(keys[i-1], "/")[1]
				curBits := strings.Split(keys[i], "/")[1]
				prevN, _ := strconv.Atoi(prevBits)
				curN, _ := strconv.Atoi(curBits)
				if prevN <= curN {
					t.Errorf("keys should go from most specific to least specific at index %d: /%d <= /%d", i, prevN, curN)
				}
			}
		})
	}
}

func TestCIDRKeys_IPVariants(t *testing.T) {
	tests := []struct {
		ip       string
		wantKeys int
	}{
		{"0.0.0.0", 33},
		{"255.255.255.255", 33},
		{"1.2.3.4", 33},
		{"10.0.0.1", 33},
		{"192.168.1.1", 33},
		{"invalid", 0},
		{"", 0},
		{"   ", 0},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			keys := CIDRKeys(tt.ip)
			if len(keys) != tt.wantKeys {
				t.Errorf("CIDRKeys(%q) returned %d keys, want %d", tt.ip, len(keys), tt.wantKeys)
			}
		})
	}
}

func TestCIDRKeys_VerifyNetworkAddress(t *testing.T) {
	keys := CIDRKeys("10.1.2.3")
	tests := []struct {
		bits int
		want string
	}{
		{24, "10.1.2.0/24"},
		{16, "10.1.0.0/16"},
		{8, "10.0.0.0/8"},
	}
	for _, tt := range tests {
		if got := keys[32-tt.bits]; got != tt.want {
			t.Errorf("/%d network should be %s, got %s", tt.bits, tt.want, got)
		}
	}
}

func TestCIDRKeys_VerifyNetworkAddressIPv6(t *testing.T) {
	keys := CIDRKeys("2001:db8:1:2:3:4:5:6")
	tests := []struct {
		bits int
		want string
	}{
		{64, "2001:db8:1:2::/64"},
		{48, "2001:db8:1::/48"},
		{32, "2001:db8::/32"},
	}
	for _, tt := range tests {
		if got := keys[128-tt.bits]; got != tt.want {
			t.Errorf("/%d network should be %s, got %s", tt.bits, tt.want, got)
		}
	}
}

// TestCIDRKeys_MatchNormalizeCIDR covers the invariant range support rests on: the key
// written for a decision is a key looked up for the IPs it covers, and only those.
func TestCIDRKeys_MatchNormalizeCIDR(t *testing.T) {
	tests := []struct {
		cidr  string
		ip    string
		match bool
	}{
		{cidr: "10.0.0.0/8", ip: "10.1.2.3", match: true},
		{cidr: "10.0.0.0/24", ip: "10.0.0.1", match: true},
		{cidr: "10.0.0.0/24", ip: "10.0.1.1", match: false},
		{cidr: "1.2.3.4/32", ip: "1.2.3.4", match: true},
		{cidr: "1.2.3.4/32", ip: "1.2.3.5", match: false},
		{cidr: "0.0.0.0/0", ip: "8.8.8.8", match: true},
		// LAPI does not have to send a network address, the host bits are dropped.
		{cidr: "10.0.0.5/24", ip: "10.0.0.9", match: true},
		{cidr: "  192.168.1.0/24  ", ip: "192.168.1.42", match: true},
		{cidr: "2001:db8::/32", ip: "2001:db8::1", match: true},
		{cidr: "2001:db8::/32", ip: "2001:db9::1", match: false},
		{cidr: "::/0", ip: "2001:db8::1", match: true},
		// An IPv4 range and an IPv4 mapped client still have to meet.
		{cidr: "10.0.0.0/8", ip: "::ffff:10.1.2.3", match: true},
		{cidr: "::ffff:10.0.0.0/104", ip: "10.1.2.3", match: true},
		// Families do not mix.
		{cidr: "::/0", ip: "8.8.8.8", match: false},
		{cidr: "2001:db8::/32", ip: "::ffff:10.0.0.1", match: false},
	}
	for _, tt := range tests {
		t.Run(tt.cidr+"_"+tt.ip, func(t *testing.T) {
			key := NormalizeCIDR(tt.cidr)
			if key == "" {
				t.Fatalf("NormalizeCIDR(%q) returned nothing", tt.cidr)
			}
			found := false
			for _, candidate := range CIDRKeys(tt.ip) {
				if candidate == key {
					found = true
					break
				}
			}
			if found != tt.match {
				t.Errorf("key %q of %q found in CIDRKeys(%q) = %v, want %v", key, tt.cidr, tt.ip, found, tt.match)
			}
		})
	}
}

func TestCIDRLookupKeys(t *testing.T) {
	tests := []struct {
		name       string
		ip         string
		prefixLens []int
		want       []string
	}{
		{
			name:       "most specific first",
			ip:         "10.1.2.3",
			prefixLens: []int{8, 32, 16},
			want:       []string{"10.1.2.3/32", "10.1.0.0/16", "10.0.0.0/8"},
		},
		{
			name:       "duplicates are dropped",
			ip:         "10.1.2.3",
			prefixLens: []int{24, 24, 24},
			want:       []string{"10.1.2.0/24"},
		},
		{
			name:       "lengths of the other family are skipped",
			ip:         "10.1.2.3",
			prefixLens: []int{48, 64, 24},
			want:       []string{"10.1.2.0/24"},
		},
		{
			name:       "out of range lengths are skipped",
			ip:         "10.1.2.3",
			prefixLens: []int{-1, 33, 129, 8},
			want:       []string{"10.0.0.0/8"},
		},
		{
			name:       "ipv6 keeps its own lengths",
			ip:         "2001:db8::1",
			prefixLens: []int{32, 64},
			want:       []string{"2001:db8::/64", "2001:db8::/32"},
		},
		{
			name:       "no length gives no key",
			ip:         "10.1.2.3",
			prefixLens: []int{},
			want:       []string{},
		},
		{
			name:       "invalid ip gives no key",
			ip:         "invalid",
			prefixLens: []int{24},
			want:       nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CIDRLookupKeys(tt.ip, tt.prefixLens)
			if len(got) != len(tt.want) {
				t.Fatalf("CIDRLookupKeys(%q, %v) = %v, want %v", tt.ip, tt.prefixLens, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("CIDRLookupKeys(%q, %v)[%d] = %q, want %q", tt.ip, tt.prefixLens, i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestCIDRLookupKeys_SubsetOfCIDRKeys: restricting the lengths only removes candidates,
// it never changes the key of a length that is kept.
func TestCIDRLookupKeys_SubsetOfCIDRKeys(t *testing.T) {
	for _, ipStr := range []string{"10.1.2.3", "2001:db8::1", "::ffff:10.1.2.3"} {
		t.Run(ipStr, func(t *testing.T) {
			all := CIDRKeys(ipStr)
			maxBits := len(all) - 1
			for bits := 0; bits <= maxBits; bits++ {
				got := CIDRLookupKeys(ipStr, []int{bits})
				if len(got) != 1 {
					t.Fatalf("CIDRLookupKeys(%q, [%d]) returned %d keys", ipStr, bits, len(got))
				}
				if want := all[maxBits-bits]; got[0] != want {
					t.Errorf("CIDRLookupKeys(%q, [%d]) = %q, want %q", ipStr, bits, got[0], want)
				}
			}
		})
	}
}

func TestCIDRPrefixLen(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"10.0.0.0/8", 8},
		{"10.0.0.0/32", 32},
		{"0.0.0.0/0", 0},
		{"10.0.0.5/24", 24},
		{"  10.0.0.0/16  ", 16},
		{"2001:db8::/32", 32},
		{"2001:db8::/128", 128},
		{"::/0", 0},
		{"10.0.0.1", -1},
		{"invalid", -1},
		{"", -1},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := CIDRPrefixLen(tt.input); got != tt.want {
				t.Errorf("CIDRPrefixLen(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeCIDR(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"10.0.0.0/16", "10.0.0.0/16"},
		{"192.168.1.0/24", "192.168.1.0/24"},
		{"2001:db8::/32", "2001:db8::/32"},
		{"0.0.0.0/0", "0.0.0.0/0"},
		{"::/0", "::/0"},
		{"invalid", ""},
		{"", ""},
		{"  10.0.0.0/8  ", "10.0.0.0/8"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeCIDR(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeCIDR(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
