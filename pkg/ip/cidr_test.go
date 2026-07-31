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
