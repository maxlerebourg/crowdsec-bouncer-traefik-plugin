// Package cache implements utility routines for manipulating cache.
// It supports currently local file and redis cache.
package cache

import (
	"errors"
	"testing"

	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
	simpleredis "github.com/maxlerebourg/simpleredis"
)

func Test_Get(t *testing.T) {
	IPInCache := "10.0.0.10"
	IPNotInCache := "10.0.0.20"
	client := &Client{cache: &localCache{}, log: logger.New("INFO", "")}
	client.Set(IPInCache, BannedValue, 10)
	type args struct {
		clientIP string
	}
	tests := []struct {
		name     string
		args     args
		want     string
		wantErr  bool
		valueErr string
	}{
		{name: "Fetch Known valid IP", args: args{clientIP: IPInCache}, want: BannedValue, wantErr: false, valueErr: ""},
		{name: "Fetch Unknown valid IP", args: args{clientIP: IPNotInCache}, want: "", wantErr: true, valueErr: CacheMiss},
		{name: "Fetch invalid value", args: args{clientIP: "test"}, want: "", wantErr: true, valueErr: CacheMiss},
		{name: "Fetch empty value", args: args{clientIP: ""}, want: "", wantErr: true, valueErr: CacheMiss},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := client.Get(tt.args.clientIP)
			if (err != nil) != tt.wantErr {
				t.Errorf("Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Get() = %v, want %v", got, tt.want)
				return
			}
			if tt.valueErr != "" && tt.valueErr != err.Error() {
				t.Errorf("Get() err = %v, want %v", err.Error(), tt.valueErr)
			}
		})
	}
}

func Test_Set(t *testing.T) {
	client := &Client{cache: &localCache{}, log: logger.New("INFO", "")}
	IPInCache := "10.0.0.11"
	type args struct {
		clientIP string
		value    string
		duration int64
	}

	tests := []struct {
		name     string
		args     args
		want     string
		wantErr  bool
		valueErr string
	}{
		{name: "Set valid IP in local cache for 0 sec", args: args{clientIP: IPInCache, value: BannedValue, duration: 0}, want: "", wantErr: true, valueErr: CacheMiss},
		{name: "Set valid IP in local cache for 10 sec", args: args{clientIP: IPInCache, value: BannedValue, duration: 10}, want: BannedValue, wantErr: false, valueErr: ""},
		{name: "Set valid IP in local cache for 10 sec", args: args{clientIP: IPInCache, value: NoBannedValue, duration: 10}, want: NoBannedValue, wantErr: false, valueErr: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client.Set(tt.args.clientIP, tt.args.value, tt.args.duration)
			got, err := client.Get(tt.args.clientIP)
			if (err != nil) != tt.wantErr {
				t.Errorf("Set() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Set() = %v, want %v", got, tt.want)
				return
			}
			if tt.valueErr != "" && tt.valueErr != err.Error() {
				t.Errorf("Set() err = %v, want %v", err.Error(), tt.valueErr)
			}
		})
	}
}

func Test_Delete(t *testing.T) {
	IPInCache := "10.0.0.12"
	IPNotInCache := "10.0.0.22"
	client := &Client{cache: &localCache{}, log: logger.New("INFO", "")}
	client.Set(IPInCache, BannedValue, 10)
	type args struct {
		clientIP string
	}

	tests := []struct {
		name     string
		args     args
		want     string
		wantErr  bool
		valueErr string
	}{
		{name: "Delete Known valid IP", args: args{clientIP: IPInCache}, want: "", wantErr: true, valueErr: CacheMiss},
		{name: "Delete Unknown valid IP", args: args{clientIP: IPNotInCache}, want: "", wantErr: true, valueErr: CacheMiss},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client.Delete(tt.args.clientIP)
			got, err := client.Get(tt.args.clientIP)
			if (err != nil) != tt.wantErr {
				t.Errorf("Delete() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Delete() = %v, want %v", got, tt.want)
				return
			}
			if tt.valueErr != "" && tt.valueErr != err.Error() {
				t.Errorf("Delete() err = %v, want %v", err.Error(), tt.valueErr)
			}
		})
	}
}

// indexOfReader returns the position of r inside rc.readers, or -1 when r is the writer (the no-readers fallback).
func indexOfReader(rc *redisCache, r *simpleredis.SimpleRedis) int {
	if r == &rc.writer {
		return -1
	}
	for i := range rc.readers {
		if r == &rc.readers[i] {
			return i
		}
	}
	return -2
}

func Test_nextReader(t *testing.T) {
	// The counter starts at 0, so the first Add(1) yields index 1, then 2, 0, 1, ... over n readers.
	tests := []struct {
		name    string
		readers int
		want    []int
	}{
		{name: "round-robin over three readers", readers: 3, want: []int{1, 2, 0, 1, 2, 0, 1}},
		{name: "single reader always selected", readers: 1, want: []int{0, 0, 0, 0, 0}},
		{name: "no readers fall back to writer", readers: 0, want: []int{-1, -1, -1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := &redisCache{log: logger.New("INFO", "")}
			rc.readers = make([]simpleredis.SimpleRedis, tt.readers)
			for call, want := range tt.want {
				if got := indexOfReader(rc, rc.nextReader()); got != want {
					t.Errorf("call %d: nextReader() -> reader[%d], want reader[%d]", call, got, want)
				}
			}
		})
	}
}

// countingCache is an isolated cacheInterface recording how many reads a lookup costs,
// so a CIDR lookup can be checked for both its result and its price.
type countingCache struct {
	values map[string]string
	reads  int
}

func newCountingCache() *countingCache {
	return &countingCache{values: map[string]string{}}
}

func (c *countingCache) get(key string) (string, error) {
	c.reads++
	if value, found := c.values[key]; found && value != "" {
		return value, nil
	}
	return "", errors.New(CacheMiss)
}

func (c *countingCache) set(key, value string, _ int64) {
	c.values[key] = value
}

func (c *countingCache) delete(key string) {
	delete(c.values, key)
}

func newCIDRClient(decisions map[string]string) (*Client, *countingCache) {
	counting := newCountingCache()
	client := &Client{cache: counting, log: logger.New("INFO", "")}
	for cidr, value := range decisions {
		client.SetCIDR(cidr, value, 60)
	}
	return client, counting
}

func Test_GetCIDR(t *testing.T) {
	decisions := map[string]string{
		"10.0.0.0/24":     BannedValue,
		"192.168.1.42/24": CaptchaValue, // not a network address, host bits are dropped
		"2001:db8::/32":   BannedValue,
	}
	tests := []struct {
		name     string
		clientIP string
		want     string
		wantErr  bool
	}{
		{name: "IP inside a banned range", clientIP: "10.0.0.7", want: BannedValue},
		{name: "network address itself", clientIP: "10.0.0.0", want: BannedValue},
		{name: "broadcast address of the range", clientIP: "10.0.0.255", want: BannedValue},
		{name: "IP just outside the range", clientIP: "10.0.1.0", wantErr: true},
		{name: "IP inside a captcha range", clientIP: "192.168.1.7", want: CaptchaValue},
		{name: "IP inside an IPv6 range", clientIP: "2001:db8::dead:beef", want: BannedValue},
		{name: "IP outside the IPv6 range", clientIP: "2001:db9::1", wantErr: true},
		{name: "IPv4 mapped client against an IPv4 range", clientIP: "::ffff:10.0.0.7", want: BannedValue},
		{name: "unknown IP", clientIP: "8.8.8.8", wantErr: true},
		{name: "invalid IP", clientIP: "not-an-ip", wantErr: true},
		{name: "empty IP", clientIP: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := newCIDRClient(decisions)
			got, err := client.GetCIDR(tt.clientIP)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GetCIDR(%q) error = %v, wantErr %v", tt.clientIP, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("GetCIDR(%q) = %q, want %q", tt.clientIP, got, tt.want)
			}
		})
	}
}

// Test_GetCIDR_MostSpecific pins precedence: the narrowest range wins, so a captcha on
// a /24 is not overruled by a ban on its /8.
func Test_GetCIDR_MostSpecific(t *testing.T) {
	client, _ := newCIDRClient(map[string]string{
		"10.0.0.0/8":    BannedValue,
		"10.1.0.0/16":   CaptchaValue,
		"10.1.2.0/24":   BannedValue,
		"2001:db8::/32": BannedValue,
		"2001:db8::/48": CaptchaValue,
	})
	tests := []struct {
		clientIP string
		want     string
	}{
		{clientIP: "10.1.2.3", want: BannedValue},
		{clientIP: "10.1.3.3", want: CaptchaValue},
		{clientIP: "10.2.3.4", want: BannedValue},
		{clientIP: "2001:db8::1", want: CaptchaValue},
		{clientIP: "2001:db8:1::1", want: BannedValue},
	}
	for _, tt := range tests {
		t.Run(tt.clientIP, func(t *testing.T) {
			got, err := client.GetCIDR(tt.clientIP)
			if err != nil {
				t.Fatalf("GetCIDR(%q) unexpected error %v", tt.clientIP, err)
			}
			if got != tt.want {
				t.Errorf("GetCIDR(%q) = %q, want %q", tt.clientIP, got, tt.want)
			}
		})
	}
}

func Test_DeleteCIDR(t *testing.T) {
	client, _ := newCIDRClient(map[string]string{
		"10.0.0.0/8":  BannedValue,
		"10.1.2.0/24": CaptchaValue,
	})
	client.DeleteCIDR("10.1.2.0/24")
	// The wider decision is untouched and takes over.
	if got, err := client.GetCIDR("10.1.2.3"); err != nil || got != BannedValue {
		t.Errorf("after deleting the /24, GetCIDR = %q %v, want %q", got, err, BannedValue)
	}
	client.DeleteCIDR("10.0.0.0/8")
	if _, err := client.GetCIDR("10.1.2.3"); err == nil {
		t.Error("GetCIDR should miss once every decision is deleted")
	}
}

func Test_SetCIDR_InvalidIsNotStored(t *testing.T) {
	for _, cidr := range []string{"", "garbage", "10.0.0.1", "10.0.0.0/33", "10.0.0.0/-1"} {
		t.Run(cidr, func(t *testing.T) {
			_, counting := newCIDRClient(map[string]string{cidr: BannedValue})
			if len(counting.values) != 0 {
				t.Errorf("SetCIDR(%q) stored %v, want nothing", cidr, counting.values)
			}
		})
	}
}

// Test_GetCIDR_Reads guards the cost of the lookup: it must probe only the prefix
// lengths that have a decision, not every possible one.
func Test_GetCIDR_Reads(t *testing.T) {
	tests := []struct {
		name      string
		decisions map[string]string
		clientIP  string
		wantReads int
	}{
		{name: "no decision at all, IPv4", decisions: nil, clientIP: "10.0.0.1", wantReads: 1},
		{name: "no decision at all, IPv6", decisions: nil, clientIP: "2001:db8::1", wantReads: 1},
		{
			name:      "one prefix length, hit",
			decisions: map[string]string{"10.0.0.0/24": BannedValue},
			clientIP:  "10.0.0.1",
			wantReads: 2,
		},
		{
			name:      "one prefix length, miss",
			decisions: map[string]string{"10.0.0.0/24": BannedValue},
			clientIP:  "11.0.0.1",
			wantReads: 2,
		},
		{
			name:      "three prefix lengths, miss probes each once",
			decisions: map[string]string{"10.0.0.0/8": BannedValue, "10.1.0.0/16": BannedValue, "10.1.2.0/24": BannedValue},
			clientIP:  "11.0.0.1",
			wantReads: 4,
		},
		{
			name:      "IPv6 client does not probe every length",
			decisions: map[string]string{"2001:db8::/32": BannedValue},
			clientIP:  "2001:dead::1",
			wantReads: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, counting := newCIDRClient(tt.decisions)
			counting.reads = 0
			// Only the number of reads matters here, the result is covered above.
			_, _ = client.GetCIDR(tt.clientIP)
			if counting.reads != tt.wantReads {
				t.Errorf("GetCIDR(%q) did %d cache reads, want %d", tt.clientIP, counting.reads, tt.wantReads)
			}
		})
	}
}
