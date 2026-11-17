// Package cache implements utility routines for manipulating cache.
// It supports currently local file and redis cache.
package cache

import (
	"testing"
	"time"

	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
	simpleredis "github.com/maxlerebourg/simpleredis"
)

func Test_Get(t *testing.T) {
	IPInCache := "10.0.0.10"
	IPNotInCache := "10.0.0.20"
	client := &Client{cache: &localCache{}, log: logger.New("INFO", "")}
	client.Set(IPInCache, BannedValue, 10, time.Time{})
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
			client.Set(tt.args.clientIP, tt.args.value, tt.args.duration, time.Time{})
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
	client.Set(IPInCache, BannedValue, 10, time.Time{})
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

func Test_SetEnd(t *testing.T) {
	client := &Client{cache: &localCache{}, log: logger.New("INFO", "")}
	end := time.UnixMilli(time.Now().Add(time.Hour).UnixMilli())
	client.Set("10.0.0.30", BannedValue, 10, end)

	value, gotEnd, err := client.GetDecision("10.0.0.30")
	if err != nil || value != BannedValue || !gotEnd.Equal(end) {
		t.Errorf("GetDecision() = %q, %v, %v, want %q, %v", value, gotEnd, err, BannedValue, end)
	}
	if value, err := client.Get("10.0.0.30"); err != nil || value != BannedValue {
		t.Errorf("Get() = %q, %v, want the value without its end", value, err)
	}

	client.Set("10.0.0.31", CaptchaValue, 10, end)
	if raw, err := client.cache.get("10.0.0.31"); err != nil || raw != CaptchaValue {
		t.Errorf("a captcha is cached as %q, %v, want %q as earlier versions read it", raw, err, CaptchaValue)
	}

	client.Set("10.0.0.32", BannedValue, 10, time.Time{})
	if value, gotEnd, err := client.GetDecision("10.0.0.32"); err != nil || value != BannedValue || !gotEnd.IsZero() {
		t.Errorf("GetDecision() of a value cached without an end = %q, %v, %v", value, gotEnd, err)
	}

	client.cache.set("10.0.0.33", BannedValue+decisionEndSeparator+"soon", 10)
	if value, gotEnd, err := client.GetDecision("10.0.0.33"); err != nil || value != BannedValue || !gotEnd.IsZero() {
		t.Errorf("GetDecision() of an unreadable end = %q, %v, %v", value, gotEnd, err)
	}

	if _, _, err := client.GetDecision("10.0.0.34"); err == nil || err.Error() != CacheMiss {
		t.Errorf("GetDecision() of a missing key error = %v, want %s", err, CacheMiss)
	}
}
