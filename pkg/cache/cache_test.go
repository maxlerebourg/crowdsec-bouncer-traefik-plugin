// Package cache implements utility routines for manipulating cache.
// It supports currently local file and redis cache.
package cache

import (
	"testing"

	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func Test_Get(t *testing.T) {
	IPInCache := "10.0.0.10"
	IPNotInCache := "10.0.0.20"
	client := &Client{cache: &localCache{}, log: logger.New("INFO")}
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
	client := &Client{cache: &localCache{}, log: logger.New("INFO")}
	IPInCache := "10.0.0.11"
	type args struct {
		clientIP string
		value    string
		duration int64
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{name: "Set valid IP in local cache for 0 sec", args: args{clientIP: IPInCache, value: BannedValue, duration: 0}, want: NoBannedValue},
		{name: "Set valid IP in local cache for 10 sec", args: args{clientIP: IPInCache, value: BannedValue, duration: 10}, want: BannedValue},
		{name: "Set valid IP in local cache for 10 sec", args: args{clientIP: IPInCache, value: NoBannedValue, duration: 10}, want: NoBannedValue},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client.Set(tt.args.clientIP, tt.args.value, tt.args.duration)
			got, _ := client.Get(tt.args.clientIP)
			if got != tt.want {
				t.Errorf("Set() = %v, want %v", got, tt.want)
				return
			}
		})
	}
}

func Test_Delete(t *testing.T) {
	IPInCache := "10.0.0.12"
	IPNotInCache := "10.0.0.22"
	client := &Client{cache: &localCache{}, log: logger.New("INFO")}
	client.Set(IPInCache, BannedValue, 10)
	type args struct {
		clientIP string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{name: "Delete Known valid IP", args: args{clientIP: IPInCache}, want: NoBannedValue},
		{name: "Delete Unknown valid IP", args: args{clientIP: IPNotInCache}, want: NoBannedValue},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client.Delete(tt.args.clientIP)
			got, _ := client.Get(tt.args.clientIP)
			if got != tt.want {
				t.Errorf("Delete() = %v, want %v", got, tt.want)
				return
			}
		})
	}
}
