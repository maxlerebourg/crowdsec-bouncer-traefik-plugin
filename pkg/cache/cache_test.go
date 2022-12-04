// Package cache implements utility routines for manipulating cache.
// It supports currently local file and redis cache.
package cache

import (
	"errors"
	"testing"
)

func Test_getDecisionLocalCache(t *testing.T) {
	IPInCache := "10.0.0.10"
	IPNotInCache := "10.0.0.20"
	setDecisionLocalCache(IPInCache, "t", 10)
	type args struct {
		clientIP string
	}
	tests := []struct {
		name     string
		args     args
		want     bool
		wantErr  bool
		valueErr error
	}{
		{name: "Fetch Known valid IP", args: args{clientIP: IPInCache}, want: true, wantErr: false, valueErr: nil},
		{name: "Fetch Unknown valid IP", args: args{clientIP: IPNotInCache}, want: false, wantErr: true, valueErr: errors.New("cache:miss")},
		{name: "Fetch invalid value", args: args{clientIP: "zaeaea"}, want: false, wantErr: true, valueErr: errors.New("cache:miss")},
		{name: "Fetch empty value", args: args{clientIP: ""}, want: false, wantErr: true, valueErr: errors.New("cache:miss")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getDecisionLocalCache(tt.args.clientIP)
			if (err != nil) != tt.wantErr {
				t.Errorf("getDecisionLocalCache() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getDecisionLocalCache() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_setDecisionLocalCache(t *testing.T) {
	IPInCache := "10.0.0.10"
	type args struct {
		clientIP string
		value    string
		duration int64
	}
	tests := []struct {
		name string
		args args
	}{
		{name: "Set valid IP in local cache as t", args: args{clientIP: IPInCache, value: "t", duration: 0}},
		{name: "Set valid IP in local cache as f", args: args{clientIP: IPInCache, value: "f", duration: 0}},
		{name: "Set valid IP in local cache as empty str", args: args{clientIP: IPInCache, value: "", duration: 0}},
		{name: "Set valid IP in local cache as f for -1 sec", args: args{clientIP: IPInCache, value: "f", duration: -1}},
		{name: "Set valid IP in local cache as f for 10 sec", args: args{clientIP: IPInCache, value: "f", duration: 10}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setDecisionLocalCache(tt.args.clientIP, tt.args.value, tt.args.duration)
		})
	}
}

func Test_deleteDecisionLocalCache(t *testing.T) {
	type args struct {
		clientIP string
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deleteDecisionLocalCache(tt.args.clientIP)
		})
	}
}

func Test_getDecisionRedisCache(t *testing.T) {
	type args struct {
		clientIP string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getDecisionRedisCache(tt.args.clientIP)
			if (err != nil) != tt.wantErr {
				t.Errorf("getDecisionRedisCache() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getDecisionRedisCache() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_setDecisionRedisCache(t *testing.T) {
	type args struct {
		clientIP string
		value    string
		duration int64
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setDecisionRedisCache(tt.args.clientIP, tt.args.value, tt.args.duration)
		})
	}
}

func Test_deleteDecisionRedisCache(t *testing.T) {
	type args struct {
		clientIP string
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deleteDecisionRedisCache(tt.args.clientIP)
		})
	}
}

func TestDeleteDecision(t *testing.T) {
	type args struct {
		clientIP string
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			DeleteDecision(tt.args.clientIP)
		})
	}
}

func TestGetDecision(t *testing.T) {
	type args struct {
		clientIP string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetDecision(tt.args.clientIP)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetDecision() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetDecision() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSetDecision(t *testing.T) {
	type args struct {
		clientIP string
		isBanned bool
		duration int64
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetDecision(tt.args.clientIP, tt.args.isBanned, tt.args.duration)
		})
	}
}

func TestInitRedisClient(t *testing.T) {
	type args struct {
		host string
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			InitRedisClient(tt.args.host)
		})
	}
}
