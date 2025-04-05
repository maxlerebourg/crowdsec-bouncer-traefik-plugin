package configuration

import (
	"crypto/tls"
	"reflect"
	"testing"

	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func getMinimalConfig() *Config {
	cfg := New()
	cfg.CrowdsecLapiKey = "test"
	return cfg
}

func Test_contains(t *testing.T) {
	type args struct {
		source []string
		target string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{name: "Contain in the list", args: args{source: []string{"a", "b"}, target: "a"}, want: true},
		{name: "Contain not in the list", args: args{source: []string{"a", "b"}, target: "c"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := contains(tt.args.source, tt.args.target); got != tt.want {
				t.Errorf("contains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_GetVariable(t *testing.T) {
	cfg1 := New()
	cfg1.CrowdsecLapiKey = "test"
	cfg2 := New()
	cfg2.CrowdsecLapiKeyFile = "../../tests/.keytest"
	cfg3 := New()
	cfg3.CrowdsecLapiKeyFile = "../../tests/.bad"
	type args struct {
		config *Config
		key    string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{name: "Validate a key string", args: args{config: cfg1, key: "CrowdsecLapiKey"}, want: "test", wantErr: false},
		{name: "Validate a key file", args: args{config: cfg2, key: "CrowdsecLapiKey"}, want: "test", wantErr: false},
		{name: "Not validate an invalid file", args: args{config: cfg3, key: "CrowdsecLapiKey"}, want: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetVariable(tt.args.config, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("getVariable() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getVariable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ValidateParams(t *testing.T) {
	cfg1 := New()
	cfg1.CrowdsecLapiKey = "test\n\n"
	cfg2 := New()
	cfg2.CrowdsecLapiKey = "test@"
	cfg3 := getMinimalConfig()
	cfg3.CrowdsecMode = "bad"
	cfg4 := getMinimalConfig()
	cfg4.UpdateIntervalSeconds = 0
	cfg5 := getMinimalConfig()
	cfg5.ClientTrustedIPs = []string{0: "bad"}
	cfg6 := getMinimalConfig()
	cfg6.CrowdsecLapiScheme = HTTPS
	cfg6.CrowdsecLapiTLSInsecureVerify = true
	cfg7 := getMinimalConfig()
	cfg7.CrowdsecLapiScheme = HTTPS
	cfg8 := getMinimalConfig()
	cfg8.LogLevel = LogINFO
	cfg9 := getMinimalConfig()
	cfg9.LogLevel = "info"
	cfg10 := getMinimalConfig()
	cfg10.LogLevel = "Warning"
	type args struct {
		config *Config
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "Validate minimal config", args: args{config: getMinimalConfig()}, wantErr: false},
		{name: "Validate a non trimed crowdsec lapi key", args: args{config: cfg1}, wantErr: false},
		{name: "Not validate unauthorized character in crowdsec lapi key", args: args{config: cfg2}, wantErr: true},
		{name: "Not validate an absent crowdsec lapi key", args: args{config: New()}, wantErr: true},
		{name: "Not validate a not listed item", args: args{config: cfg3}, wantErr: true},
		{name: "Not validate a bad number", args: args{config: cfg4}, wantErr: true},
		{name: "Not validate a bad clients ips", args: args{config: cfg5}, wantErr: true},
		// HTTPS enabled
		{name: "Validate https config with insecure verify", args: args{config: cfg6}, wantErr: false},
		{name: "Not validate https without cert authority", args: args{config: cfg7}, wantErr: true},
		{name: "Valid log level uppercase INFO", args: args{config: cfg8}, wantErr: false},
		{name: "Valid log level lowercase info", args: args{config: cfg9}, wantErr: false},
		{name: "Invalid log level Warning", args: args{config: cfg10}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateParams(tt.args.config); (err != nil) != tt.wantErr {
				t.Errorf("validateParams() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_validateParamsTLS(t *testing.T) {
	type args struct {
		config *Config
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateParamsTLS(tt.args.config); (err != nil) != tt.wantErr {
				t.Errorf("validateParamsTLS() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_validateParamsIPs(t *testing.T) {
	type args struct {
		listIP []string
		key    string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "Not validate a non ip", args: args{listIP: []string{0: "bad"}}, wantErr: true},
		{name: "Not validate localhost", args: args{listIP: []string{0: "localhost"}}, wantErr: true},
		{name: "Not validate a weird ip", args: args{listIP: []string{0: "0.0.0.0/89"}}, wantErr: true},
		{name: "Not validate a weird ip 2", args: args{listIP: []string{0: "0.0.0.256/12"}}, wantErr: true},
		{name: "Validate an ip not trimmed", args: args{listIP: []string{0: " 0.0.0.0/0"}}, wantErr: false},
		{name: "Validate an ip", args: args{listIP: []string{0: "0.0.0.0/12"}}, wantErr: false},
		{name: "Validate an ip list", args: args{listIP: []string{0: "0.0.0.0/0", 1: "1.1.1.1/1"}}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateParamsIPs(tt.args.listIP, tt.args.key); (err != nil) != tt.wantErr {
				t.Errorf("validateParamsIPs() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_validateParamsRequired(t *testing.T) {
	cfg2 := getMinimalConfig()
	cfg2.CrowdsecLapiScheme = "bad"
	cfg3 := getMinimalConfig()
	cfg3.CrowdsecMode = "bad"
	cfg4 := getMinimalConfig()
	cfg4.UpdateIntervalSeconds = 0
	cfg5 := getMinimalConfig()
	cfg5.DefaultDecisionSeconds = 0
	type args struct {
		config *Config
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "Validate minimal config", args: args{config: getMinimalConfig()}, wantErr: false},
		{name: "Not validate a bad crowdsec scheme", args: args{config: cfg2}, wantErr: true},
		{name: "Not validate a bad crowdsec mode", args: args{config: cfg3}, wantErr: true},
		{name: "Not validate a bad update interval seconds", args: args{config: cfg4}, wantErr: true},
		{name: "Not validate a bad default decision seconds", args: args{config: cfg5}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateParamsRequired(tt.args.config); (err != nil) != tt.wantErr {
				t.Errorf("validateParamsRequired() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_validateParamsAPIKey(t *testing.T) {
	type args struct {
		lapiKey string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "Validate all the valid characters", args: args{lapiKey: "test!#$%&'*+-.^_`|~"}, wantErr: false},
		{name: "Not validate a @", args: args{lapiKey: "test@"}, wantErr: true},
		{name: "Not validate a (", args: args{lapiKey: "test("}, wantErr: true},
		{name: "Not validate a [", args: args{lapiKey: "test["}, wantErr: true},
		{name: "Not validate a ?", args: args{lapiKey: "test?"}, wantErr: true},
		{name: "Not validate a \\n, (must be trimed before)", args: args{lapiKey: "test\n"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateParamsAPIKey(tt.args.lapiKey); (err != nil) != tt.wantErr {
				t.Errorf("validateParamsAPIKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_GetTLSConfigCrowdsec(t *testing.T) {
	type args struct {
		config *Config
	}
	tests := []struct {
		name    string
		args    args
		want    *tls.Config
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetTLSConfigCrowdsec(tt.args.config, logger.New("INFO", ""))
			if (err != nil) != tt.wantErr {
				t.Errorf("getTLSConfigCrowdsec() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getTLSConfigCrowdsec() = %v, want %v", got, tt.want)
			}
		})
	}
}
