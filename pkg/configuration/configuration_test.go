package configuration

import (
	"testing"

	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// validPEM is a minimal self-signed certificate accepted by AppendCertsFromPEM,
// shared by the TLS tests below.
const validPEM = `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`

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
	log := logger.New("INFO", "")
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
		{name: "Validate https without cert authority (falls back to system trust store)", args: args{config: cfg7}, wantErr: false},
		{name: "Valid log level uppercase INFO", args: args{config: cfg8}, wantErr: false},
		{name: "Valid log level lowercase info", args: args{config: cfg9}, wantErr: false},
		{name: "Invalid log level Warning", args: args{config: cfg10}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateParams(tt.args.config, log); (err != nil) != tt.wantErr {
				t.Errorf("validateParams() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_validateParamsTLS(t *testing.T) {
	cfgEmpty := getMinimalConfig()
	cfgValid := getMinimalConfig()
	cfgValid.CrowdsecLapiTLSCertificateAuthority = validPEM
	cfgInvalidCA := getMinimalConfig()
	cfgInvalidCA.CrowdsecLapiTLSCertificateAuthority = "not a pem"

	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{name: "Empty CA is accepted (system trust store used at runtime)", config: cfgEmpty, wantErr: false},
		{name: "Valid PEM CA is accepted", config: cfgValid, wantErr: false},
		{name: "Invalid CA is rejected", config: cfgInvalidCA, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateParamsTLS(tt.config); (err != nil) != tt.wantErr {
				t.Errorf("validateParamsTLS() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_validateParamsIPs(t *testing.T) {
	log := logger.New("INFO", "")
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
			if err := validateParamsIPs(log, tt.args.listIP, tt.args.key); (err != nil) != tt.wantErr {
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
		lapiKey   string
		paramName string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "Validate all the valid characters", args: args{lapiKey: "test!#$%&'*+-.^_`|~", paramName: "CrowdsecParamName"}, wantErr: false},
		{name: "Not validate a @", args: args{lapiKey: "test@", paramName: "CrowdsecParamName"}, wantErr: true},
		{name: "Not validate a (", args: args{lapiKey: "test(", paramName: "CrowdsecParamName"}, wantErr: true},
		{name: "Not validate a [", args: args{lapiKey: "test[", paramName: "CrowdsecParamName"}, wantErr: true},
		{name: "Not validate a ?", args: args{lapiKey: "test?", paramName: "CrowdsecParamName"}, wantErr: true},
		{name: "Not validate a \\n, (must be trimed before)", args: args{lapiKey: "test\n", paramName: "CrowdsecParamName"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateParamsAPIKey(tt.args.lapiKey, tt.args.paramName); (err != nil) != tt.wantErr {
				t.Errorf("validateParamsAPIKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_GetTLSConfigCrowdsec(t *testing.T) {
	log := logger.New("INFO", "")

	httpCfg := getMinimalConfig()
	httpCfg.CrowdsecLapiScheme = HTTP

	httpsSystemCA := getMinimalConfig()
	httpsSystemCA.CrowdsecLapiScheme = HTTPS

	httpsCustomCA := getMinimalConfig()
	httpsCustomCA.CrowdsecLapiScheme = HTTPS
	httpsCustomCA.CrowdsecLapiTLSCertificateAuthority = validPEM

	httpsInsecure := getMinimalConfig()
	httpsInsecure.CrowdsecLapiScheme = HTTPS
	httpsInsecure.CrowdsecLapiTLSInsecureVerify = true

	httpsBadCA := getMinimalConfig()
	httpsBadCA.CrowdsecLapiScheme = HTTPS
	httpsBadCA.CrowdsecLapiTLSCertificateAuthority = "not a pem"

	tests := []struct {
		name             string
		config           *Config
		wantErr          bool
		wantRootCAsNil   bool
		wantInsecureSkip bool
	}{
		{name: "HTTP scheme returns empty tls.Config", config: httpCfg, wantRootCAsNil: true},
		{name: "HTTPS without CA leaves RootCAs nil (system trust store)", config: httpsSystemCA, wantRootCAsNil: true},
		{name: "HTTPS with custom CA populates RootCAs", config: httpsCustomCA, wantRootCAsNil: false},
		{name: "HTTPS with insecure verify sets InsecureSkipVerify", config: httpsInsecure, wantRootCAsNil: true, wantInsecureSkip: true},
		{name: "HTTPS with garbage CA is rejected", config: httpsBadCA, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetTLSConfigCrowdsec(tt.config, log, false)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetTLSConfigCrowdsec() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if (got.RootCAs == nil) != tt.wantRootCAsNil {
				t.Errorf("GetTLSConfigCrowdsec() RootCAs nil = %v, want nil = %v", got.RootCAs == nil, tt.wantRootCAsNil)
			}
			if got.InsecureSkipVerify != tt.wantInsecureSkip {
				t.Errorf("GetTLSConfigCrowdsec() InsecureSkipVerify = %v, want %v", got.InsecureSkipVerify, tt.wantInsecureSkip)
			}
		})
	}
}
