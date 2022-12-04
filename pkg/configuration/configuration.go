// Package configuration implements plugin Config, default Config values and validation param functions.
package configuration

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"

	ip "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/ip"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// Enums for crowdsec mode.
const (
	StreamMode              = "stream"
	LiveMode                = "live"
	NoneMode                = "none"
)

// Config the plugin configuration.
type Config struct {
	Enabled                                  bool     `json:"enabled,omitempty"`
	LogLevel                                 string   `json:"logLevel,omitempty"`
	CrowdsecMode                             string   `json:"crowdsecMode,omitempty"`
	CrowdsecLapiScheme                       string   `json:"crowdsecLapiScheme,omitempty"`
	CrowdsecLapiHost                         string   `json:"crowdsecLapiHost,omitempty"`
	CrowdsecLapiKey                          string   `json:"crowdsecLapiKey,omitempty"`
	CrowdsecLapiKeyFile                      string   `json:"crowdsecLapiKeyFile,omitempty"`
	CrowdsecLapiTLSInsecureVerify            bool     `json:"crowdsecLapiTlsInsecureVerify,omitempty"`
	CrowdsecLapiTLSCertificateAuthority      string   `json:"crowdsecLapiTlsCertificateAuthority,omitempty"`
	CrowdsecLapiTLSCertificateAuthorityFile  string   `json:"crowdsecLapiTlsCertificateAuthorityFile,omitempty"`
	CrowdsecLapiTLSCertificateBouncer        string   `json:"crowdsecLapiTlsCertificateBouncer,omitempty"`
	CrowdsecLapiTLSCertificateBouncerFile    string   `json:"crowdsecLapiTlsCertificateBouncerFile,omitempty"`
	CrowdsecLapiTLSCertificateBouncerKey     string   `json:"crowdsecLapiTlsCertificateBouncerKey,omitempty"`
	CrowdsecLapiTLSCertificateBouncerKeyFile string   `json:"crowdsecLapiTlsCertificateBouncerKeyFile,omitempty"`
	UpdateIntervalSeconds                    int64    `json:"updateIntervalSeconds,omitempty"`
	DefaultDecisionSeconds                   int64    `json:"defaultDecisionSeconds,omitempty"`
	ForwardedHeadersCustomName               string   `json:"forwardedheaderscustomheader,omitempty"`
	ForwardedHeadersTrustedIPs               []string `json:"forwardedHeadersTrustedIps,omitempty"`
	ClientTrustedIPs                         []string `json:"clientTrustedIps,omitempty"`
	RedisCacheEnabled                        bool     `json:"redisCacheEnabled,omitempty"`
	RedisCacheHost                           string   `json:"redisCacheHost,omitempty"`
}

func contains(source []string, target string) bool {
	for _, item := range source {
		if item == target {
			return true
		}
	}
	return false
}

// New creates the default plugin configuration.
func New() *Config {
	return &Config{
		Enabled:                       false,
		LogLevel:                      "INFO",
		CrowdsecMode:                  LiveMode,
		CrowdsecLapiScheme:            "http",
		CrowdsecLapiHost:              "crowdsec:8080",
		CrowdsecLapiKey:               "",
		CrowdsecLapiTLSInsecureVerify: false,
		UpdateIntervalSeconds:         60,
		DefaultDecisionSeconds:        60,
		ForwardedHeadersCustomName:    "X-Forwarded-For",
		ForwardedHeadersTrustedIPs:    []string{},
		ClientTrustedIPs:              []string{},
		RedisCacheEnabled:             false,
		RedisCacheHost:                "redis:6379",
	}
}

// GetVariable get variable from file and after in the variables gave by user.
func GetVariable(config *Config, key string) (string, error) {
	value := ""
	object := reflect.Indirect(reflect.ValueOf(config))
	field := object.FieldByName(fmt.Sprintf("%sFile", key))
	// Here linter say you should simplify this code, but lets not, performance is important not clarity and complexity
	fp := field.String()
	if fp != "" {
		file, err := os.Stat(fp)
		if err != nil {
			return value, fmt.Errorf("%s:%s invalid path %w", key, fp, err)
		}
		if file.IsDir() {
			return value, fmt.Errorf("%s:%s path must be a file", key, fp)
		}
		fileValue, err := os.ReadFile(filepath.Clean(fp))
		if err != nil {
			return value, fmt.Errorf("%s:%s read file path failed %w", key, fp, err)
		}
		value = string(fileValue)
		return value, nil
	}
	field = object.FieldByName(key)
	value = field.String()
	return value, nil
}

// ValidateParams validate all the param gave by user.
func ValidateParams(config *Config) error {
	if err := validateParamsRequired(config); err != nil {
		return err
	}

	// This only check that the format of the URL scheme:// is correct and do not make requests
	testURL := url.URL{
		Scheme: config.CrowdsecLapiScheme,
		Host:   config.CrowdsecLapiHost,
	}
	if _, err := http.NewRequest(http.MethodGet, testURL.String(), nil); err != nil {
		return fmt.Errorf("CrowdsecLapiScheme://CrowdsecLapiHost: '%v://%v' must be an URL", config.CrowdsecLapiScheme, config.CrowdsecLapiHost)
	}

	if err := validateParamsIPs(config.ForwardedHeadersTrustedIPs, "ForwardedHeadersTrustedIPs"); err != nil {
		return err
	}
	if err := validateParamsIPs(config.ClientTrustedIPs, "ClientTrustedIPs"); err != nil {
		return err
	}

	lapiKey, err := GetVariable(config, "CrowdsecLapiKey")
	if err != nil {
		return err
	}
	certBouncer, err := GetVariable(config, "CrowdsecLapiTLSCertificateBouncer")
	if err != nil {
		return err
	}
	certBouncerKey, err := GetVariable(config, "CrowdsecLapiTLSCertificateBouncerKey")
	if err != nil {
		return err
	}
	// We need to either have crowdsecLapiKey defined or the BouncerCert and Bouncerkey
	if lapiKey == "" && (certBouncer == "" || certBouncerKey == "") {
		return fmt.Errorf("CrowdsecLapiKey || (CrowdsecLapiTLSCertificateBouncer && CrowdsecLapiTLSCertificateBouncerKey): cannot be both empty")
	}

	// Case https to contact Crowdsec LAPI and certificate must be provided
	if config.CrowdsecLapiScheme == "https" && !config.CrowdsecLapiTLSInsecureVerify {
		err = validateParamsTLS(config)
		if err != nil {
			return err
		}
	}

	return nil
}

func validateParamsTLS(config *Config) error {
	certAuth, err := GetVariable(config, "CrowdsecLapiTLSCertificateAuthority")
	if err != nil {
		return err
	}
	if certAuth == "" {
		return fmt.Errorf("CrowdsecLapiTLSCertificateAuthority must be specified when CrowdsecLapiScheme='https' and CrowdsecLapiTLSInsecureVerify=false")
	}
	tlsConfig := new(tls.Config)
	tlsConfig.RootCAs = x509.NewCertPool()
	if !tlsConfig.RootCAs.AppendCertsFromPEM([]byte(certAuth)) {
		return fmt.Errorf("failed parsing pem file")
	}
	return nil
}

func validateParamsIPs(listIP []string, key string) error {
	if len(listIP) > 0 {
		if _, err := ip.NewChecker(listIP); err != nil {
			return fmt.Errorf("%s must be a list of IP/CIDR :%w", key, err)
		}
	} else {
		logger.Debug(fmt.Sprintf("No IP provided for %s", key))
	}
	return nil
}

func validateParamsRequired(config *Config) error {
	requiredStrings := map[string]string{
		"CrowdsecLapiScheme": config.CrowdsecLapiScheme,
		"CrowdsecLapiHost":   config.CrowdsecLapiHost,
		"CrowdsecMode":       config.CrowdsecMode,
	}
	for key, val := range requiredStrings {
		if len(val) == 0 {
			return fmt.Errorf("%v: cannot be empty", key)
		}
	}
	requiredInt := map[string]int64{
		"UpdateIntervalSeconds":  config.UpdateIntervalSeconds,
		"DefaultDecisionSeconds": config.DefaultDecisionSeconds,
	}
	for key, val := range requiredInt {
		if val < 1 {
			return fmt.Errorf("%v: cannot be less than 1", key)
		}
	}
	if !contains([]string{NoneMode, LiveMode, StreamMode}, config.CrowdsecMode) {
		return fmt.Errorf("CrowdsecMode: must be one of 'none', 'live' or 'stream'")
	}
	if !contains([]string{"http", "https"}, config.CrowdsecLapiScheme) {
		return fmt.Errorf("CrowdsecLapiScheme: must be one of 'http' or 'https'")
	}
	return nil
}
