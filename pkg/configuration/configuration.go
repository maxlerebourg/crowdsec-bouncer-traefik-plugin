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
	"regexp"
	"strings"

	ip "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/ip"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// Enums for crowdsec mode.
const (
	AloneMode  = "alone"
	StreamMode = "stream"
	LiveMode   = "live"
	NoneMode   = "none"
	HTTPS      = "https"
	HTTP       = "http"
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
	CrowdsecCapiMachineID                    string   `json:"crowdsecCapiMachineId,omitempty"`
	CrowdsecCapiMachineIDFile                string   `json:"crowdsecCapiMachineIdFile,omitempty"`
	CrowdsecCapiPassword                     string   `json:"crowdsecCapiPassword,omitempty"`
	CrowdsecCapiPasswordFile                 string   `json:"crowdsecCapiPasswordFile,omitempty"`
	CrowdsecCapiScenarios                    []string `json:"crowdsecCapiScenarios,omitempty"`
	UpdateIntervalSeconds                    int64    `json:"updateIntervalSeconds,omitempty"`
	DefaultDecisionSeconds                   int64    `json:"defaultDecisionSeconds,omitempty"`
	HTTPTimeoutSeconds                       int64    `json:"httpTimeoutSeconds,omitempty"`
	ForwardedHeadersCustomName               string   `json:"forwardedheaderscustomheader,omitempty"`
	ForwardedHeadersTrustedIPs               []string `json:"forwardedHeadersTrustedIps,omitempty"`
	ClientTrustedIPs                         []string `json:"clientTrustedIps,omitempty"`
	RedisCacheEnabled                        bool     `json:"redisCacheEnabled,omitempty"`
	RedisCacheHost                           string   `json:"redisCacheHost,omitempty"`
	RedisCachePassword                       string   `json:"redisCachePassword,omitempty"`
	RedisCachePasswordFile                   string   `json:"redisCachePasswordFile,omitempty"`
	RedisCacheDatabase                       string   `json:"redisCacheDatabase,omitempty"`
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
		CrowdsecLapiScheme:            HTTP,
		CrowdsecLapiHost:              "crowdsec:8080",
		CrowdsecLapiKey:               "",
		CrowdsecLapiTLSInsecureVerify: false,
		UpdateIntervalSeconds:         60,
		DefaultDecisionSeconds:        60,
		HTTPTimeoutSeconds:            10,
		ForwardedHeadersCustomName:    "X-Forwarded-For",
		ForwardedHeadersTrustedIPs:    []string{},
		ClientTrustedIPs:              []string{},
		RedisCacheEnabled:             false,
		RedisCacheHost:                "redis:6379",
		RedisCachePassword:            "",
		RedisCacheDatabase:            "",
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
		return strings.TrimSpace(value), nil
	}
	field = object.FieldByName(key)
	value = field.String()
	return strings.TrimSpace(value), nil
}

// ValidateParams validate all the param gave by user.
//
//nolint:gocyclo,gocognit
func ValidateParams(config *Config) error {
	if err := validateParamsRequired(config); err != nil {
		return err
	}

	if err := validateParamsIPs(config.ForwardedHeadersTrustedIPs, "ForwardedHeadersTrustedIPs"); err != nil {
		return err
	}
	if err := validateParamsIPs(config.ClientTrustedIPs, "ClientTrustedIPs"); err != nil {
		return err
	}

	if _, err := GetVariable(config, "RedisCachePassword"); err != nil {
		return err
	}

	if config.CrowdsecMode == AloneMode {
		if _, err := GetVariable(config, "CrowdsecCapiMachineID"); err != nil {
			return err
		}
		if _, err := GetVariable(config, "CrowdsecCapiPassword"); err != nil {
			return err
		}
		return nil
	}

	// This only check that the format of the URL scheme:// is correct and do not make requests
	testURL := url.URL{
		Scheme: config.CrowdsecLapiScheme,
		Host:   config.CrowdsecLapiHost,
	}
	if _, err := http.NewRequest(http.MethodGet, testURL.String(), nil); err != nil {
		return fmt.Errorf("CrowdsecLapiScheme://CrowdsecLapiHost: '%v://%v' must be an URL", config.CrowdsecLapiScheme, config.CrowdsecLapiHost)
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
		return fmt.Errorf("CrowdsecLapiKey || (CrowdsecLapiTLSCertificateBouncer && CrowdsecLapiTLSCertificateBouncerKey): cannot be all empty")
	} else if lapiKey != "" && (certBouncer == "" || certBouncerKey == "") {
		lapiKey = strings.TrimSpace(lapiKey)
		if err = validateParamsAPIKey(lapiKey); err != nil {
			return err
		}
	}

	// Case https to contact Crowdsec LAPI and certificate must be provided
	if config.CrowdsecLapiScheme == HTTPS && !config.CrowdsecLapiTLSInsecureVerify {
		if err = validateParamsTLS(config); err != nil {
			return err
		}
	}

	return nil
}

// validHeaderFieldByte reports whether b is a valid byte in a header
// field name. RFC 7230 says:
// valid ! # $ % & ' * + - . ^ _ ` | ~ DIGIT ALPHA
// See https://httpwg.github.io/specs/rfc7230.html#rule.token.separators
func validateParamsAPIKey(lapiKey string) error {
	reg := regexp.MustCompile("^[a-zA-Z0-9 !#$%&'*+-.^_`|~]*$")
	if !reg.Match([]byte(lapiKey)) {
		return fmt.Errorf("CrowdsecLapiKey doesn't valid this regexp: '/%s/'", reg.String())
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
		"HTTPTimeoutSeconds":     config.HTTPTimeoutSeconds,
	}
	for key, val := range requiredInt {
		if val < 1 {
			return fmt.Errorf("%v: cannot be less than 1", key)
		}
	}
	if !contains([]string{NoneMode, LiveMode, StreamMode, AloneMode}, config.CrowdsecMode) {
		return fmt.Errorf("CrowdsecMode: must be one of 'none', 'live', 'stream' or 'alone'")
	}
	if !contains([]string{HTTP, HTTPS}, config.CrowdsecLapiScheme) {
		return fmt.Errorf("CrowdsecLapiScheme: must be one of 'http' or 'https'")
	}
	return nil
}

// GetTLSConfigCrowdsec get TLS config from Config.
func GetTLSConfigCrowdsec(config *Config) (*tls.Config, error) {
	tlsConfig := new(tls.Config)
	tlsConfig.RootCAs = x509.NewCertPool()
	//nolint:gocritic
	if config.CrowdsecLapiScheme != HTTPS {
		logger.Debug("getTLSConfigCrowdsec:CrowdsecLapiScheme https:no")
		return tlsConfig, nil
	} else if config.CrowdsecLapiTLSInsecureVerify {
		logger.Debug("getTLSConfigCrowdsec:CrowdsecLapiTLSInsecureVerify tlsInsecure:true")
		tlsConfig.InsecureSkipVerify = true
		// If we return here and still want to use client auth this won't work
		// return tlsConfig, nil
	} else {
		certAuthority, err := GetVariable(config, "CrowdsecLapiTLSCertificateAuthority")
		if err != nil {
			return nil, err
		}
		cert := []byte(certAuthority)
		if !tlsConfig.RootCAs.AppendCertsFromPEM(cert) {
			logger.Debug("getTLSConfigCrowdsec:CrowdsecLapiTLSCertificateAuthority read cert failed")
			// here we return because if CrowdsecLapiTLSInsecureVerify is false
			// and CA not load, we can't communicate with https
			return nil, fmt.Errorf("getTLSConfigCrowdsec:cannot load CA and verify cert is enabled")
		}
	}

	certBouncer, err := GetVariable(config, "CrowdsecLapiTLSCertificateBouncer")
	if err != nil {
		return nil, err
	}
	certBouncerKey, err := GetVariable(config, "CrowdsecLapiTLSCertificateBouncerKey")
	if err != nil {
		return nil, err
	}
	if certBouncer == "" || certBouncerKey == "" {
		return tlsConfig, nil
	}
	clientCert, err := tls.X509KeyPair([]byte(certBouncer), []byte(certBouncerKey))
	if err != nil {
		return nil, fmt.Errorf("getTLSClientConfigCrowdsec impossible to generate ClientCert %w", err)
	}
	tlsConfig.Certificates = append(tlsConfig.Certificates, clientCert)

	return tlsConfig, nil
}
