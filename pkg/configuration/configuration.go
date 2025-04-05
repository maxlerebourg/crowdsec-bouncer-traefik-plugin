// Package configuration implements plugin Config, default Config values and validation param functions.
package configuration

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"html/template"
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
	AloneMode         = "alone"
	StreamMode        = "stream"
	LiveMode          = "live"
	NoneMode          = "none"
	AppsecMode        = "appsec"
	HTTPS             = "https"
	HTTP              = "http"
	LogDEBUG          = "DEBUG"
	LogINFO           = "INFO"
	LogERROR          = "ERROR"
	LogTRACE          = "TRACE"
	HcaptchaProvider  = "hcaptcha"
	RecaptchaProvider = "recaptcha"
	TurnstileProvider = "turnstile"
)

// Config the plugin configuration.
type Config struct {
	Enabled                                  bool     `json:"enabled,omitempty"`
	LogLevel                                 string   `json:"logLevel,omitempty"`
	LogFilePath                              string   `json:"logFilePath,omitempty"`
	CrowdsecMode                             string   `json:"crowdsecMode,omitempty"`
	CrowdsecAppsecEnabled                    bool     `json:"crowdsecAppsecEnabled,omitempty"`
	CrowdsecAppsecHost                       string   `json:"crowdsecAppsecHost,omitempty"`
	CrowdsecAppsecPath                       string   `json:"crowdsecAppsecPath,omitempty"`
	CrowdsecAppsecFailureBlock               bool     `json:"crowdsecAppsecFailureBlock,omitempty"`
	CrowdsecAppsecUnreachableBlock           bool     `json:"crowdsecAppsecUnreachableBlock,omitempty"`
	CrowdsecAppsecBodyLimit                  int64    `json:"crowdsecAppsecBodyLimit,omitempty"`
	CrowdsecLapiScheme                       string   `json:"crowdsecLapiScheme,omitempty"`
	CrowdsecLapiHost                         string   `json:"crowdsecLapiHost,omitempty"`
	CrowdsecLapiPath                         string   `json:"crowdsecLapiPath,omitempty"`
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
	MetricsUpdateIntervalSeconds             int64    `json:"metricsUpdateIntervalSeconds,omitempty"`
	UpdateMaxFailure                         int64    `json:"updateMaxFailure,omitempty"`
	DefaultDecisionSeconds                   int64    `json:"defaultDecisionSeconds,omitempty"`
	HTTPTimeoutSeconds                       int64    `json:"httpTimeoutSeconds,omitempty"`
	RemediationHeadersCustomName             string   `json:"remediationHeadersCustomName,omitempty"`
	ForwardedHeadersCustomName               string   `json:"forwardedHeadersCustomName,omitempty"`
	ForwardedHeadersTrustedIPs               []string `json:"forwardedHeadersTrustedIps,omitempty"`
	ClientTrustedIPs                         []string `json:"clientTrustedIps,omitempty"`
	RedisCacheEnabled                        bool     `json:"redisCacheEnabled,omitempty"`
	RedisCacheHost                           string   `json:"redisCacheHost,omitempty"`
	RedisCachePassword                       string   `json:"redisCachePassword,omitempty"`
	RedisCachePasswordFile                   string   `json:"redisCachePasswordFile,omitempty"`
	RedisCacheDatabase                       string   `json:"redisCacheDatabase,omitempty"`
	RedisCacheUnreachableBlock               bool     `json:"redisCacheUnreachableBlock,omitempty"`
	BanHTMLFilePath                          string   `json:"banHtmlFilePath,omitempty"`
	CaptchaHTMLFilePath                      string   `json:"captchaHtmlFilePath,omitempty"`
	CaptchaProvider                          string   `json:"captchaProvider,omitempty"`
	CaptchaSiteKey                           string   `json:"captchaSiteKey,omitempty"`
	CaptchaSiteKeyFile                       string   `json:"captchaSiteKeyFile,omitempty"`
	CaptchaSecretKey                         string   `json:"captchaSecretKey,omitempty"`
	CaptchaSecretKeyFile                     string   `json:"captchaSecretKeyFile,omitempty"`
	CaptchaGracePeriodSeconds                int64    `json:"captchaGracePeriodSeconds,omitempty"`
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
		Enabled:                        false,
		LogLevel:                       LogINFO,
		LogFilePath:                    "",
		CrowdsecMode:                   LiveMode,
		CrowdsecAppsecEnabled:          false,
		CrowdsecAppsecHost:             "crowdsec:7422",
		CrowdsecAppsecPath:             "/",
		CrowdsecAppsecFailureBlock:     true,
		CrowdsecAppsecUnreachableBlock: true,
		CrowdsecAppsecBodyLimit:        10485760,
		CrowdsecLapiScheme:             HTTP,
		CrowdsecLapiHost:               "crowdsec:8080",
		CrowdsecLapiPath:               "/",
		CrowdsecLapiKey:                "",
		CrowdsecLapiTLSInsecureVerify:  false,
		UpdateIntervalSeconds:          60,
		MetricsUpdateIntervalSeconds:   600,
		UpdateMaxFailure:               0,
		DefaultDecisionSeconds:         60,
		HTTPTimeoutSeconds:             10,
		CaptchaProvider:                "",
		CaptchaSiteKey:                 "",
		CaptchaSecretKey:               "",
		CaptchaGracePeriodSeconds:      1800,
		CaptchaHTMLFilePath:            "/captcha.html",
		BanHTMLFilePath:                "",
		RemediationHeadersCustomName:   "",
		ForwardedHeadersCustomName:     "X-Forwarded-For",
		ForwardedHeadersTrustedIPs:     []string{},
		ClientTrustedIPs:               []string{},
		RedisCacheEnabled:              false,
		RedisCacheHost:                 "redis:6379",
		RedisCachePassword:             "",
		RedisCacheDatabase:             "",
		RedisCacheUnreachableBlock:     true,
	}
}

// GetVariable get variable from file and after in the variables gave by user.
func GetVariable(config *Config, key string) (string, error) {
	value := ""
	object := reflect.Indirect(reflect.ValueOf(config))
	field := object.FieldByName(key + "File")
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

// GetHTMLTemplate get compiled HTML template.
func GetHTMLTemplate(path string) (*template.Template, error) {
	var err error
	if path == "" {
		return nil, errors.New("no html template provided")
	}
	//nolint:gosec
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	html := string(b)
	compiledTemplate, err := template.New("html").Parse(html)
	if err != nil {
		return nil, fmt.Errorf("impossible to compile html template: %w", err)
	}
	return compiledTemplate, nil
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

	if config.CaptchaProvider != "" {
		if _, err := GetVariable(config, "CaptchaSiteKey"); err != nil {
			return err
		}
		if _, err := GetVariable(config, "CaptchaSecretKey"); err != nil {
			return err
		}
		if _, err := GetHTMLTemplate(config.CaptchaHTMLFilePath); err != nil {
			return err
		}
	}
	if config.BanHTMLFilePath != "" {
		if _, err := GetHTMLTemplate(config.BanHTMLFilePath); err != nil {
			return err
		}
	}

	if err := validateURL("CrowdsecLapi", config.CrowdsecLapiScheme, config.CrowdsecLapiHost, config.CrowdsecLapiPath); err != nil {
		return err
	}

	if err := validateURL("CrowdsecAppsec", config.CrowdsecLapiScheme, config.CrowdsecAppsecHost, config.CrowdsecAppsecPath); err != nil {
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
		return errors.New("CrowdsecLapiKey || (CrowdsecLapiTLSCertificateBouncer && CrowdsecLapiTLSCertificateBouncerKey): cannot be all empty")
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

	// Check logging configuration

	if !contains([]string{LogERROR, LogDEBUG, LogINFO, LogTRACE}, config.LogLevel) {
		return fmt.Errorf("LogLevel should be one of (%s,%s,%s,%s)", LogDEBUG, LogINFO, LogERROR, LogTRACE)
	}
	if config.LogFilePath != "" {
		_, err = os.OpenFile(filepath.Clean(config.LogFilePath), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("LogFilePath is not writable %w", err)
		}
	}
	return nil
}

func validateURL(variable, scheme, host, path string) error {
	// This only check that the format of the URL scheme://host/path is correct and do not make requests
	testURL := url.URL{Scheme: scheme, Host: host, Path: path}
	if _, err := http.NewRequest(http.MethodGet, testURL.String(), nil); err != nil {
		return fmt.Errorf("CrowdsecLapiScheme://%sHost: '%v://%v%v' must be a valid URL", variable, scheme, host, path)
	}
	return nil
}

// validHeaderFieldByte reports whether b is a valid byte in a header
// field name. RFC 7230 says:
// valid ! # $ % & ' * + - . ^ _ ` | ~ DIGIT ALPHA
// See https://httpwg.github.io/specs/rfc7230.html#rule.token.separators
func validateParamsAPIKey(lapiKey string) error {
	reg := regexp.MustCompile("^[a-zA-Z0-9 !#$%&'*+-.^_`|~=/]*$")
	if !reg.MatchString(lapiKey) {
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
		return errors.New("CrowdsecLapiTLSCertificateAuthority must be specified when CrowdsecLapiScheme='https' and CrowdsecLapiTLSInsecureVerify=false")
	}
	tlsConfig := new(tls.Config)
	tlsConfig.RootCAs = x509.NewCertPool()
	if !tlsConfig.RootCAs.AppendCertsFromPEM([]byte(certAuth)) {
		return errors.New("failed parsing pem file")
	}
	return nil
}

func validateParamsIPs(listIP []string, key string) error {
	if len(listIP) > 0 {
		if _, err := ip.NewChecker(logger.New(LogINFO, ""), listIP); err != nil {
			return fmt.Errorf("%s must be a list of IP/CIDR :%w", key, err)
		}
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
		"UpdateIntervalSeconds":        config.UpdateIntervalSeconds,
		"MetricsUpdateIntervalSeconds": config.MetricsUpdateIntervalSeconds,
		"DefaultDecisionSeconds":       config.DefaultDecisionSeconds,
		"HTTPTimeoutSeconds":           config.HTTPTimeoutSeconds,
		"CaptchaGracePeriodSeconds":    config.CaptchaGracePeriodSeconds,
	}
	for key, val := range requiredInt {
		if val < 1 {
			return fmt.Errorf("%v: cannot be less than 1", key)
		}
	}
	if config.UpdateMaxFailure < -1 {
		return errors.New("UpdateMaxFailure: cannot be less than -1")
	}
	if config.CrowdsecAppsecBodyLimit < 0 {
		return errors.New("CrowdsecAppsecBodyLimit: cannot be less than 0")
	}

	if !contains([]string{NoneMode, LiveMode, StreamMode, AloneMode, AppsecMode}, config.CrowdsecMode) {
		return errors.New("CrowdsecMode: must be one of 'none', 'live', 'stream', 'alone' or 'appsec'")
	}
	if !contains([]string{HTTP, HTTPS}, config.CrowdsecLapiScheme) {
		return errors.New("CrowdsecLapiScheme: must be one of 'http' or 'https'")
	}
	if !contains([]string{"", HcaptchaProvider, RecaptchaProvider, TurnstileProvider}, config.CaptchaProvider) {
		return errors.New("CaptchaProvider: must be one of 'hcaptcha', 'recaptcha' or 'turnstile'")
	}
	return nil
}

// GetTLSConfigCrowdsec get TLS config from Config.
//
//nolint:nestif
func GetTLSConfigCrowdsec(config *Config, log *logger.Log) (*tls.Config, error) {
	tlsConfig := new(tls.Config)
	tlsConfig.RootCAs = x509.NewCertPool()
	//nolint:gocritic
	if config.CrowdsecLapiScheme != HTTPS {
		log.Debug("getTLSConfigCrowdsec:CrowdsecLapiScheme https:no")
		return tlsConfig, nil
	} else if config.CrowdsecLapiTLSInsecureVerify {
		tlsConfig.InsecureSkipVerify = true
		log.Debug("getTLSConfigCrowdsec:CrowdsecLapiTLSInsecureVerify tlsInsecure:true")
		// If we return here and still want to use client auth this won't work
		// return tlsConfig, nil
	} else {
		certAuthority, err := GetVariable(config, "CrowdsecLapiTLSCertificateAuthority")
		if err != nil {
			return nil, err
		}
		if len(certAuthority) > 0 {
			if !tlsConfig.RootCAs.AppendCertsFromPEM([]byte(certAuthority)) {
				// here we return because if CrowdsecLapiTLSInsecureVerify is false
				// and CA not load, we can't communicate with https
				return nil, errors.New("getTLSConfigCrowdsec:cannot load CA and verify cert is enabled")
			}
			log.Debug("getTLSConfigCrowdsec:CrowdsecLapiTLSCertificateAuthority CA added successfully")
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
