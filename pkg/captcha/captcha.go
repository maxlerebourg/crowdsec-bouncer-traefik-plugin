package captcha

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

type Client struct {
	Provider            string
	Template            string
	TemplateFile        string
	CompiledTemplate    *template.Template
	FallbackRemediation string
	Valid               bool
	GracePeriod         int64
	SiteKey             string
	SecretKey           string
	Http                *http.Client
}

var (
	ValidProviders = []string{"hcaptcha", "recaptcha", "turnstile"}
	FrontendJS     = map[string]string{
		"hcaptcha":  "https://hcaptcha.com/1/api.js",
		"recaptcha": "https://www.google.com/recaptcha/api.js",
		"turnstile": "https://challenges.cloudflare.com/turnstile/v0/api.js",
	}
	FrontendKey = map[string]string{
		"hcaptcha":  "h-captcha",
		"recaptcha": "g-recaptcha",
		"turnstile": "cf-captcha",
	}
	ValidateEndpoints = map[string]string{
		"hcaptcha":  "https://api.hcaptcha.com/verify",
		"recaptcha": "https://www.google.com/recaptcha/api/siteverify",
		"turnstile": "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	}
	InvalidMethod        = "invalid:method"
	InvalidConfiguration = "invalid:configuration"
)

func (c *Client) CompileTemplate() error {
	var err error
	if c.Template == "" && c.TemplateFile == "" {
		c.Valid = false
		return fmt.Errorf("no captcha template provided, captcha decisions will fallback to %s", c.FallbackRemediation)
	}
	if c.TemplateFile != "" {
		b, err := os.ReadFile(c.TemplateFile)
		if err != nil {
			return err
		}
		c.Template = string(b)
	}
	c.CompiledTemplate, err = template.New("captcha").Parse(c.Template)
	if err != nil {
		c.Valid = false
		return fmt.Errorf("error compiling captcha template: %s", err.Error())
	}
	c.Valid = true
	return err
}

func (c *Client) New(siteKey, secretKey, provider, template, templateFile, fallback string, gracePeriod int64) error {
	c.SiteKey = siteKey
	c.SecretKey = secretKey
	c.Provider = provider
	c.Template = template
	c.TemplateFile = templateFile
	c.FallbackRemediation = fallback
	c.GracePeriod = gracePeriod
	c.Http = &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:    10,
			IdleConnTimeout: 30 * time.Second,
		},
		Timeout: 10 * time.Second,
	}
	return c.CompileTemplate()
}

func (c *Client) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if !c.Valid && c.FallbackRemediation == "ban" {
		logger.Debug("captcha is not valid and fallback remediation is set to ban, returning 403")
		rw.WriteHeader(http.StatusForbidden)
		return
	}
	c.CompiledTemplate.Execute(rw, map[string]string{
		"Site_key":     c.SiteKey,
		"Frontend_js":  FrontendJS[c.Provider],
		"Frontend_key": FrontendKey[c.Provider],
	})
}

type CaptchaResponse struct {
	Success bool `json:"success"`
	//ChallengeTS string `json:"challenge_ts"`
	//Hostname    string `json:"hostname"`
}

func (c *Client) Validate(r *http.Request) (bool, error) {
	if r.Method != "POST" {
		logger.Debug(fmt.Sprintf("invalid method %s", r.Method))
		return false, fmt.Errorf(InvalidMethod)
	}
	var response = r.FormValue(fmt.Sprintf("%s-response", FrontendKey[c.Provider]))
	if response == "" {
		logger.Debug("post body missing captcha form value")
		return false, fmt.Errorf("invalid:missing-response")
	}
	logger.Debug(fmt.Sprintf("validating captcha with response: %s", response))
	var body = url.Values{}
	body.Add("secret", c.SecretKey)
	body.Add("response", response)
	resp, err := c.Http.PostForm(ValidateEndpoints[c.Provider], body)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Type") != "application/json" {
		b, _ := io.ReadAll(r.Body)
		logger.Debug(fmt.Sprintf("status: %s, body: %s", resp.Status, string(b)))
		return false, fmt.Errorf("invalid:content-type")
	}
	var captchaResponse CaptchaResponse
	err = json.NewDecoder(resp.Body).Decode(&captchaResponse)
	if err != nil {
		return false, err
	}
	logger.Debug(fmt.Sprintf("validating captcha success: %v", captchaResponse.Success))
	return captchaResponse.Success, nil
}
