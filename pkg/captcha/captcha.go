// Package captcha implements utility for captcha management.
package captcha

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// Client Captcha client.
type Client struct {
	Valid              bool
	provider           string
	siteKey            string
	secretKey          string
	gracePeriodSeconds int64
	htmlPage           *template.Template
	cacheClient        *cache.Client
	httpClient         *http.Client
	log                *logger.Log
}

// CaptchaProvider Define js, key and URL to validate.
type CaptchaProvider struct {
	js       string
	key      string
	validate string
}

var (
	captcha = map[string]CaptchaProvider{
		configuration.HcaptchaProvider: {
			js:       "https://hcaptcha.com/1/api.js",
			key:      "h-captcha",
			validate: "https://api.hcaptcha.com/siteverify",
		},
		configuration.RecaptchaProvider: {
			js:       "https://www.google.com/recaptcha/api.js",
			key:      "g-recaptcha",
			validate: "https://www.google.com/recaptcha/api/siteverify",
		},
		configuration.TurnstileProvider: {
			js:       "https://challenges.cloudflare.com/turnstile/v0/api.js",
			key:      "cf-captcha",
			validate: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
		},
	}
)

func compileTemplate(path string) (*template.Template, error) {
	var err error
	if path == "" {
		return nil, fmt.Errorf("No captcha template provided")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	html := string(b)
	compiledTemplate, err := template.New("captcha").Parse(html)
	if err != nil {
		return nil, fmt.Errorf("Impossible to compile captcha template: %s", err.Error())
	}
	return compiledTemplate, nil
}

// New Initialize captcha client.
func (c *Client) New(log *logger.Log, cacheClient *cache.Client, httpClient *http.Client, provider, siteKey, secretKey, htmlPagePath string, gracePeriodSeconds int64) error {
	c.Valid = provider != ""
	if !c.Valid {
		return nil
	}
	c.siteKey = siteKey
	c.secretKey = secretKey
	c.provider = provider
	html, err := compileTemplate(htmlPagePath)
	if err != nil {
		return err
	}
	c.htmlPage = html
	c.gracePeriodSeconds = gracePeriodSeconds
	c.log = log
	c.httpClient = httpClient
	c.cacheClient = cacheClient
	return nil
}

// ServeHTTP Handle captcha html page or validation.
func (c *Client) ServeHTTP(rw http.ResponseWriter, r *http.Request, remoteIP string) {
	valid, err := c.Validate(r)
	if err != nil {
		c.log.Debug(fmt.Sprintf("captcha:ServeHTTP:validate %s", err.Error()))
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	if valid {
		c.log.Debug("captcha:ServeHTTP captcha:valid")
		c.cacheClient.Set(fmt.Sprintf("%s_captcha", remoteIP), cache.CaptchaDoneValue, c.gracePeriodSeconds)
		http.Redirect(rw, r, r.URL.String(), http.StatusFound)
		return
	}
	c.htmlPage.Execute(rw, map[string]string{
		"SiteKey":     c.siteKey,
		"FrontendJS":  captcha[c.provider].js,
		"FrontendKey": captcha[c.provider].key,
	})
}

// Check Check if the captcha is already done.
func (c *Client) Check(remoteIP string) bool {
	value, _ := c.cacheClient.Get(fmt.Sprintf("%s_captcha", remoteIP))
	passed := value == cache.CaptchaDoneValue
	c.log.Debug(fmt.Sprintf("captcha:Check ip:%s pass:%v", remoteIP, passed))
	return passed
}

// CaptchaResponse Body returned from captcha provider API.
type CaptchaResponse struct {
	Success bool `json:"success"`
}

// Validate Verify the captcha from provider API.
func (c *Client) Validate(r *http.Request) (bool, error) {
	if r.Method != http.MethodPost {
		c.log.Debug(fmt.Sprintf("captcha:Validate invalid method: %s", r.Method))
		return false, nil
	}
	var response = r.FormValue(fmt.Sprintf("%s-response", captcha[c.provider].key))
	if response == "" {
		c.log.Debug("captcha:Validate no captcha response found in request")
		return false, nil
	}
	var body = url.Values{}
	body.Add("secret", c.secretKey)
	body.Add("response", response)
	resp, err := c.httpClient.PostForm(captcha[c.provider].validate, body)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.Header.Get("content-type") != "application/json" {
		return false, nil
	}
	var captchaResponse CaptchaResponse
	err = json.NewDecoder(resp.Body).Decode(&captchaResponse)
	if err != nil {
		return false, err
	}
	c.log.Debug(fmt.Sprintf("captcha:Validate success:%v", captchaResponse.Success))
	return captchaResponse.Success, nil
}
