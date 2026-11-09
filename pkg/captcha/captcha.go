// Package captcha implements utility for captcha management.
package captcha

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"text/template"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

// Client Captcha client.
type Client struct {
	Valid                   bool
	siteKey                 string
	secretKey               string
	remediationCustomHeader string
	gracePeriodSeconds      int64
	templateContentType     string
	template                *template.Template
	cacheClient             *cache.Client
	httpClient              *http.Client
	log                     *slog.Logger
	infoProvider            *infoProvider
	captchaResources        []captchaResource
}

// captchaResource is a pre-parsed, normalized representation of one pass-through URL.
type captchaResource struct {
	host string // empty = path-only (no host check); otherwise host[:port], default port stripped
	path string
}

// normalizeHost strips the scheme-default port from a host[:port] string and
// lowercases the result.
func normalizeHost(host, scheme string) string {
	h, port, err := net.SplitHostPort(host)
	if err != nil {
		// No port present, nothing to strip.
		return strings.ToLower(host)
	}
	switch {
	case scheme == "http" && port == "80":
		return strings.ToLower(h)
	case scheme == "https" && port == "443":
		return strings.ToLower(h)
	default:
		return strings.ToLower(host) // non-default port: keep it
	}
}

// parseCaptchaResourceURLs parses raw URL strings into captchaResources used
// for per-request pass-through matching. Empty strings are skipped.
func parseCaptchaResourceURLs(rawURLs ...string) []captchaResource {
	out := make([]captchaResource, 0, len(rawURLs))
	for _, raw := range rawURLs {
		if raw == "" {
			continue
		}
		// Validation in configuration.validateCaptcha already rejects bad URLs
		u, _ := url.Parse(raw)
		res := captchaResource{path: u.Path}
		if u.Host != "" {
			res.host = normalizeHost(u.Host, u.Scheme)
		}
		out = append(out, res)
	}
	return out
}

// Information for self-hosted provider.
type infoProvider struct {
	js       string
	key      string
	response string
	validate string
}

//nolint:gochecknoglobals
var infoProviders = map[string]*infoProvider{
	configuration.HcaptchaProvider: {
		js:       "https://hcaptcha.com/1/api.js",
		key:      "h-captcha",
		response: "h-captcha-response",
		validate: "https://api.hcaptcha.com/siteverify",
	},
	configuration.RecaptchaProvider: {
		js:       "https://www.google.com/recaptcha/api.js",
		key:      "g-recaptcha",
		response: "g-recaptcha-response",
		validate: "https://www.google.com/recaptcha/api/siteverify",
	},
	configuration.TurnstileProvider: {
		js:       "https://challenges.cloudflare.com/turnstile/v0/api.js",
		key:      "cf-turnstile",
		response: "cf-turnstile-response",
		validate: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	},
}

// New Initialize captcha client.
func (c *Client) New(log *slog.Logger, cacheClient *cache.Client, httpClient *http.Client, provider, js, challenge, key, response, validate, siteKey, secretKey, remediationCustomHeader, captchaTemplatePath string, gracePeriodSeconds int64) error {
	c.Valid = provider != ""
	if !c.Valid {
		return nil
	}
	var info *infoProvider
	if provider == configuration.CustomProvider {
		info = &infoProvider{js: js, key: key, response: response, validate: validate}
		c.captchaResources = parseCaptchaResourceURLs(js, challenge)
	} else {
		info = infoProviders[provider]
	}
	c.infoProvider = info
	c.siteKey = siteKey
	c.secretKey = secretKey
	c.remediationCustomHeader = remediationCustomHeader
	template, contentType, _ := configuration.GetTemplate(captchaTemplatePath)
	c.template = template
	c.templateContentType = contentType
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
		c.log.Info("captcha:ServeHTTP:validate " + err.Error())
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	if valid {
		c.log.Debug("captcha:ServeHTTP captcha:valid")
		c.cacheClient.Set(remoteIP+"_captcha", cache.CaptchaDoneValue, c.gracePeriodSeconds)
		if c.remediationCustomHeader != "" {
			rw.Header().Set(c.remediationCustomHeader, "solved-captcha")
		}
		http.Redirect(rw, r, r.URL.String(), http.StatusFound)
		return
	}
	rw.Header().Set("Content-Type", c.templateContentType)
	if c.remediationCustomHeader != "" {
		rw.Header().Set(c.remediationCustomHeader, "captcha")
	}
	rw.WriteHeader(http.StatusOK)
	err = c.template.Execute(rw, map[string]string{
		"SiteKey":     c.siteKey,
		"FrontendJS":  c.infoProvider.js,
		"FrontendKey": c.infoProvider.key,
	})
	if err != nil {
		c.log.Info("captcha:ServeHTTP captchaTemplateServe " + err.Error())
	}
}

// Check Verify if the captcha is already done.
func (c *Client) Check(remoteIP string) bool {
	value, _ := c.cacheClient.Get(remoteIP + "_captcha")
	passed := value == cache.CaptchaDoneValue
	c.log.Debug(fmt.Sprintf("captcha:Check ip:%s pass:%v", remoteIP, passed))
	return passed
}

type responseProvider struct {
	Success bool `json:"success"`
}

// Validate Verify the captcha from provider API.
func (c *Client) Validate(r *http.Request) (bool, error) {
	if r.Method != http.MethodPost {
		c.log.Debug("captcha:Validate invalid method: " + r.Method)
		return false, nil
	}
	var response = r.FormValue(c.infoProvider.response)
	if response == "" {
		c.log.Debug("captcha:Validate no captcha response found in request")
		return false, nil
	}
	var body = url.Values{}
	body.Add("secret", c.secretKey)
	body.Add("response", response)
	res, err := c.httpClient.PostForm(c.infoProvider.validate, body)
	if err != nil {
		return false, err
	}
	defer func() {
		if err = res.Body.Close(); err != nil {
			c.log.Error("captcha:Validate " + err.Error())
		}
	}()
	if !strings.Contains(res.Header.Get("Content-Type"), "application/json") {
		c.log.Debug("captcha:Validate responseType:noJson")
		return false, nil
	}
	var captchaResponse responseProvider
	err = json.NewDecoder(res.Body).Decode(&captchaResponse)
	if err != nil {
		return false, err
	}
	c.log.Debug(fmt.Sprintf("captcha:Validate success:%v", captchaResponse.Success))
	return captchaResponse.Success, nil
}

// IsCaptchaResource reports whether req targets one of the captcha resource
// paths (CaptchaCustomJsURL, CaptchaCustomChallengeURL). Captcha-pending IPs
// must reach these paths for the widget to load and submit; all other paths are
// still blocked.
//
// Matching rules:
//   - Path must match exactly.
//   - If the configured URL includes a host, req.Host must match case-insensitively.
//   - If the configured URL includes a non-default port, the port in req.Host must match.
//   - If the configured URL is path-only (no host), only the path is checked.
func (c *Client) IsCaptchaResource(req *http.Request) bool {
	if len(c.captchaResources) == 0 {
		return false
	}
	reqPath := req.URL.Path
	// Infer request scheme from TLS state; needed for default-port stripping.
	reqScheme := "http"
	if req.TLS != nil {
		reqScheme = "https"
	}
	reqHost := normalizeHost(req.Host, reqScheme)

	for _, res := range c.captchaResources {
		if reqPath != res.path {
			continue
		}
		if res.host != "" && res.host != reqHost {
			continue
		}
		return true
	}
	return false
}
