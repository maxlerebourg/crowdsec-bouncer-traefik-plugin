// Package captcha implements utility for captcha management.
package captcha

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// Client Captcha client.
type Client struct {
	Valid                   bool
	provider                string
	referer                 string
	siteKey                 string
	secretKey               string
	validationURL           string
	challengeURL            string
	remediationCustomHeader string
	gracePeriodSeconds      int64
	captchaTemplate         *template.Template
	cacheClient             *cache.Client
	httpClient              *http.Client
	log                     *logger.Log
}

type infoProvider struct {
	js          string
	key         string
	responseKey string
	challenge   string
	validate    string
}

var (
	//nolint:gochecknoglobals
	captcha = map[string]infoProvider{
		configuration.HcaptchaProvider: {
			js:          "https://hcaptcha.com/1/api.js",
			key:         "h-captcha",
			responseKey: "h-captcha-response",
			validate:    "https://api.hcaptcha.com/siteverify",
		},
		configuration.RecaptchaProvider: {
			js:          "https://www.google.com/recaptcha/api.js",
			key:         "g-recaptcha",
			responseKey: "g-recaptcha-response",
			validate:    "https://www.google.com/recaptcha/api/siteverify",
		},
		configuration.TurnstileProvider: {
			js:          "https://challenges.cloudflare.com/turnstile/v0/api.js",
			key:         "cf-turnstile",
			responseKey: "cf-turnstile-response",
			validate:    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
		},
		configuration.AltchaProvider: {
			js:          "https://cdn.jsdelivr.net/npm/altcha/dist/altcha.min.js",
			key:         "altcha",
			responseKey: "altcha",
			challenge:   "https://eu.altcha.org/api/v1/challenge",
			validate:    "https://eu.altcha.org/api/v1/challenge/verify",
		},
	}
)

type templateRenderData struct {
	SiteKey       string
	FrontendJS    string
	FrontendKey   string
	ChallengeData altchaChallengeData
}

// New Initialize captcha client.
func (c *Client) New(log *logger.Log, cacheClient *cache.Client, httpClient *http.Client, provider, siteKey, secretKey, validationURL, challengeURL, referer, remediationCustomHeader, captchaTemplatePath string, gracePeriodSeconds int64) error {
	c.Valid = provider != ""
	if !c.Valid {
		return nil
	}
	c.referer = referer
	c.siteKey = siteKey
	c.secretKey = secretKey
	c.provider = provider
	c.remediationCustomHeader = remediationCustomHeader
	html, _ := configuration.GetHTMLTemplate(captchaTemplatePath)
	c.captchaTemplate = html
	c.gracePeriodSeconds = gracePeriodSeconds
	c.log = log
	c.validationURL = captcha[c.provider].validate
	if validationURL != "" {
		c.log.Debug("captcha:Client overriding default provider Validation URL with '" + validationURL + "'")
		c.validationURL = validationURL
	}
	c.challengeURL = captcha[c.provider].challenge
	if challengeURL != "" {
		c.log.Debug("captcha:Client overriding default provider Challenge URL with '" + challengeURL + "'")
		c.challengeURL = challengeURL
	}
	c.httpClient = httpClient
	c.cacheClient = cacheClient
	return nil
}

// ServeHTTP Handle captcha html page or validation.
func (c *Client) ServeHTTP(rw http.ResponseWriter, r *http.Request, remoteIP string) {
	if r.Method == http.MethodPost {
		valid, err := c.Validate(r)
		if err != nil {
			c.log.Info("captcha:ServeHTTP:validate " + err.Error())
			rw.WriteHeader(http.StatusBadRequest)
			return
		}
		if valid {
			c.log.Debug("captcha:ServeHTTP captcha:valid")
			c.cacheClient.Set(remoteIP+"_captcha", cache.CaptchaDoneValue, c.gracePeriodSeconds)
			http.Redirect(rw, r, r.URL.String(), http.StatusFound)
			return
		}
	}
	var challengeData altchaChallengeData
	if c.provider == "altcha" {
		err := challengeData.Get(c)
		if err != nil {
			c.log.Error("captcha:ServeHTTP captchaChallengeDataGet " + err.Error())
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	if c.remediationCustomHeader != "" {
		rw.Header().Set(c.remediationCustomHeader, "captcha")
	}
	rw.WriteHeader(http.StatusOK)
	err := c.captchaTemplate.Execute(rw, templateRenderData{
		SiteKey:       c.siteKey,
		FrontendJS:    captcha[c.provider].js,
		FrontendKey:   captcha[c.provider].key,
		ChallengeData: challengeData,
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

type altchaResponseProvider struct {
	Success bool `json:"verified"`
}

type altchaVerifyPayload struct {
	Payload string `json:"payload"`
}

// Validate Verify the captcha from provider API.
func (c *Client) Validate(r *http.Request) (bool, error) {
	var response = r.FormValue(captcha[c.provider].responseKey)
	if response == "" {
		c.log.Debug("captcha:Validate no captcha response found in request")
		return false, nil
	}
	var err error
	var res *http.Response
	if c.provider == "altcha" {
		// altcha requires JSON body POSTs rather than formdata
		body := altchaVerifyPayload{
			Payload: response,
		}
		jsonBody, aErr := json.Marshal(body)
		if aErr != nil {
			return false, aErr
		}
		req, aErr := http.NewRequest(http.MethodPost, c.validationURL, bytes.NewBuffer(jsonBody))
		if aErr != nil {
			return false, aErr
		}
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", "Bearer "+c.secretKey)
		req.Header.Add("Referer", c.referer)
		res, err = c.httpClient.Do(req)
	} else {
		var body = url.Values{}
		body.Add("secret", c.secretKey)
		body.Add("response", response)
		res, err = c.httpClient.PostForm(c.validationURL, body)
	}
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

	var captchaSuccess bool
	if c.provider == "altcha" {
		var captchaResponse altchaResponseProvider
		err = json.NewDecoder(res.Body).Decode(&captchaResponse)
		captchaSuccess = captchaResponse.Success
	} else {
		var captchaResponse responseProvider
		err = json.NewDecoder(res.Body).Decode(&captchaResponse)
		captchaSuccess = captchaResponse.Success
	}
	if err != nil {
		return false, err
	}
	c.log.Debug(fmt.Sprintf("captcha:Validate success:%v", captchaSuccess))
	return captchaSuccess, nil
}

type altchaChallengeData struct {
	Algorithm string `json:"algorithm"`
	Challenge string `json:"challenge"`
	MaxNumber int    `json:"maxnumber"`
	Salt      string `json:"salt"`
	Signature string `json:"signature"`
	Error     string `json:"error"`
}

func (cd *altchaChallengeData) Get(c *Client) error {
	req, err := http.NewRequest(http.MethodGet, c.challengeURL, nil)
	if err != nil {
		return err
	}
	req.Header.Add("Referer", c.referer)
	req.Header.Add("Authorization", "Bearer "+c.secretKey)
	res, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if err = res.Body.Close(); err != nil {
			c.log.Error("captcha:Validate " + err.Error())
		}
	}()
	err = json.NewDecoder(res.Body).Decode(&cd)
	if res.StatusCode != http.StatusOK {
		return errors.New("error retrieving challenge data: (" + res.Status + ") " + cd.Error)
	}
	return err
}
