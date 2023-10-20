package captcha

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
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
	Cache               *cache.Client
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
		"hcaptcha":  "https://api.hcaptcha.com/siteverify",
		"recaptcha": "https://www.google.com/recaptcha/api/siteverify",
		"turnstile": "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	}
	InvalidMethod        = "invalid:method"
	InvalidConfiguration = "invalid:configuration"
)

func (c *Client) CompileTemplate() error {
	var err error
	if c.Template == "" && c.TemplateFile == "" {
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
		return fmt.Errorf("error compiling captcha template: %s", err.Error())
	}
	c.Valid = true
	return err
}

func (c *Client) Debug(message string) {
	logger.Debug(fmt.Sprintf("captchaClient: %s", message))
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

func (c *Client) ServeHTTP(rw http.ResponseWriter, r *http.Request, remoteIP string) {
	valid, err := c.Validate(r)
	if err != nil {
		c.Debug(fmt.Sprintf("error validating captcha: %s", err.Error()))
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	if valid {
		c.Debug("captcha is valid, setting cookie")
		uri, err := c.Cache.Get(fmt.Sprintf("%s_captcha", remoteIP))
		c.SetCookie(rw)
		if err != nil && err.Error() == cache.CacheMiss {
			c.Debug("no original request URI found in cache")
			http.Redirect(rw, r, "/", http.StatusFound)
			return
		}
		c.Cache.Delete(fmt.Sprintf("%s_captcha", remoteIP))
		http.Redirect(rw, r, uri, http.StatusFound)
		return
	}
	c.Cache.Set(fmt.Sprintf("%s_captcha", remoteIP), r.RequestURI, 60*5)
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

func (c *Client) CheckCookie(rw http.ResponseWriter, r *http.Request) bool {
	c.Debug("validating captcha cookie")
	cookie, err := r.Cookie("crowdsec_captcha")
	if err != nil {
		c.Debug(fmt.Sprintf("error getting captcha cookie: %s", err.Error()))
		return false
	}
	_, err = c.validateJWT(cookie.Value)
	if err != nil {
		c.Debug(fmt.Sprintf("error validating jwt token: %s", err.Error()))
		http.SetCookie(rw, &http.Cookie{
			Name:     "crowdsec_captcha",
			Value:    "",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			Expires:  time.Now().Add(3 * time.Second),
		})
		return false
	}
	return err == nil
}

func (c *Client) validateJWT(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(c.SecretKey), nil
	})
	if err != nil {
		c.Debug(fmt.Sprintf("error from jwt parse %s", err.Error()))
		return &jwt.Token{}, err
	}
	if !token.Valid {
		return &jwt.Token{}, fmt.Errorf("invalid jwt token")
	}
	return token, nil
}

func (c *Client) generateJWT(exp time.Time) (string, error) {
	c.Debug("generating jwt token")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": exp.Unix(),
	})
	return token.SignedString([]byte(c.SecretKey))
}

func (c *Client) SetCookie(rw http.ResponseWriter) {
	//TODO handle jwt error
	exp := time.Now().Add(time.Duration(c.GracePeriod) * time.Minute)
	token, err := c.generateJWT(exp)
	if err != nil {
		c.Debug(fmt.Sprintf("error generating jwt token: %s", err.Error()))
		return
	}
	http.SetCookie(rw, &http.Cookie{
		Name:     "crowdsec_captcha",
		Value:    token,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  exp,
	})
}

func (c *Client) Validate(r *http.Request) (bool, error) {
	if r.Method != "POST" {
		c.Debug(fmt.Sprintf("invalid method: %s", r.Method))
		return false, nil
	}
	var response = r.FormValue(fmt.Sprintf("%s-response", FrontendKey[c.Provider]))
	if response == "" {
		c.Debug("no captcha response found in request")
		return false, nil
	}
	var body = url.Values{}
	body.Add("secret", c.SecretKey)
	body.Add("response", response)
	resp, err := c.Http.PostForm(ValidateEndpoints[c.Provider], body)
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
	c.Debug(fmt.Sprintf("validating captcha success: %v", captchaResponse.Success))
	return captchaResponse.Success, nil
}
