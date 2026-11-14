package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	captcha "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestSolvedCaptchaSubmission(t *testing.T) {
	log := logger.New("ERROR", "")
	cacheClient := &cache.Client{}
	cacheClient.New(log, false, "", nil, "", "")
	cacheClient.Set("192.0.2.1_captcha", cache.CaptchaDoneValue, 60)
	captchaClient := &captcha.Client{}
	if err := captchaClient.New(log, cacheClient, &http.Client{}, configuration.HcaptchaProvider, "", "", "", "", "site", "secret", "", "captcha.html", 60); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		body     string
		appsec   bool
		wantCode int
		wantNext bool
	}{
		{name: "lapi captcha submitted again", body: "h-captcha-response=token", wantCode: http.StatusFound},
		{name: "lapi other form", body: "name=value", wantCode: http.StatusOK, wantNext: true},
		{name: "appsec captcha submitted again", body: "h-captcha-response=token", appsec: true, wantCode: http.StatusFound},
		{name: "appsec other form", body: "name=value", appsec: true, wantCode: http.StatusOK, wantNext: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nextBody string
			bouncer := &Bouncer{
				next: http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
					body, _ := io.ReadAll(req.Body)
					nextBody = string(body)
				}),
				cacheClient:   cacheClient,
				captchaClient: captchaClient,
				log:           log,
			}
			req := httptest.NewRequest(http.MethodPost, "http://example.com/page?a=1", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rw := httptest.NewRecorder()

			if tt.appsec {
				if !bouncer.handleAppsecDecisionServeHTTP(rw, req, "192.0.2.1", &AppSecResponse{Action: appsecCaptchaAction}) {
					bouncer.next.ServeHTTP(rw, req)
				}
			} else {
				bouncer.handleRemediationServeHTTP(rw, req, "192.0.2.1", cache.CaptchaValue)
			}

			if rw.Code != tt.wantCode {
				t.Errorf("status = %d, want %d", rw.Code, tt.wantCode)
			}
			if tt.wantCode == http.StatusFound && rw.Header().Get("Location") != "http://example.com/page?a=1" {
				t.Errorf("Location = %q", rw.Header().Get("Location"))
			}
			if tt.wantNext != (nextBody == tt.body) {
				t.Errorf("next got body %q, want next called: %v", nextBody, tt.wantNext)
			}
		})
	}
}
