package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"testing"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestRemediationForDecision(t *testing.T) {
	log := logger.New("INFO", "")
	configured := &Bouncer{log: log, captchaBanOrigins: []string{"CAPI", "lists"}}
	defaultCfg := &Bouncer{log: log, captchaBanOrigins: []string{}}

	tests := []struct {
		name     string
		bouncer  *Bouncer
		decision Decision
		expected string
	}{
		{
			name:     "ban from a listed origin is served a captcha",
			bouncer:  configured,
			decision: Decision{Type: "ban", Origin: "CAPI"},
			expected: cache.CaptchaValue,
		},
		{
			name:     "ban from another listed origin is served a captcha",
			bouncer:  configured,
			decision: Decision{Type: "ban", Origin: "lists"},
			expected: cache.CaptchaValue,
		},
		{
			name:     "ban from an unlisted origin stays a ban",
			bouncer:  configured,
			decision: Decision{Type: "ban", Origin: "crowdsec"},
			expected: cache.BannedValue,
		},
		{
			name:     "manual cscli ban stays a ban",
			bouncer:  configured,
			decision: Decision{Type: "ban", Origin: "cscli"},
			expected: cache.BannedValue,
		},
		{
			name:     "captcha decision is unaffected",
			bouncer:  configured,
			decision: Decision{Type: "captcha", Origin: "crowdsec"},
			expected: cache.CaptchaValue,
		},
		{
			name:     "default configuration maps nothing",
			bouncer:  defaultCfg,
			decision: Decision{Type: "ban", Origin: "CAPI"},
			expected: cache.BannedValue,
		},
		{
			name:     "unknown decision type keeps the previous behaviour",
			bouncer:  configured,
			decision: Decision{Type: "mfa", Origin: "CAPI"},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.bouncer.remediationForDecision(tt.decision); got != tt.expected {
				t.Errorf("remediationForDecision() = %q, want %q", got, tt.expected)
			}
		})
	}
}
