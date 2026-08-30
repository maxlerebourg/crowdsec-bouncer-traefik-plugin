package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"testing"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func newTestDecisionCache() *cache.Client {
	client := &cache.Client{}
	client.New(logger.New("ERROR", ""), false, "", "", "")
	return client
}

func TestMatchRangeBanWins(t *testing.T) {
	client := newTestDecisionCache()
	addRange(client, "10.0.0.0/8", cache.CaptchaValue, 60)
	addRange(client, "10.1.0.0/16", cache.BannedValue, 60)
	if got := matchRange(client, "10.1.2.3"); got != cache.BannedValue {
		t.Fatalf("got %q, want ban", got)
	}
	if got := matchRange(client, "11.0.0.1"); got != "" {
		t.Fatalf("outside range got %q", got)
	}
}

func TestRemoveRange(t *testing.T) {
	client := newTestDecisionCache()
	addRange(client, "192.168.0.0/16", cache.BannedValue, 60)
	removeRange(client, "192.168.0.0/16")
	if got := matchRange(client, "192.168.1.1"); got != "" {
		t.Fatalf("removed range still matched: %q", got)
	}
}
