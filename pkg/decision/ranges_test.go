package decision

import (
	"testing"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func newTestCache() *cache.Client {
	client := &cache.Client{}
	client.New(logger.New("ERROR", ""), false, "", "", "")
	return client
}

func TestMatchRangeBanWins(t *testing.T) {
	client := newTestCache()
	AddRange(client, "10.0.0.0/8", cache.CaptchaValue, 60)
	AddRange(client, "10.1.0.0/16", cache.BannedValue, 60)
	if got := MatchRange(client, "10.1.2.3"); got != cache.BannedValue {
		t.Fatalf("got %q, want ban", got)
	}
	if got := MatchRange(client, "11.0.0.1"); got != "" {
		t.Fatalf("outside range got %q", got)
	}
}

func TestRemoveRange(t *testing.T) {
	client := newTestCache()
	AddRange(client, "192.168.0.0/16", cache.BannedValue, 60)
	RemoveRange(client, "192.168.0.0/16")
	if got := MatchRange(client, "192.168.1.1"); got != "" {
		t.Fatalf("removed range still matched: %q", got)
	}
}
