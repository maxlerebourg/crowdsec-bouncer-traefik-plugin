package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	decision "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/decision"
)

// requestCountry reads and normalizes the configured country header.
func requestCountry(bouncer *Bouncer, req *http.Request) string {
	if bouncer.countryHeader == "" {
		return ""
	}
	return decision.NormalizeCountry(req.Header.Get(bouncer.countryHeader))
}

// requestASN reads and normalizes the configured ASN header.
func requestASN(bouncer *Bouncer, req *http.Request) string {
	if bouncer.asnHeader == "" {
		return ""
	}
	return decision.NormalizeASN(req.Header.Get(bouncer.asnHeader))
}

// isActiveRemediation reports whether value is ban or captcha.
func isActiveRemediation(value string) bool {
	return value == cache.BannedValue || value == cache.CaptchaValue
}

// remediationValue maps a CrowdSec decision type to a cache remediation.
func remediationValue(decisionType string) string {
	switch decisionType {
	case "ban":
		return cache.BannedValue
	case "captcha":
		return cache.CaptchaValue
	default:
		return ""
	}
}

// preferRemediation keeps ban over captcha over empty.
func preferRemediation(current, incoming string) string {
	if current == cache.BannedValue || incoming == cache.BannedValue {
		return cache.BannedValue
	}
	if isActiveRemediation(current) {
		return current
	}
	return incoming
}

// lookupCachedRemediation checks Ip, Range, Country, then AS in the shared cache.
func lookupCachedRemediation(bouncer *Bouncer, remoteIP, country, asn string) (string, error) {
	value, err := bouncer.cacheClient.Get(remoteIP)
	switch {
	case err == nil && isActiveRemediation(value):
		return value, nil
	case err != nil && err.Error() != cache.CacheMiss:
		return "", err
	}
	if rangeValue := decision.MatchRange(bouncer.cacheClient, remoteIP); isActiveRemediation(rangeValue) {
		return rangeValue, nil
	}
	if countryValue, countryErr := lookupScopeKey(bouncer, decision.CountryKey(country), country); countryErr != nil || countryValue != "" {
		return countryValue, countryErr
	}
	if asnValue, asnErr := lookupScopeKey(bouncer, decision.ASKey(asn), asn); asnErr != nil || asnValue != "" {
		return asnValue, asnErr
	}
	if err == nil {
		return value, nil
	}
	return "", err
}

// lookupScopeKey returns an active remediation for a Country or AS cache key.
func lookupScopeKey(bouncer *Bouncer, key, identifier string) (string, error) {
	if identifier == "" {
		return "", nil
	}
	value, err := bouncer.cacheClient.Get(key)
	if err == nil && isActiveRemediation(value) {
		return value, nil
	}
	if err != nil && err.Error() != cache.CacheMiss {
		return "", err
	}
	return "", nil
}

// streamQuery is the LAPI/CAPI stream RawQuery. LAPI adds scopes= when this is not CAPI.
func streamQuery(bouncer *Bouncer) string {
	query := fmt.Sprintf("startup=%t", !isCrowdsecStreamHealthy || isCrowdsecStreamStartup)
	if bouncer.crowdsecStreamRoute != crowdsecLapiStreamRoute {
		return query
	}
	return query + "&scopes=" + streamScopeList(bouncer)
}

// streamScopeList is the LAPI scopes query value for this bouncer config.
func streamScopeList(bouncer *Bouncer) string {
	scopes := "ip,range"
	if bouncer.countryHeader != "" {
		scopes += ",country"
	}
	if bouncer.asnHeader != "" {
		scopes += ",AS"
	}
	return scopes
}

// storeStreamDecision writes one stream New decision into the shared cache by scope.
func storeStreamDecision(bouncer *Bouncer, item Decision, duration int64) {
	value := remediationValue(item.Type)
	if value == "" {
		bouncer.log.Debug("handleStreamCache:unknownType " + item.Type)
		return
	}
	switch decision.NormalizeScope(item.Scope) {
	case decision.ScopeIP, "":
		bouncer.cacheClient.Set(decision.IPCacheKey(item.Value), value, duration)
	case decision.ScopeRange:
		decision.AddRange(bouncer.cacheClient, item.Value, value, duration)
	case decision.ScopeCountry:
		code := decision.NormalizeCountry(item.Value)
		if code == "" {
			return
		}
		bouncer.cacheClient.Set(decision.CountryKey(code), value, duration)
	case decision.ScopeAS:
		asn := decision.NormalizeASN(item.Value)
		if asn == "" {
			return
		}
		bouncer.cacheClient.Set(decision.ASKey(asn), value, duration)
	default:
		bouncer.log.Debug("handleStreamCache:ignoredScope " + item.Scope)
	}
}

// deleteStreamDecision removes one stream Deleted decision from the shared cache.
func deleteStreamDecision(bouncer *Bouncer, item Decision) {
	switch decision.NormalizeScope(item.Scope) {
	case decision.ScopeIP, "":
		bouncer.cacheClient.Delete(decision.IPCacheKey(item.Value))
		bouncer.cacheClient.Delete(item.Value)
	case decision.ScopeRange:
		decision.RemoveRange(bouncer.cacheClient, item.Value)
	case decision.ScopeCountry:
		code := decision.NormalizeCountry(item.Value)
		if code != "" {
			bouncer.cacheClient.Delete(decision.CountryKey(code))
		}
	case decision.ScopeAS:
		asn := decision.NormalizeASN(item.Value)
		if asn != "" {
			bouncer.cacheClient.Delete(decision.ASKey(asn))
		}
	default:
		bouncer.cacheClient.Delete(item.Value)
	}
}

// queryLiveDecisions calls LAPI GET /v1/decisions with rawQuery and picks ban over captcha.
func queryLiveDecisions(bouncer *Bouncer, rawQuery string) (string, time.Duration, error) {
	routeURL := url.URL{
		Scheme:   bouncer.crowdsecScheme,
		Host:     bouncer.crowdsecHost,
		Path:     bouncer.crowdsecPath + crowdsecLapiRoute,
		RawQuery: rawQuery,
	}
	body, err := crowdsecQuery(bouncer, routeURL.String(), nil)
	if err != nil {
		return cache.BannedValue, 0, err
	}
	if bytes.Equal(body, []byte("null")) {
		return cache.NoBannedValue, 0, nil
	}
	var items []Decision
	err = json.Unmarshal(body, &items)
	if err != nil {
		return cache.BannedValue, 0, fmt.Errorf("handleNoStreamCache:parseBody %w", err)
	}
	if len(items) == 0 {
		return cache.NoBannedValue, 0, nil
	}
	picked := pickDecision(items)
	if picked == nil {
		return cache.NoBannedValue, 0, nil
	}
	parsedDuration, err := time.ParseDuration(picked.Duration)
	if err != nil {
		return cache.BannedValue, 0, fmt.Errorf("handleNoStreamCache:parseDuration %w", err)
	}
	value := remediationValue(picked.Type)
	if value == "" {
		return cache.NoBannedValue, 0, nil
	}
	return value, parsedDuration, nil
}

// pickDecision returns the first ban, else the last captcha-capable item.
func pickDecision(items []Decision) *Decision {
	var fallback *Decision
	for i := range items {
		if items[i].Type == "ban" {
			return &items[i]
		}
		if items[i].Type == "captcha" {
			fallback = &items[i]
		}
	}
	return fallback
}

func cacheLiveScope(bouncer *Bouncer, key, value string, parsedDuration time.Duration, isLiveMode bool) {
	if !isLiveMode || bouncer.defaultDecisionTimeout <= 0 {
		return
	}
	if !isActiveRemediation(value) {
		bouncer.cacheClient.Set(key, cache.NoBannedValue, bouncer.defaultDecisionTimeout)
		return
	}
	bouncer.cacheClient.Set(key, value, liveCacheTTL(bouncer, parsedDuration))
}

func liveCacheTTL(bouncer *Bouncer, parsedDuration time.Duration) int64 {
	durationSecond := int64(parsedDuration.Seconds())
	if durationSecond <= 0 || bouncer.defaultDecisionTimeout < durationSecond {
		return bouncer.defaultDecisionTimeout
	}
	return durationSecond
}
