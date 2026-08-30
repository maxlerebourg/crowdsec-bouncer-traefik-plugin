package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
)

// requestScopeValues reads configured scope headers and normalizes Country and AS ad-hoc.
func requestScopeValues(bouncer *Bouncer, req *http.Request) map[string]string {
	if len(bouncer.scopeHeaders) == 0 {
		return nil
	}
	out := make(map[string]string, len(bouncer.scopeHeaders))
	for scope, header := range bouncer.scopeHeaders {
		raw := req.Header.Get(header)
		var value string
		switch scope {
		case scopeCountry:
			value = normalizeCountry(raw)
		case scopeAS:
			value = normalizeASN(raw)
		default:
			value = strings.TrimSpace(raw)
		}
		if value != "" {
			out[scope] = value
		}
	}
	return out
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

// lookupCachedRemediation checks Ip, Range, Country, AS, then other configured header scopes.
func lookupCachedRemediation(bouncer *Bouncer, remoteIP string, scopes map[string]string) (string, error) {
	value, err := bouncer.cacheClient.Get(remoteIP)
	switch {
	case err == nil && isActiveRemediation(value):
		return value, nil
	case err != nil && err.Error() != cache.CacheMiss:
		return "", err
	}
	if rangeValue := matchRange(bouncer.cacheClient, remoteIP); isActiveRemediation(rangeValue) {
		return rangeValue, nil
	}
	if countryValue, countryErr := lookupScopeKey(bouncer, countryKey(scopes[scopeCountry]), scopes[scopeCountry]); countryErr != nil || countryValue != "" {
		return countryValue, countryErr
	}
	if asnValue, asnErr := lookupScopeKey(bouncer, asKey(scopes[scopeAS]), scopes[scopeAS]); asnErr != nil || asnValue != "" {
		return asnValue, asnErr
	}
	for _, scope := range extraHeaderScopes(bouncer) {
		identifier := scopes[scope]
		if headerValue, headerErr := lookupScopeKey(bouncer, headerScopeKey(scope, identifier), identifier); headerErr != nil || headerValue != "" {
			return headerValue, headerErr
		}
	}
	if err == nil {
		return value, nil
	}
	return "", err
}

// lookupScopeKey returns an active remediation for a header-scope cache key.
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
	parts := []string{"ip", "range"}
	if _, ok := bouncer.scopeHeaders[scopeCountry]; ok {
		parts = append(parts, "country")
	}
	if _, ok := bouncer.scopeHeaders[scopeAS]; ok {
		parts = append(parts, "AS")
	}
	return strings.Join(append(parts, extraHeaderScopes(bouncer)...), ",")
}

// extraHeaderScopes is configured header scopes other than Country and AS, sorted.
func extraHeaderScopes(bouncer *Bouncer) []string {
	extras := make([]string, 0)
	for scope := range bouncer.scopeHeaders {
		if scope == scopeCountry || scope == scopeAS {
			continue
		}
		extras = append(extras, scope)
	}
	sort.Strings(extras)
	return extras
}

// storeStreamDecision writes one stream New decision into the shared cache by scope.
func storeStreamDecision(bouncer *Bouncer, item Decision, duration int64) {
	value := remediationValue(item.Type)
	if value == "" {
		bouncer.log.Debug("handleStreamCache:unknownType " + item.Type)
		return
	}
	switch normalizeScope(item.Scope) {
	case scopeIP, "":
		bouncer.cacheClient.Set(ipCacheKey(item.Value), value, duration)
	case scopeRange:
		addRange(bouncer.cacheClient, item.Value, value, duration)
	case scopeCountry:
		code := normalizeCountry(item.Value)
		if code == "" {
			return
		}
		bouncer.cacheClient.Set(countryKey(code), value, duration)
	case scopeAS:
		asn := normalizeASN(item.Value)
		if asn == "" {
			return
		}
		bouncer.cacheClient.Set(asKey(asn), value, duration)
	default:
		scope := normalizeScope(item.Scope)
		if _, ok := bouncer.scopeHeaders[scope]; !ok {
			bouncer.log.Debug("handleStreamCache:ignoredScope " + item.Scope)
			return
		}
		trimmed := strings.TrimSpace(item.Value)
		if trimmed == "" {
			return
		}
		bouncer.cacheClient.Set(headerScopeKey(scope, trimmed), value, duration)
	}
}

// deleteStreamDecision removes one stream Deleted decision from the shared cache.
func deleteStreamDecision(bouncer *Bouncer, item Decision) {
	switch normalizeScope(item.Scope) {
	case scopeIP, "":
		bouncer.cacheClient.Delete(ipCacheKey(item.Value))
		bouncer.cacheClient.Delete(item.Value)
	case scopeRange:
		removeRange(bouncer.cacheClient, item.Value)
	case scopeCountry:
		code := normalizeCountry(item.Value)
		if code != "" {
			bouncer.cacheClient.Delete(countryKey(code))
		}
	case scopeAS:
		asn := normalizeASN(item.Value)
		if asn != "" {
			bouncer.cacheClient.Delete(asKey(asn))
		}
	default:
		scope := normalizeScope(item.Scope)
		trimmed := strings.TrimSpace(item.Value)
		if trimmed != "" {
			bouncer.cacheClient.Delete(headerScopeKey(scope, trimmed))
		}
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

func mergeLiveScope(bouncer *Bouncer, chosen string, parsedDuration time.Duration, scope, identifier string, isLiveMode bool) (string, time.Duration) {
	if identifier == "" {
		return chosen, parsedDuration
	}
	headerChosen, headerDuration, headerErr := queryLiveDecisions(bouncer, "scope="+url.QueryEscape(scope)+"&value="+url.QueryEscape(identifier))
	if headerErr != nil {
		bouncer.log.Debug("handleNoStreamCache:scopeQuery " + scope + " " + headerErr.Error())
		return chosen, parsedDuration
	}
	cacheLiveScope(bouncer, headerScopeKey(scope, identifier), headerChosen, headerDuration, isLiveMode)
	next := preferRemediation(chosen, headerChosen)
	if next != chosen {
		return next, headerDuration
	}
	return chosen, parsedDuration
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
