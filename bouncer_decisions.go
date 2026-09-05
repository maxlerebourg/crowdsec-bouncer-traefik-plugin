package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

// requestScopeValues reads configured scope headers. Country and AS are normalized; others are trimmed.
func requestScopeValues(bouncer *Bouncer, req *http.Request) map[string]string {
	if len(bouncer.decisionScopeHeaders) == 0 {
		return nil
	}
	out := make(map[string]string, len(bouncer.decisionScopeHeaders))
	for scope, header := range bouncer.decisionScopeHeaders {
		value := normalizeHeaderScopeValue(scope, req.Header.Get(header))
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

// lookupCachedRemediation checks Ip, then Range, then every present header scope (ban over captcha).
// One GetMany loads the IP, present header-scope keys, and range-index (stream/alone).
// Redis GetMany is one GET per key until simpleredis grows MGET.
// Range verdicts live on range-index (cidr=remediation). Live/none expand Range via LAPI ?ip=.
func lookupCachedRemediation(bouncer *Bouncer, remoteIP string, scopes map[string]string) (string, error) {
	useRangeIndex := bouncer.crowdsecMode == configuration.StreamMode || bouncer.crowdsecMode == configuration.AloneMode
	found, err := bouncer.cacheClient.GetMany(lookupCacheKeys(remoteIP, scopes, useRangeIndex))
	if err != nil {
		return "", err
	}
	if value := found[remoteIP]; isActiveRemediation(value) {
		return value, nil
	}
	if useRangeIndex {
		if rangeValue := matchRangeFromIndex(found[rangeIndexKey], remoteIP); isActiveRemediation(rangeValue) {
			return rangeValue, nil
		}
	}
	chosen := ""
	for scope, identifier := range scopes {
		if identifier == "" {
			continue
		}
		chosen = preferRemediation(chosen, found[headerScopeKey(scope, identifier)])
	}
	if isActiveRemediation(chosen) {
		return chosen, nil
	}
	if value, ok := found[remoteIP]; ok {
		return value, nil
	}
	return "", errors.New(cache.CacheMiss)
}

// lookupCacheKeys is the first GetMany: IP, optional range-index, then present header scopes.
func lookupCacheKeys(remoteIP string, scopes map[string]string, useRangeIndex bool) []string {
	keys := []string{remoteIP}
	if useRangeIndex {
		keys = append(keys, rangeIndexKey)
	}
	for scope, identifier := range scopes {
		if identifier != "" {
			keys = append(keys, headerScopeKey(scope, identifier))
		}
	}
	return keys
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
	mapped := make([]string, 0, len(bouncer.decisionScopeHeaders))
	for scope := range bouncer.decisionScopeHeaders {
		mapped = append(mapped, streamScopeToken(scope))
	}
	sort.Strings(mapped)
	return strings.Join(append(parts, mapped...), ",")
}

// storeStreamDecision writes one stream New decision into the shared cache by scope.
func storeStreamDecision(bouncer *Bouncer, item Decision, duration int64) {
	value := remediationValue(item.Type)
	if value == "" {
		bouncer.log.Debug("handleStreamCache:unknownType " + item.Type)
		return
	}
	scope := normalizeScope(item.Scope)
	switch scope {
	case scopeIP, "":
		bouncer.cacheClient.Set(ipCacheKey(item.Value), value, duration)
	case scopeRange:
		addRange(bouncer.cacheClient, item.Value, value, duration)
	default:
		if _, ok := bouncer.decisionScopeHeaders[scope]; !ok {
			bouncer.log.Debug("handleStreamCache:ignoredScope " + item.Scope)
			return
		}
		identifier := normalizeHeaderScopeValue(scope, item.Value)
		if identifier == "" {
			return
		}
		bouncer.cacheClient.Set(headerScopeKey(scope, identifier), value, duration)
	}
}

// deleteStreamDecision removes one stream Deleted decision from the shared cache.
func deleteStreamDecision(bouncer *Bouncer, item Decision) {
	scope := normalizeScope(item.Scope)
	switch scope {
	case scopeIP, "":
		bouncer.cacheClient.Delete(ipCacheKey(item.Value))
		bouncer.cacheClient.Delete(item.Value)
	case scopeRange:
		removeRange(bouncer.cacheClient, item.Value)
	default:
		identifier := normalizeHeaderScopeValue(scope, item.Value)
		if identifier != "" {
			bouncer.cacheClient.Delete(headerScopeKey(scope, identifier))
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
