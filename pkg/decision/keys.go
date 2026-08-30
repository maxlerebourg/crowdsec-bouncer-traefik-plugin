package decision

// Cache key prefixes so Country/AS/Range values do not collide with Ip keys.
const (
	countryKeyPrefix = "country:"
	asKeyPrefix      = "as:"
	rangeKeyPrefix   = "range:"
	rangeIndexKey    = "range-index"
	// rangeIndexTTL keeps the CIDR catalog longer than individual range keys.
	rangeIndexTTL = 365 * 24 * 3600
)

// CountryKey is the shared-cache key for a normalized country code.
func CountryKey(country string) string {
	return countryKeyPrefix + country
}

// ASKey is the shared-cache key for a normalized ASN.
func ASKey(asn string) string {
	return asKeyPrefix + asn
}

// RangeKey is the shared-cache key for one CIDR decision.
func RangeKey(cidr string) string {
	return rangeKeyPrefix + cidr
}
