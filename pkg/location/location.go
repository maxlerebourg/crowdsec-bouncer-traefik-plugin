// Package location matches requests against a list of host and path locations.
package location

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"path"
	"strings"
)

const (
	hostChars = "abcdefghijklmnopqrstuvwxyz0123456789-._"
	pathChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~!$&'()+,=:@/"
)

type entry struct {
	host   string
	path   string
	prefix string
}

// Matcher holds the locations a request is compared to.
type Matcher struct {
	entries []entry
}

// NewMatcher builds a Matcher from entries written as /path or host/path.
func NewMatcher(locations []string) (*Matcher, error) {
	matcher := &Matcher{}
	for _, raw := range locations {
		location := strings.TrimSpace(raw)
		host, locationPath := "", location
		if !strings.HasPrefix(location, "/") {
			slash := strings.IndexByte(location, '/')
			if slash <= 0 {
				return nil, fmt.Errorf("location %q must be a path starting with / or host/path", location)
			}
			host = strings.TrimSuffix(strings.ToLower(location[:slash]), ".")
			locationPath = location[slash:]
			if !isHost(host) {
				return nil, fmt.Errorf("location %q: the host must be a domain name without port or wildcard", location)
			}
		}
		if !isCanonicalPath(locationPath) {
			return nil, fmt.Errorf("location %q: the path must be clean and use only letters, digits and -._~!$&'()+,=:@/", location)
		}
		if host == "" && locationPath == "/" {
			return nil, errors.New("location \"/\" matches every request, disable AppSec instead")
		}
		prefix := locationPath
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
		matcher.entries = append(matcher.entries, entry{host: host, path: locationPath, prefix: prefix})
	}
	return matcher, nil
}

// Contains reports whether the request path, and host when the location has one, falls in a location.
func (m *Matcher) Contains(req *http.Request) bool {
	if m == nil {
		return false
	}
	reqPath := req.URL.Path
	reqHost := ""
	for _, e := range m.entries {
		if reqPath != e.path && !strings.HasPrefix(reqPath, e.prefix) {
			continue
		}
		if e.host != "" {
			if reqHost == "" {
				reqHost = canonicalHost(req.Host)
			}
			if e.host != reqHost {
				continue
			}
		}
		return req.URL.EscapedPath() == reqPath && isCanonicalPath(reqPath)
	}
	return false
}

func canonicalHost(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		addr = host
	}
	return strings.TrimSuffix(strings.ToLower(addr), ".")
}

func isHost(host string) bool {
	return host != "" && !strings.HasPrefix(host, ".") && strings.Trim(host, hostChars) == ""
}

func isCanonicalPath(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.Trim(p, pathChars) != "" {
		return false
	}
	cleaned := path.Clean(p)
	if cleaned != "/" && strings.HasSuffix(p, "/") {
		cleaned += "/"
	}
	if cleaned != p {
		return false
	}
	for _, segment := range strings.Split(p, "/") {
		if segment != "" && strings.Trim(segment, ".") == "" {
			return false
		}
	}
	return true
}
