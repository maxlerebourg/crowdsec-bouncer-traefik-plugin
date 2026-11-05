// Package location matches requests against a list of host and path locations.
package location

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
)

const (
	hostChars = "abcdefghijklmnopqrstuvwxyz0123456789-._"
	pathChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~!$&'()+,=:@/"
)

type entry struct {
	host   string
	port   string
	path   string
	prefix string
}

// Matcher holds the locations a request is compared to.
type Matcher struct {
	entries []entry
}

// NewMatcher builds a Matcher from entries written as /path, host or host/path.
func NewMatcher(locations []string) (*Matcher, error) {
	matcher := &Matcher{}
	for _, raw := range locations {
		loc := strings.TrimSpace(raw)
		host, locationPath, port := "", loc, ""
		if !strings.HasPrefix(loc, "/") {
			slash := strings.IndexByte(loc, '/')
			if slash < 0 {
				slash = len(loc)
			}
			if slash == 0 {
				return nil, fmt.Errorf("location %q must be a path starting with /, or a host optionally followed by a path", loc)
			}
			var err error
			host, port, err = parseHost(loc[:slash])
			if err != nil {
				return nil, fmt.Errorf("location %q: %w", loc, err)
			}
			locationPath = "/"
			if slash < len(loc) {
				locationPath = loc[slash:]
			}
		}
		if !isCanonicalPath(locationPath) {
			return nil, fmt.Errorf("location %q: the path must be clean and use only letters, digits and -._~!$&'()+,=:@/", loc)
		}
		if host == "" && locationPath == "/" {
			return nil, errors.New("location \"/\" matches every request, disable AppSec instead")
		}
		prefix := locationPath
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
		matcher.entries = append(matcher.entries, entry{host: host, port: port, path: locationPath, prefix: prefix})
	}
	return matcher, nil
}

// Contains reports whether the request path, and host when the location has one, falls in a location.
func (m *Matcher) Contains(req *http.Request) bool {
	if m == nil {
		return false
	}
	reqPath := req.URL.Path
	reqHost, reqPort := "", ""
	for _, e := range m.entries {
		if reqPath != e.path && !strings.HasPrefix(reqPath, e.prefix) {
			continue
		}
		if e.host != "" {
			if reqHost == "" {
				reqHost, reqPort = canonicalHost(req.Host)
			}
			if e.host != reqHost || (e.port != "" && e.port != reqPort) {
				continue
			}
		}
		return req.URL.EscapedPath() == reqPath && isCanonicalPath(reqPath)
	}
	return false
}

func parseHost(addr string) (string, string, error) {
	host, port := addr, ""
	if h, p, err := net.SplitHostPort(addr); err == nil {
		number, err := strconv.ParseUint(p, 10, 16)
		if err != nil || number == 0 {
			return "", "", errors.New("the port must be a number between 1 and 65535")
		}
		host = h
		port = strconv.FormatUint(number, 10)
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if !isHost(host) {
		return "", "", errors.New("the host must be a domain name, without wildcard")
	}
	return host, port, nil
}

func canonicalHost(addr string) (string, string) {
	host, port := addr, ""
	if h, p, err := net.SplitHostPort(addr); err == nil {
		host, port = h, p
	}
	if number, err := strconv.ParseUint(port, 10, 16); err == nil {
		port = strconv.FormatUint(number, 10)
	}
	return strings.TrimSuffix(strings.ToLower(host), "."), port
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
