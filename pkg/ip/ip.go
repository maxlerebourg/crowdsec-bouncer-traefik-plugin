// Package ip implements utility routines for to manipulates IP and CIDR.
// It allows to find on IP on a list, and find if an IP is part of a list of CIDR.
package ip

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// CHECKER

// Checker allows to check that addresses are in a trusted IPs.
type Checker struct {
	authorizedIPs    []*net.IP
	authorizedIPsNet []*net.IPNet
}

// NewChecker builds a new Checker given a list of CIDR-Strings to trusted IPs.
func NewChecker(trustedIPs []string) (*Checker, error) {
	checker := &Checker{}

	for _, ipMask := range trustedIPs {
		if ipAddr := net.ParseIP(ipMask); ipAddr != nil {
			checker.authorizedIPs = append(checker.authorizedIPs, &ipAddr)
			logger.Debug(fmt.Sprintf("IP %v is trusted", ipAddr))
			continue
		}

		_, ipAddr, err := net.ParseCIDR(ipMask)
		if err != nil {
			return nil, fmt.Errorf("parsing CIDR trusted IPs %s: %s", ipAddr, err.Error())
		}
		checker.authorizedIPsNet = append(checker.authorizedIPsNet, ipAddr)
		logger.Debug(fmt.Sprintf("IP network %v is trusted", ipAddr))
	}

	return checker, nil
}

// Contains checks if provided address is in the trusted IPs.
func (ip *Checker) Contains(addr string) (bool, error) {
	if len(addr) == 0 {
		return false, errors.New("Contains:noAddress")
	}

	ipAddr, err := parseIP(addr)
	if err != nil {
		return false, fmt.Errorf("Contains:parseAddress addr:%s %s", addr, err.Error())
	}

	return ip.ContainsIP(ipAddr), nil
}

// ContainsIP checks if provided address is in the trusted IPs.
func (ip *Checker) ContainsIP(addr net.IP) bool {
	for _, authorizedIP := range ip.authorizedIPs {
		if authorizedIP.Equal(addr) {
			return true
		}
	}

	for _, authorizedNet := range ip.authorizedIPsNet {
		if authorizedNet.Contains(addr) {
			return true
		}
	}

	return false
}

func parseIP(addr string) (net.IP, error) {
	userIP := net.ParseIP(addr)
	if userIP == nil {
		return nil, fmt.Errorf("parseIP:parseAddress %s", addr)
	}

	return userIP, nil
}

// STRATEGY

// PoolStrategy is a strategy based on an IP Checker.
// It allows to check whether addresses are in a given pool of IPs.
type PoolStrategy struct {
	Checker *Checker
}

// GetIP checks the list of Forwarded IPs (most recent first) against the
// Checker pool of IPs. It returns the first IP that is not in the pool, or the
// empty string otherwise.
func (s *PoolStrategy) getIP(req *http.Request, customHeader string) string {
	if s.Checker == nil {
		return ""
	}

	xff := req.Header.Get(customHeader)

	xffs := strings.Split(xff, ",")

	for i := len(xffs) - 1; i >= 0; i-- {
		xffTrimmed := strings.TrimSpace(xffs[i])
		if len(xffTrimmed) == 0 {
			continue
		}
		if contain, _ := s.Checker.Contains(xffTrimmed); !contain {
			return xffTrimmed
		}
	}

	return ""
}

// GetRemoteIP It returns the first IP that is not in the pool, or the empty string otherwise.
func GetRemoteIP(req *http.Request, strategy *PoolStrategy, customHeader string) (string, error) {
	remoteIP := strategy.getIP(req, customHeader)
	if len(remoteIP) != 0 {
		return remoteIP, nil
	}
	remoteIP, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return "", fmt.Errorf("GetRemoteIP:extractIP: %s", err.Error())
	}
	return remoteIP, nil
}
