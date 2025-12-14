package main

import (
	"log"
	"net"
	"net/http"
	"slices"
	"strings"
)

var (
	trustedProxies = []string{}
)

// Tries to find the source address, especially for environments using reverse proxies such as NGINX
// If the requesting ip is trusted, we also trust headers such as X-Forwarded-For
func RealSource(r *http.Request) string {
	remoteAddr := r.RemoteAddr
	host, _, err := net.SplitHostPort(remoteAddr)

	if err != nil {
		log.Printf("[Error] RealSource: %v", err)
		host = remoteAddr // Set to default value
	}

	if !slices.Contains(trustedProxies, host) {
		// Address is not trusted; use normal remote address
		return host
	}

	xForwarded := r.Header.Get("X-Forwarded-For")
	if xForwarded != "" {
		parts := strings.Split(xForwarded, ",")
		return strings.TrimSpace(parts[0])
	}

	xRealIP := r.Header.Get("X-Real-IP")
	if xRealIP != "" {
		parts := strings.Split(xRealIP, ",")
		return strings.TrimSpace(parts[0])
	}
	return host
}

/*
Used for IPv6 addresses in ratelimitting, to prevent only blacklisting /128 ranges,
since most networks have at least a /64 address.
*/
func normalizeIP(host string) string {
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}

	if ip.To4() != nil {
		return ip.String()
	}

	masked := ip.Mask(net.CIDRMask(64, 128))
	return masked.String() + "/64"
}
