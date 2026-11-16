// Package targets expands a single CLI target specification (a CIDR range,
// a bare IP, or a hostname) into the concrete list of hosts a scan module
// should probe.
//
// Before this package existed, recon.go's expandTarget/nextIP and
// dns.go's expandCIDR/incIP each reimplemented the same CIDR walk
// independently. They were not quite identical, though: recon's --target
// also accepts a bare hostname (falls back to treating unparseable input as
// a single host), while dns's --range is reverse-DNS-only and rejects
// anything that isn't a real CIDR/IP. ExpandCIDR and ExpandHostOrCIDR below
// keep that distinction explicit instead of silently picking one behavior
// for both callers.
package targets

import (
	"fmt"
	"net"
)

// ExpandCIDR expands spec into concrete IP addresses.
//
//   - A CIDR range (e.g. "192.168.1.0/24") expands to every address it
//     contains; for an IPv4 range with more than two addresses, the network
//     and broadcast addresses are dropped (never useful scan targets).
//   - A bare IP address expands to itself.
//   - Anything else is an error — spec is not a usable IP/CIDR target.
//
// Use this for inputs that must be an IP or CIDR (e.g. reverse-DNS lookup by
// range). For an input that may also legitimately be a hostname, use
// ExpandHostOrCIDR instead.
func ExpandCIDR(spec string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(spec)
	if err != nil {
		if parsed := net.ParseIP(spec); parsed != nil {
			return []string{spec}, nil
		}
		return nil, fmt.Errorf("%q is not a valid IP address or CIDR range", spec)
	}

	var ips []string
	for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); cur = nextIP(cur) {
		ips = append(ips, cur.String())
	}

	if ip.To4() != nil && len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

// ExpandHostOrCIDR behaves like ExpandCIDR, but falls back to treating spec
// as a single hostname — rather than returning an error — when it is
// neither a valid CIDR range nor a valid IP address. Use this for inputs
// that may be a hostname, a single IP, or a CIDR range (e.g. a scan
// target).
func ExpandHostOrCIDR(spec string) ([]string, error) {
	ips, err := ExpandCIDR(spec)
	if err != nil {
		return []string{spec}, nil
	}
	return ips, nil
}

// nextIP returns ip incremented by one, without mutating the input.
func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}
