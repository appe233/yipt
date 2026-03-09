package sema

import (
	"net"
	"strings"
)

// IPVersion represents which IP version(s) a rule or resource applies to.
type IPVersion int

const (
	IPvUnknown IPVersion = 0
	IPv4Only   IPVersion = 4
	IPv6Only   IPVersion = 6
	IPvBoth    IPVersion = 46
)

// ClassifyAddr classifies a CIDR or IP address as IPv4-only, IPv6-only, or unknown.
func ClassifyAddr(addr string) IPVersion {
	// Try parsing as CIDR first.
	ip, _, err := net.ParseCIDR(addr)
	if err != nil {
		// Try plain IP.
		ip = net.ParseIP(addr)
		if ip == nil {
			return IPvUnknown
		}
	}
	if ip.To4() != nil {
		return IPv4Only
	}
	return IPv6Only
}

// ClassifyProto classifies a protocol string by IP version.
// "icmp" → IPv4Only, "ipv6-icmp" → IPv6Only, else IPvUnknown.
func ClassifyProto(proto string) IPVersion {
	switch strings.ToLower(proto) {
	case "icmp":
		return IPv4Only
	case "ipv6-icmp":
		return IPv6Only
	}
	return IPvUnknown
}

// Merge combines two IPVersion constraints.
// If both are set but conflict, the result is IPvBoth (meaning both rules are needed).
// If one is unknown, return the other.
func Merge(a, b IPVersion) IPVersion {
	if a == IPvUnknown {
		return b
	}
	if b == IPvUnknown {
		return a
	}
	if a == b {
		return a
	}
	// Contradictory (e.g. IPv4Only + IPv6Only) → IPvBoth (expand to both)
	return IPvBoth
}
