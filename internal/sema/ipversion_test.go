package sema

import "testing"

func TestClassifyAddr(t *testing.T) {
	tests := []struct {
		addr string
		want IPVersion
	}{
		{"192.168.1.0/24", IPv4Only},
		{"10.0.0.1", IPv4Only},
		{"0.0.0.0/0", IPv4Only},
		{"2001:db8::/32", IPv6Only},
		{"::1", IPv6Only},
		{"fe80::/10", IPv6Only},
		{"garbage", IPvUnknown},
		{"", IPvUnknown},
		{"not-an-ip", IPvUnknown},
	}
	for _, tc := range tests {
		got := ClassifyAddr(tc.addr)
		if got != tc.want {
			t.Errorf("ClassifyAddr(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

func TestClassifyProto(t *testing.T) {
	tests := []struct {
		proto string
		want  IPVersion
	}{
		{"icmp", IPv4Only},
		{"ICMP", IPv4Only},
		{"ipv6-icmp", IPv6Only},
		{"IPV6-ICMP", IPv6Only},
		{"tcp", IPvUnknown},
		{"udp", IPvUnknown},
		{"", IPvUnknown},
	}
	for _, tc := range tests {
		got := ClassifyProto(tc.proto)
		if got != tc.want {
			t.Errorf("ClassifyProto(%q) = %v, want %v", tc.proto, got, tc.want)
		}
	}
}

func TestMerge(t *testing.T) {
	tests := []struct {
		a, b IPVersion
		want IPVersion
	}{
		{IPvUnknown, IPv4Only, IPv4Only},
		{IPv4Only, IPvUnknown, IPv4Only},
		{IPv4Only, IPv4Only, IPv4Only},
		{IPv6Only, IPv6Only, IPv6Only},
		{IPvUnknown, IPvUnknown, IPvUnknown},
		{IPv4Only, IPv6Only, IPvBoth},
		{IPv6Only, IPv4Only, IPvBoth},
	}
	for _, tc := range tests {
		got := Merge(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("Merge(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
