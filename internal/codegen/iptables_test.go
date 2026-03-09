package codegen

import (
	"strings"
	"testing"

	"yipt/internal/ir"
)

func TestRenderRule_AcceptIPv4(t *testing.T) {
	r := &ir.IRRule{
		IPVersion: 4,
		Chain:     "INPUT",
		Jump:      "ACCEPT",
	}
	got := renderRule(r)
	if !strings.HasPrefix(got, "-4 ") {
		t.Errorf("expected -4 prefix, got: %s", got)
	}
	if !strings.Contains(got, "-j ACCEPT") {
		t.Errorf("expected -j ACCEPT, got: %s", got)
	}
}

func TestRenderRule_DropIPv6(t *testing.T) {
	r := &ir.IRRule{
		IPVersion: 6,
		Chain:     "INPUT",
		Jump:      "DROP",
	}
	got := renderRule(r)
	if !strings.HasPrefix(got, "-6 ") {
		t.Errorf("expected -6 prefix, got: %s", got)
	}
	if !strings.Contains(got, "-j DROP") {
		t.Errorf("expected -j DROP, got: %s", got)
	}
}

func TestRenderRule_NoPrefixVersion0(t *testing.T) {
	r := &ir.IRRule{
		IPVersion: 0,
		Chain:     "INPUT",
		Jump:      "ACCEPT",
	}
	got := renderRule(r)
	if strings.HasPrefix(got, "-4") || strings.HasPrefix(got, "-6") {
		t.Errorf("expected no IP version prefix for version 0, got: %s", got)
	}
}

func TestRenderRule_Return(t *testing.T) {
	r := &ir.IRRule{Chain: "MYCHAIN", Jump: "RETURN"}
	got := renderRule(r)
	if !strings.Contains(got, "-j RETURN") {
		t.Errorf("expected -j RETURN, got: %s", got)
	}
}

func TestRenderRule_RejectWithTCPReset(t *testing.T) {
	r := &ir.IRRule{
		Chain:      "INPUT",
		Jump:       "REJECT",
		RejectWith: "tcp-reset",
	}
	got := renderRule(r)
	if !strings.Contains(got, "-j REJECT --reject-with tcp-reset") {
		t.Errorf("expected reject-with tcp-reset, got: %s", got)
	}
}

func TestRenderRule_LogWithPrefix(t *testing.T) {
	r := &ir.IRRule{
		Chain:     "INPUT",
		Jump:      "LOG",
		LogPrefix: "iptables[DOS]: ",
	}
	got := renderRule(r)
	if !strings.Contains(got, `-j LOG --log-prefix "iptables[DOS]: "`) {
		t.Errorf("expected log prefix, got: %s", got)
	}
}

func TestRenderRule_Mark(t *testing.T) {
	r := &ir.IRRule{
		Chain:   "OUTPUT",
		Jump:    "MARK",
		SetMark: "1",
	}
	got := renderRule(r)
	if !strings.Contains(got, "-j MARK --set-mark 1") {
		t.Errorf("expected set-mark, got: %s", got)
	}
}

func TestRenderRule_TPROXY(t *testing.T) {
	r := &ir.IRRule{
		Chain:      "PREROUTING",
		Jump:       "TPROXY",
		OnIP:       "127.0.0.1",
		OnPort:     12345,
		TProxyMark: "1",
	}
	got := renderRule(r)
	if !strings.Contains(got, "-j TPROXY") {
		t.Errorf("expected -j TPROXY, got: %s", got)
	}
	if !strings.Contains(got, "--on-ip 127.0.0.1") {
		t.Errorf("expected --on-ip, got: %s", got)
	}
	if !strings.Contains(got, "--on-port 12345") {
		t.Errorf("expected --on-port, got: %s", got)
	}
	if !strings.Contains(got, "--tproxy-mark 1") {
		t.Errorf("expected --tproxy-mark, got: %s", got)
	}
}

func TestRenderRule_ICMPType(t *testing.T) {
	r := &ir.IRRule{
		IPVersion: 4,
		Chain:     "INPUT",
		Proto:     "icmp",
		ICMPType:  "0",
		Jump:      "ACCEPT",
	}
	got := renderRule(r)
	if !strings.Contains(got, "--icmp-type 0") {
		t.Errorf("expected --icmp-type 0, got: %s", got)
	}
}

func TestRenderRule_ICMPv6Type(t *testing.T) {
	r := &ir.IRRule{
		IPVersion:  6,
		Chain:      "INPUT",
		Proto:      "ipv6-icmp",
		ICMPv6Type: "128",
		Jump:       "ACCEPT",
	}
	got := renderRule(r)
	if !strings.Contains(got, "--icmpv6-type 128") {
		t.Errorf("expected --icmpv6-type 128, got: %s", got)
	}
}

func TestRenderRule_Comment(t *testing.T) {
	r := &ir.IRRule{
		Chain:   "INPUT",
		Jump:    "ACCEPT",
		Comment: "WireGuard peers",
	}
	got := renderRule(r)
	if !strings.Contains(got, `-m comment --comment "WireGuard peers"`) {
		t.Errorf("expected comment flag, got: %s", got)
	}
}

func TestRenderRule_NegatedInterface(t *testing.T) {
	r := &ir.IRRule{
		Chain:  "INPUT",
		In:     "lo",
		InNeg:  true,
		Jump:   "DROP",
	}
	got := renderRule(r)
	if !strings.Contains(got, "! -i lo") {
		t.Errorf("expected '! -i lo', got: %s", got)
	}
}

func TestRenderRule_IPSetSrc(t *testing.T) {
	r := &ir.IRRule{
		Chain:    "INPUT",
		Src:      "bgp_peers_v4",
		SrcIsSet: true,
		Jump:     "ACCEPT",
	}
	got := renderRule(r)
	if !strings.Contains(got, "-m set --match-set bgp_peers_v4 src") {
		t.Errorf("expected ipset match, got: %s", got)
	}
}

func TestRenderRule_MultiportDports(t *testing.T) {
	r := &ir.IRRule{
		Chain:      "INPUT",
		Proto:      "tcp",
		DPort:      "80,443",
		DPortMulti: true,
		Jump:       "ACCEPT",
	}
	got := renderRule(r)
	if !strings.Contains(got, "-m multiport --dports 80,443") {
		t.Errorf("expected multiport dports, got: %s", got)
	}
}

func TestRenderRule_SingleDport(t *testing.T) {
	r := &ir.IRRule{
		Chain: "INPUT",
		Proto: "tcp",
		DPort: "22",
		Jump:  "ACCEPT",
	}
	got := renderRule(r)
	if strings.Contains(got, "multiport") {
		t.Errorf("unexpected multiport for single port, got: %s", got)
	}
	if !strings.Contains(got, "--dport 22") {
		t.Errorf("expected --dport 22, got: %s", got)
	}
}
