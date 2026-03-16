package codegen

import (
	"strings"
	"testing"

	"github.com/appe233/yipt/internal/ir"
)

func TestRenderRule_AcceptIPv4(t *testing.T) {
	r := &ir.IRRule{
		IPVersion: 4,
		Chain:     "INPUT",
		Jump:      "ACCEPT",
	}
	got := renderRules(r)[0]
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
	got := renderRules(r)[0]
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
	got := renderRules(r)[0]
	if strings.HasPrefix(got, "-4") || strings.HasPrefix(got, "-6") {
		t.Errorf("expected no IP version prefix for version 0, got: %s", got)
	}
}

func TestRenderRule_Return(t *testing.T) {
	r := &ir.IRRule{Chain: "MYCHAIN", Jump: "RETURN"}
	got := renderRules(r)[0]
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
	got := renderRules(r)[0]
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
	got := renderRules(r)[0]
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
	got := renderRules(r)[0]
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
	got := renderRules(r)[0]
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
	got := renderRules(r)[0]
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
	got := renderRules(r)[0]
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
	got := renderRules(r)[0]
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
	got := renderRules(r)[0]
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
	got := renderRules(r)[0]
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
	got := renderRules(r)[0]
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
	got := renderRules(r)[0]
	if strings.Contains(got, "multiport") {
		t.Errorf("unexpected multiport for single port, got: %s", got)
	}
	if !strings.Contains(got, "--dport 22") {
		t.Errorf("expected --dport 22, got: %s", got)
	}
}

func TestRenderRule_Masquerade(t *testing.T) {
	r := &ir.IRRule{
		Chain: "POSTROUTING",
		Jump:  "MASQUERADE",
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j MASQUERADE") {
		t.Errorf("expected -j MASQUERADE, got: %s", got)
	}
}

func TestRenderRule_MasqueradeWithToPorts(t *testing.T) {
	r := &ir.IRRule{
		Chain:   "POSTROUTING",
		Jump:    "MASQUERADE",
		ToPorts: "1024-65535",
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j MASQUERADE --to-ports 1024-65535") {
		t.Errorf("expected -j MASQUERADE --to-ports 1024-65535, got: %s", got)
	}
}

func TestRenderRule_SNAT(t *testing.T) {
	r := &ir.IRRule{
		Chain:    "POSTROUTING",
		Jump:     "SNAT",
		ToSource: "203.0.113.1",
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j SNAT --to-source 203.0.113.1") {
		t.Errorf("expected -j SNAT --to-source, got: %s", got)
	}
}

func TestRenderRule_DNAT(t *testing.T) {
	r := &ir.IRRule{
		Chain:  "PREROUTING",
		Jump:   "DNAT",
		ToDest: "192.168.1.100",
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j DNAT --to-destination 192.168.1.100") {
		t.Errorf("expected -j DNAT --to-destination, got: %s", got)
	}
}

func TestRenderRule_Redirect(t *testing.T) {
	r := &ir.IRRule{
		Chain:   "PREROUTING",
		Jump:    "REDIRECT",
		ToPorts: "8080",
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j REDIRECT --to-ports 8080") {
		t.Errorf("expected -j REDIRECT --to-ports 8080, got: %s", got)
	}
}

func TestRenderRule_RedirectNoPorts(t *testing.T) {
	r := &ir.IRRule{
		Chain: "PREROUTING",
		Jump:  "REDIRECT",
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j REDIRECT") {
		t.Errorf("expected -j REDIRECT, got: %s", got)
	}
	if strings.Contains(got, "--to-ports") {
		t.Errorf("unexpected --to-ports in REDIRECT without ToPorts, got: %s", got)
	}
}

func TestRenderRule_MatchMAC(t *testing.T) {
	r := &ir.IRRule{
		IPVersion:      4,
		Chain:          "INPUT",
		Jump:           "ACCEPT",
		MatchFragments: []string{"-m mac --mac-source aa:bb:cc:dd:ee:ff"},
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-m mac --mac-source aa:bb:cc:dd:ee:ff") {
		t.Errorf("expected mac match fragment, got: %s", got)
	}
}

func TestRenderRule_MatchTime(t *testing.T) {
	r := &ir.IRRule{
		Chain:          "INPUT",
		Jump:           "DROP",
		MatchFragments: []string{"-m time --timestart 08:00 --timestop 18:00 --weekdays Mon,Tue,Wed,Thu,Fri"},
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-m time --timestart 08:00") {
		t.Errorf("expected time match fragment, got: %s", got)
	}
}

func TestRenderRule_MatchState(t *testing.T) {
	r := &ir.IRRule{
		Chain:          "INPUT",
		Jump:           "ACCEPT",
		MatchFragments: []string{"-m state --state ESTABLISHED,RELATED"},
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-m state --state ESTABLISHED,RELATED") {
		t.Errorf("expected state match fragment, got: %s", got)
	}
}

func TestMultiportCost(t *testing.T) {
	if multiportCost("80") != 1 {
		t.Error("single port should cost 1")
	}
	if multiportCost("1024:65535") != 2 {
		t.Error("port range should cost 2")
	}
}

func TestSplitMultiportEntries_Exact15(t *testing.T) {
	// 15 single ports → 1 chunk
	ports := "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15"
	chunks := splitMultiportEntries(ports)
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(chunks))
	}
	if chunks[0] != ports {
		t.Errorf("expected %s, got %s", ports, chunks[0])
	}
}

func TestSplitMultiportEntries_16Ports(t *testing.T) {
	// 16 single ports → 2 chunks (15 + 1)
	ports := "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16"
	chunks := splitMultiportEntries(ports)
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}
	if chunks[0] != "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15" {
		t.Errorf("first chunk wrong: %s", chunks[0])
	}
	if chunks[1] != "16" {
		t.Errorf("second chunk wrong: %s", chunks[1])
	}
}

func TestSplitMultiportEntries_RangeCosts2(t *testing.T) {
	// 14 single ports + 1 range = 14 + 2 = 16 > 15 → 2 chunks
	ports := "1,2,3,4,5,6,7,8,9,10,11,12,13,14,1024:65535"
	chunks := splitMultiportEntries(ports)
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}
	if chunks[0] != "1,2,3,4,5,6,7,8,9,10,11,12,13,14" {
		t.Errorf("first chunk wrong: %s", chunks[0])
	}
	if chunks[1] != "1024:65535" {
		t.Errorf("second chunk wrong: %s", chunks[1])
	}
}

func TestRenderRules_SplitDPort(t *testing.T) {
	r := &ir.IRRule{
		Chain:      "INPUT",
		Proto:      "tcp",
		DPort:      "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16",
		DPortMulti: true,
		Jump:       "ACCEPT",
	}
	lines := renderRules(r)
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	if !strings.Contains(lines[0], "--dports 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15") {
		t.Errorf("first line wrong: %s", lines[0])
	}
	if !strings.Contains(lines[1], "--dports 16") {
		t.Errorf("second line wrong: %s", lines[1])
	}
	// Both should have the jump target
	for i, l := range lines {
		if !strings.Contains(l, "-j ACCEPT") {
			t.Errorf("line %d missing jump: %s", i, l)
		}
	}
}

func TestRenderRules_CartesianProduct(t *testing.T) {
	// Both SPort and DPort exceed limit → cartesian product
	r := &ir.IRRule{
		Chain:      "FORWARD",
		Proto:      "tcp",
		SPort:      "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16",
		SPortMulti: true,
		DPort:      "21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36",
		DPortMulti: true,
		Jump:       "ACCEPT",
	}
	lines := renderRules(r)
	// 2 sport chunks × 2 dport chunks = 4 lines
	if len(lines) != 4 {
		t.Fatalf("expected 4 lines (cartesian product), got %d", len(lines))
	}
	// Verify each line has both --sports and --dports
	for i, l := range lines {
		if !strings.Contains(l, "--sports") {
			t.Errorf("line %d missing --sports: %s", i, l)
		}
		if !strings.Contains(l, "--dports") {
			t.Errorf("line %d missing --dports: %s", i, l)
		}
	}
}

func TestRenderRules_NoSplitUnderLimit(t *testing.T) {
	r := &ir.IRRule{
		Chain:      "INPUT",
		Proto:      "tcp",
		DPort:      "80,443,8080",
		DPortMulti: true,
		Jump:       "ACCEPT",
	}
	lines := renderRules(r)
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	if !strings.Contains(lines[0], "--dports 80,443,8080") {
		t.Errorf("expected original ports, got: %s", lines[0])
	}
}

func TestFilterRulesByVersion(t *testing.T) {
	rules := []*ir.IRRule{
		{IPVersion: 4, Chain: "INPUT", Jump: "ACCEPT"},
		{IPVersion: 6, Chain: "INPUT", Jump: "ACCEPT"},
		{IPVersion: 0, Chain: "INPUT", Jump: "DROP"},
	}

	// Filter for IPv4 - should get v4 and v0
	v4 := filterRulesByVersion(rules, 4)
	if len(v4) != 2 {
		t.Errorf("expected 2 rules for IPv4, got %d", len(v4))
	}

	// Filter for IPv6 - should get v6 and v0
	v6 := filterRulesByVersion(rules, 6)
	if len(v6) != 2 {
		t.Errorf("expected 2 rules for IPv6, got %d", len(v6))
	}

	// Filter for all (version 0) - should get all 3
	all := filterRulesByVersion(rules, 0)
	if len(all) != 3 {
		t.Errorf("expected 3 rules for version 0, got %d", len(all))
	}
}

func TestRenderIptablesRestoreIPv4(t *testing.T) {
	prog := &ir.Program{
		Tables: map[string]*ir.Table{
			"filter": {
				Name: "filter",
				Chains: []*ir.Chain{
					{
						Name:    "INPUT",
						Policy:  "DROP",
						BuiltIn: true,
						IRRules: []*ir.IRRule{
							{IPVersion: 4, Chain: "INPUT", Jump: "ACCEPT"},
							{IPVersion: 6, Chain: "INPUT", Jump: "DROP"},
							{IPVersion: 0, Chain: "INPUT", Proto: "tcp", DPort: "22", Jump: "ACCEPT"},
						},
					},
				},
			},
		},
	}

	output := RenderIptablesRestoreIPv4(prog)

	// Should contain IPv4 rule and version-0 rule, but not IPv6 rule
	if !strings.Contains(output, "*filter") {
		t.Error("expected *filter table")
	}
	if !strings.Contains(output, ":INPUT DROP") {
		t.Error("expected INPUT policy")
	}

	// Count rules - should have 2 (v4 + v0)
	ruleCount := strings.Count(output, "-A INPUT")
	if ruleCount != 2 {
		t.Errorf("expected 2 rules, got %d", ruleCount)
	}

	// Should NOT have -4 or -6 prefix
	if strings.Contains(output, "-4 -A") {
		t.Error("should not contain -4 prefix in IPv4-only output")
	}
	if strings.Contains(output, "-6 -A") {
		t.Error("should not contain -6 prefix in IPv4-only output")
	}
}

func TestRenderIptablesRestoreIPv6(t *testing.T) {
	prog := &ir.Program{
		Tables: map[string]*ir.Table{
			"filter": {
				Name: "filter",
				Chains: []*ir.Chain{
					{
						Name:    "INPUT",
						Policy:  "DROP",
						BuiltIn: true,
						IRRules: []*ir.IRRule{
							{IPVersion: 4, Chain: "INPUT", Jump: "ACCEPT"},
							{IPVersion: 6, Chain: "INPUT", Jump: "DROP"},
							{IPVersion: 0, Chain: "INPUT", Proto: "tcp", DPort: "22", Jump: "ACCEPT"},
						},
					},
				},
			},
		},
	}

	output := RenderIptablesRestoreIPv6(prog)

	// Should contain IPv6 rule and version-0 rule, but not IPv4 rule
	if !strings.Contains(output, "*filter") {
		t.Error("expected *filter table")
	}

	// Count rules - should have 2 (v6 + v0)
	ruleCount := strings.Count(output, "-A INPUT")
	if ruleCount != 2 {
		t.Errorf("expected 2 rules, got %d", ruleCount)
	}

	// Should NOT have -4 or -6 prefix
	if strings.Contains(output, "-4 -A") {
		t.Error("should not contain -4 prefix in IPv6-only output")
	}
	if strings.Contains(output, "-6 -A") {
		t.Error("should not contain -6 prefix in IPv6-only output")
	}
}

func TestRenderIptablesRestore_Combined(t *testing.T) {
	prog := &ir.Program{
		Tables: map[string]*ir.Table{
			"filter": {
				Name: "filter",
				Chains: []*ir.Chain{
					{
						Name:    "INPUT",
						Policy:  "ACCEPT",
						BuiltIn: true,
						IRRules: []*ir.IRRule{
							{IPVersion: 4, Chain: "INPUT", Jump: "ACCEPT"},
							{IPVersion: 6, Chain: "INPUT", Jump: "DROP"},
						},
					},
				},
			},
		},
	}

	output := RenderIptablesRestore(prog)

	// Should have -4 and -6 prefixes in combined mode
	if !strings.Contains(output, "-4 -A INPUT") {
		t.Error("expected -4 prefix in combined output")
	}
	if !strings.Contains(output, "-6 -A INPUT") {
		t.Error("expected -6 prefix in combined output")
	}
}
