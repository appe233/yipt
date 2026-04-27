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

func TestRenderRule_NOTRACK(t *testing.T) {
	r := &ir.IRRule{
		Chain: "PREROUTING",
		Proto: "udp",
		SPort: "53",
		Jump:  "NOTRACK",
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j NOTRACK") {
		t.Errorf("expected -j NOTRACK, got: %s", got)
	}
}

func TestRenderRule_CTZoneHelper(t *testing.T) {
	r := &ir.IRRule{
		Chain:  "PREROUTING",
		Proto:  "tcp",
		DPort:  "21",
		Zone:   5,
		Helper: "ftp",
		Jump:   "CT",
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j CT --zone 5 --helper ftp") {
		t.Errorf("expected -j CT --zone 5 --helper ftp, got: %s", got)
	}
}

func TestRenderRule_CTEvents(t *testing.T) {
	r := &ir.IRRule{
		Chain:    "PREROUTING",
		Jump:     "CT",
		CTEvents: []string{"new", "destroy"},
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "--ctevents new,destroy") {
		t.Errorf("expected --ctevents new,destroy, got: %s", got)
	}
}

func TestRenderRule_TCPMSSClamp(t *testing.T) {
	r := &ir.IRRule{
		Chain:          "FORWARD",
		Proto:          "tcp",
		Jump:           "TCPMSS",
		ClampMSSToPMTU: true,
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j TCPMSS --clamp-mss-to-pmtu") {
		t.Errorf("expected -j TCPMSS --clamp-mss-to-pmtu, got: %s", got)
	}
}

func TestRenderRule_TCPMSSSetMSS(t *testing.T) {
	r := &ir.IRRule{
		Chain:  "FORWARD",
		Proto:  "tcp",
		Jump:   "TCPMSS",
		SetMSS: 1400,
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j TCPMSS --set-mss 1400") {
		t.Errorf("expected -j TCPMSS --set-mss 1400, got: %s", got)
	}
}

func TestRenderRule_TCPFlags(t *testing.T) {
	r := &ir.IRRule{
		Chain:        "INPUT",
		Proto:        "tcp",
		TCPFlagsMask: "SYN,ACK,FIN,RST",
		TCPFlagsComp: "SYN",
		Jump:         "ACCEPT",
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "--tcp-flags SYN,ACK,FIN,RST SYN") {
		t.Errorf("expected --tcp-flags SYN,ACK,FIN,RST SYN, got: %s", got)
	}
}

func TestRenderRule_TCPFlagsNone(t *testing.T) {
	r := &ir.IRRule{
		Chain:        "INPUT",
		Proto:        "tcp",
		TCPFlagsMask: "ALL",
		TCPFlagsComp: "NONE",
		Jump:         "DROP",
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "--tcp-flags ALL NONE") {
		t.Errorf("expected --tcp-flags ALL NONE, got: %s", got)
	}
}

func TestRenderRule_Fragment(t *testing.T) {
	r := &ir.IRRule{
		IPVersion: 4,
		Chain:     "INPUT",
		Fragment:  true,
		Jump:      "DROP",
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, " -f ") && !strings.HasSuffix(got, " -f") {
		t.Errorf("expected -f flag, got: %s", got)
	}
	if !strings.Contains(got, "-j DROP") {
		t.Errorf("expected -j DROP, got: %s", got)
	}
}

func TestRenderRule_TCPOption(t *testing.T) {
	r := &ir.IRRule{
		Chain:     "INPUT",
		Proto:     "tcp",
		TCPOption: 7,
		Jump:      "DROP",
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "--tcp-option 7") {
		t.Errorf("expected --tcp-option 7, got: %s", got)
	}
}

func TestRenderIptablesRestore_RawTable(t *testing.T) {
	prog := &ir.Program{
		Tables: map[string]*ir.Table{
			"raw": {
				Name: "raw",
				Chains: []*ir.Chain{
					{
						Name:    "PREROUTING",
						BuiltIn: true,
						IRRules: []*ir.IRRule{
							{Chain: "PREROUTING", Proto: "udp", SPort: "53", Jump: "NOTRACK"},
						},
					},
					{
						Name:    "OUTPUT",
						BuiltIn: true,
					},
				},
			},
		},
	}
	output := RenderIptablesRestore(prog)
	if !strings.Contains(output, "*raw") {
		t.Error("expected *raw table header")
	}
	if !strings.Contains(output, ":PREROUTING ACCEPT [0:0]") {
		t.Error("expected :PREROUTING ACCEPT [0:0] policy line in raw table")
	}
	if !strings.Contains(output, ":OUTPUT ACCEPT [0:0]") {
		t.Error("expected :OUTPUT ACCEPT [0:0] policy line in raw table")
	}
	if !strings.Contains(output, "-j NOTRACK") {
		t.Error("expected NOTRACK rule emitted in raw table")
	}
	// raw must appear before filter in the output order.
	rawIdx := strings.Index(output, "*raw")
	filterIdx := strings.Index(output, "*filter")
	if filterIdx != -1 && rawIdx > filterIdx {
		t.Errorf("expected *raw before *filter, got raw=%d filter=%d", rawIdx, filterIdx)
	}
}

func TestRenderIptablesRestore_SecurityTable(t *testing.T) {
	prog := &ir.Program{
		Tables: map[string]*ir.Table{
			"security": {
				Name: "security",
				Chains: []*ir.Chain{
					{
						Name:    "INPUT",
						BuiltIn: true,
						IRRules: []*ir.IRRule{
							{Chain: "INPUT", Jump: "SECMARK", SelCtx: "system_u:object_r:http_t:s0"},
						},
					},
					{Name: "FORWARD", BuiltIn: true},
					{Name: "OUTPUT", BuiltIn: true},
				},
			},
			"filter": {
				Name:   "filter",
				Chains: []*ir.Chain{{Name: "INPUT", BuiltIn: true}},
			},
		},
	}
	output := RenderIptablesRestore(prog)
	if !strings.Contains(output, "*security") {
		t.Error("expected *security table header")
	}
	if !strings.Contains(output, ":FORWARD ACCEPT [0:0]") {
		t.Error("expected :FORWARD ACCEPT [0:0] policy line in security table")
	}
	if !strings.Contains(output, `-j SECMARK --selctx system_u:object_r:http_t:s0`) {
		t.Errorf("expected SECMARK rule in security table, got: %s", output)
	}
	// security must appear after filter in the output order.
	securityIdx := strings.Index(output, "*security")
	filterIdx := strings.Index(output, "*filter")
	if securityIdx < filterIdx {
		t.Errorf("expected *security after *filter, got security=%d filter=%d", securityIdx, filterIdx)
	}
}

func TestRenderRule_ConnmarkSaveMark(t *testing.T) {
	r := &ir.IRRule{
		Chain:    "POSTROUTING",
		Jump:     "CONNMARK",
		SaveMark: true,
		NfMask:   "0xff",
		CTMask:   "0xff",
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j CONNMARK --save-mark --nfmask 0xff --ctmask 0xff") {
		t.Errorf("expected -j CONNMARK --save-mark --nfmask 0xff --ctmask 0xff, got: %s", got)
	}
}

func TestRenderRule_ConnmarkRestoreMark(t *testing.T) {
	r := &ir.IRRule{
		Chain:       "PREROUTING",
		Jump:        "CONNMARK",
		RestoreMark: true,
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j CONNMARK --restore-mark") {
		t.Errorf("expected -j CONNMARK --restore-mark, got: %s", got)
	}
}

func TestRenderRule_ConnmarkSetMark(t *testing.T) {
	r := &ir.IRRule{
		Chain:   "POSTROUTING",
		Jump:    "CONNMARK",
		SetMark: "0x42",
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j CONNMARK --set-mark 0x42") {
		t.Errorf("expected -j CONNMARK --set-mark 0x42, got: %s", got)
	}
}

func TestRenderRule_ConnmarkMatch(t *testing.T) {
	r := &ir.IRRule{
		Chain:          "INPUT",
		MatchFragments: []string{"-m connmark --mark 0xff"},
		Jump:           "ACCEPT",
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-m connmark --mark 0xff") {
		t.Errorf("expected -m connmark --mark 0xff, got: %s", got)
	}
}

// === Phase 6: NFLOG / NFQUEUE / SET targets ===

func TestRenderRule_NFLOGAllOptions(t *testing.T) {
	r := &ir.IRRule{
		Chain:          "INPUT",
		Jump:           "NFLOG",
		NflogGroup:     2,
		NflogPrefix:    "DROPPED: ",
		NflogRange:     256,
		NflogThreshold: 5,
	}
	got := renderRules(r)[0]
	want := `-j NFLOG --nflog-group 2 --nflog-prefix "DROPPED: " --nflog-range 256 --nflog-threshold 5`
	if !strings.Contains(got, want) {
		t.Errorf("expected %q, got: %s", want, got)
	}
}

func TestRenderRule_NFLOGBareGroup(t *testing.T) {
	r := &ir.IRRule{
		Chain:      "INPUT",
		Jump:       "NFLOG",
		NflogGroup: 1,
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j NFLOG --nflog-group 1") {
		t.Errorf("expected -j NFLOG --nflog-group 1, got: %s", got)
	}
	if strings.Contains(got, "--nflog-prefix") {
		t.Errorf("expected no --nflog-prefix, got: %s", got)
	}
}

func TestRenderRule_NFQUEUENum(t *testing.T) {
	r := &ir.IRRule{
		Chain:       "FORWARD",
		Jump:        "NFQUEUE",
		QueueNum:    0,
		QueueNumSet: true,
		QueueBypass: true,
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j NFQUEUE --queue-num 0 --queue-bypass") {
		t.Errorf("expected -j NFQUEUE --queue-num 0 --queue-bypass, got: %s", got)
	}
}

func TestRenderRule_NFQUEUEBalance(t *testing.T) {
	r := &ir.IRRule{
		Chain:          "FORWARD",
		Jump:           "NFQUEUE",
		QueueBalance:   "0:3",
		QueueCPUFanout: true,
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j NFQUEUE --queue-balance 0:3 --queue-cpu-fanout") {
		t.Errorf("expected -j NFQUEUE --queue-balance 0:3 --queue-cpu-fanout, got: %s", got)
	}
}

func TestRenderRule_SETAdd(t *testing.T) {
	r := &ir.IRRule{
		Chain:      "INPUT",
		Jump:       "SET",
		AddSet:     "blocklist",
		SetFlags:   []string{"src"},
		SetExist:   true,
		SetTimeout: 3600,
	}
	got := renderRules(r)[0]
	want := "-j SET --add-set blocklist src --exist --timeout 3600"
	if !strings.Contains(got, want) {
		t.Errorf("expected %q, got: %s", want, got)
	}
}

func TestRenderRule_SETDelMultipleFlags(t *testing.T) {
	r := &ir.IRRule{
		Chain:    "INPUT",
		Jump:     "SET",
		DelSet:   "blocklist",
		SetFlags: []string{"src", "dst"},
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j SET --del-set blocklist src,dst") {
		t.Errorf("expected -j SET --del-set blocklist src,dst, got: %s", got)
	}
}

// -----------------------------------------------------------------------------
// Phase 7 — multi-dim match-set direction rendering.
// -----------------------------------------------------------------------------

func TestRenderRule_SetMatchSrcDefault(t *testing.T) {
	r := &ir.IRRule{
		Chain:    "INPUT",
		Src:      "nets",
		SrcIsSet: true,
		Jump:     "ACCEPT",
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-m set --match-set nets src") {
		t.Errorf("expected default direction 'src', got: %s", got)
	}
}

func TestRenderRule_SetMatchSrcMultiDim(t *testing.T) {
	r := &ir.IRRule{
		Chain:     "INPUT",
		Src:       "ipport",
		SrcIsSet:  true,
		SrcSetDir: "src,src",
		Jump:      "ACCEPT",
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-m set --match-set ipport src,src") {
		t.Errorf("expected 'src,src' direction tuple, got: %s", got)
	}
}

func TestRenderRule_SetMatchDstMultiDim(t *testing.T) {
	r := &ir.IRRule{
		Chain:     "INPUT",
		Dst:       "ipport",
		DstIsSet:  true,
		DstSetDir: "dst,dst",
		Jump:      "ACCEPT",
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-m set --match-set ipport dst,dst") {
		t.Errorf("expected 'dst,dst' direction tuple, got: %s", got)
	}
}

func TestRenderRule_SetMatchNegatedMultiDim(t *testing.T) {
	r := &ir.IRRule{
		Chain:     "INPUT",
		Src:       "ipport",
		SrcIsSet:  true,
		SrcNeg:    true,
		SrcSetDir: "src,dst",
		Jump:      "DROP",
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-m set ! --match-set ipport src,dst") {
		t.Errorf("expected negated multi-dim set match, got: %s", got)
	}
}

// === Phase 9 — packet-modification target rendering ===

func TestRenderRule_CLASSIFY(t *testing.T) {
	r := &ir.IRRule{Chain: "FORWARD", Jump: "CLASSIFY", SetClass: "1:10"}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j CLASSIFY --set-class 1:10") {
		t.Errorf("got: %s", got)
	}
}

func TestRenderRule_DSCPValue(t *testing.T) {
	r := &ir.IRRule{Chain: "FORWARD", Jump: "DSCP", SetDSCP: "46"}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j DSCP --set-dscp 46") {
		t.Errorf("got: %s", got)
	}
}

func TestRenderRule_DSCPClass(t *testing.T) {
	r := &ir.IRRule{Chain: "FORWARD", Jump: "DSCP", SetDSCPClass: "ef"}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j DSCP --set-dscp-class EF") {
		t.Errorf("expected upper-cased DSCP class, got: %s", got)
	}
}

func TestRenderRule_TOSSet(t *testing.T) {
	r := &ir.IRRule{Chain: "FORWARD", Jump: "TOS", SetTOS: "0x10"}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j TOS --set-tos 0x10") {
		t.Errorf("got: %s", got)
	}
}

func TestRenderRule_TOSAnd(t *testing.T) {
	r := &ir.IRRule{Chain: "FORWARD", Jump: "TOS", AndTOS: "0xff"}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j TOS --and-tos 0xff") {
		t.Errorf("got: %s", got)
	}
}

func TestRenderRule_ECN(t *testing.T) {
	r := &ir.IRRule{Chain: "PREROUTING", Jump: "ECN", ECNTCPRemove: true}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j ECN --ecn-tcp-remove") {
		t.Errorf("got: %s", got)
	}
}

func TestRenderRule_TTLTarget(t *testing.T) {
	v := 64
	r := &ir.IRRule{Chain: "FORWARD", Jump: "TTL", TTLSet: &v}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j TTL --ttl-set 64") {
		t.Errorf("got: %s", got)
	}
}

func TestRenderRule_HLTarget(t *testing.T) {
	v := 1
	r := &ir.IRRule{Chain: "FORWARD", Jump: "HL", HLDec: &v}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j HL --hl-dec 1") {
		t.Errorf("got: %s", got)
	}
}

func TestRenderRule_SECMARK(t *testing.T) {
	r := &ir.IRRule{Chain: "FORWARD", Jump: "SECMARK", SelCtx: "system_u:object_r:http_t:s0"}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j SECMARK --selctx system_u:object_r:http_t:s0") {
		t.Errorf("got: %s", got)
	}
}

func TestRenderRule_CONNSECMARKSave(t *testing.T) {
	r := &ir.IRRule{Chain: "FORWARD", Jump: "CONNSECMARK", ConnSecMarkSave: true}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j CONNSECMARK --save") {
		t.Errorf("got: %s", got)
	}
}

func TestRenderRule_CONNSECMARKRestore(t *testing.T) {
	r := &ir.IRRule{Chain: "FORWARD", Jump: "CONNSECMARK", ConnSecMarkRestore: true}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j CONNSECMARK --restore") {
		t.Errorf("got: %s", got)
	}
}

func TestRenderRule_SYNPROXY(t *testing.T) {
	r := &ir.IRRule{
		Chain: "INPUT", Jump: "SYNPROXY",
		SynproxyMSS: 1460, SynproxyWScale: 7,
		SynproxyTimestamp: true, SynproxySAckPerm: true,
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j SYNPROXY --mss 1460 --wscale 7 --timestamp --sack-perm") {
		t.Errorf("got: %s", got)
	}
}

func TestRenderRule_TEE(t *testing.T) {
	r := &ir.IRRule{Chain: "FORWARD", Jump: "TEE", Gateway: "10.0.0.2"}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j TEE --gateway 10.0.0.2") {
		t.Errorf("got: %s", got)
	}
}

func TestRenderRule_TRACE(t *testing.T) {
	r := &ir.IRRule{Chain: "PREROUTING", Jump: "TRACE"}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j TRACE") {
		t.Errorf("got: %s", got)
	}
}

func TestRenderRule_AUDIT(t *testing.T) {
	r := &ir.IRRule{Chain: "INPUT", Jump: "AUDIT", AuditType: "accept"}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j AUDIT --type accept") {
		t.Errorf("got: %s", got)
	}
}

func TestRenderRule_CHECKSUM(t *testing.T) {
	r := &ir.IRRule{Chain: "POSTROUTING", Jump: "CHECKSUM", ChecksumFill: true}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j CHECKSUM --checksum-fill") {
		t.Errorf("got: %s", got)
	}
}

func TestRenderRule_NETMAP(t *testing.T) {
	r := &ir.IRRule{Chain: "POSTROUTING", Jump: "NETMAP", NetmapTo: "192.168.100.0/24"}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j NETMAP --to 192.168.100.0/24") {
		t.Errorf("got: %s", got)
	}
}

func TestRenderRule_CLUSTERIP(t *testing.T) {
	r := &ir.IRRule{
		Chain: "PREROUTING", Jump: "CLUSTERIP",
		ClusterIPNew:        true,
		ClusterIPHashmode:   "sourceip",
		ClusterIPClusterMAC: "01:00:5e:01:02:03",
		ClusterIPTotalNodes: 4,
		ClusterIPLocalNode:  1,
		ClusterIPHashInit:   12345,
	}
	got := renderRules(r)[0]
	want := "-j CLUSTERIP --new --hashmode sourceip --clustermac 01:00:5e:01:02:03 --total-nodes 4 --local-node 1 --hash-init 12345"
	if !strings.Contains(got, want) {
		t.Errorf("want %q in %q", want, got)
	}
}

func TestRenderRule_IDLETIMER(t *testing.T) {
	r := &ir.IRRule{
		Chain: "FORWARD", Jump: "IDLETIMER",
		IdletimerTimeout: 600, IdletimerLabel: "metrics", IdletimerAlarm: true,
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j IDLETIMER --timeout 600 --label metrics --alarm") {
		t.Errorf("got: %s", got)
	}
}

func TestRenderRule_RATEEST(t *testing.T) {
	r := &ir.IRRule{
		Chain: "FORWARD", Jump: "RATEEST",
		RateestName: "eth0", RateestInterval: 250, RateestEwmalog: 2,
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j RATEEST --rateest-name eth0 --rateest-interval 250 --rateest-ewmalog 2") {
		t.Errorf("got: %s", got)
	}
}

func TestRenderRule_LED(t *testing.T) {
	r := &ir.IRRule{
		Chain: "FORWARD", Jump: "LED",
		LEDTriggerID: "http", LEDDelay: 500, LEDDelaySet: true, LEDAlwaysBlink: true,
	}
	got := renderRules(r)[0]
	if !strings.Contains(got, "-j LED --led-trigger-id http --led-delay 500 --led-always-blink") {
		t.Errorf("got: %s", got)
	}
}
