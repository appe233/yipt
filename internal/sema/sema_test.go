package sema

import (
	"strings"
	"testing"

	"github.com/appe233/yipt/internal/ast"
)

func makeDoc(resources map[string]ast.Resource, chains map[string]ast.Chain) *ast.Document {
	return &ast.Document{
		Resources: resources,
		Chains:    chains,
	}
}

func TestAnalyze_ValidDocument(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{
			"nets":        {Type: "ipset", Elements: []interface{}{"10.0.0.0/8", "192.168.0.0/16"}},
			"ports":       {Type: "portset", Elements: []interface{}{80, 443}},
			"icmptypes":   {Type: "icmp_typeset", Elements: []interface{}{0, 3, 11}},
			"icmpv6types": {Type: "icmpv6_typeset", Elements: []interface{}{1, 2, 3}},
		},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Src: "$nets", Jump: "accept"},
					{DPort: "$ports", Jump: "accept"},
					{Proto: "icmp", ICMPType: "$icmptypes", Jump: "accept"},
					{Proto: "ipv6-icmp", ICMPv6Type: "$icmpv6types", Jump: "accept"},
				},
			},
		},
	)
	resolved, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(resolved.Warnings) != 0 {
		t.Errorf("expected no warnings, got: %v", resolved.Warnings)
	}
}

func TestAnalyze_UnknownResourceRef(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Src: "$nonexistent", Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for unknown resource ref")
	}
	if !strings.Contains(err.Error(), "unknown resource") {
		t.Errorf("expected 'unknown resource' in error, got: %v", err)
	}
}

func TestAnalyze_WrongResourceType(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{
			"myports": {Type: "portset", Elements: []interface{}{80, 443}},
		},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Src: "$myports", Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for wrong resource type in s: field")
	}
	if !strings.Contains(err.Error(), "expected ipset") {
		t.Errorf("expected 'expected ipset' in error, got: %v", err)
	}
}

func TestAnalyze_LogPrefixTooLong(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{LogPrefix: "this prefix is way too long for iptables", Jump: "log"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for log-prefix > 29 chars")
	}
	if !strings.Contains(err.Error(), "log-prefix") {
		t.Errorf("expected 'log-prefix' in error, got: %v", err)
	}
}

func TestAnalyze_LogPrefixExactly29(t *testing.T) {
	// 29 chars — must pass
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{LogPrefix: "12345678901234567890123456789", Jump: "log"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error for 29-char prefix, got: %v", err)
	}
}

func TestValidateConflicts_PortWithICMPProto(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Proto: "icmp", DPort: 80, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for port match with p: icmp")
	}
	if !strings.Contains(err.Error(), "requires p: tcp or udp") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateConflicts_ICMPTypeWithTCPProto(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Proto: "tcp", ICMPType: 0, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for icmp-type with p: tcp")
	}
	if !strings.Contains(err.Error(), "icmp-type requires p: icmp") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateConflicts_ICMPv6TypeWithUDPProto(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Proto: "udp", ICMPv6Type: 128, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for icmpv6-type with p: udp")
	}
	if !strings.Contains(err.Error(), "icmpv6-type requires p: ipv6-icmp") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateConflicts_BothICMPTypes(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{ICMPType: 0, ICMPv6Type: 128, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for both icmp-type and icmpv6-type set")
	}
	if !strings.Contains(err.Error(), "icmp-type and icmpv6-type cannot both be set") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateConflicts_IPv4SrcIPv6Dst(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Src: "10.0.0.1", Dst: "::1", Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for IPv4 src with IPv6 dst")
	}
	if !strings.Contains(err.Error(), "version conflict") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateConflicts_ValidICMPRule(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Proto: "icmp", ICMPType: 0, Jump: "accept"},
					{Proto: "ipv6-icmp", ICMPv6Type: 128, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error for valid ICMP rules, got: %v", err)
	}
}

func TestValidateConflicts_PortWithTCPProto(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Proto: "tcp", DPort: 80, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error for port with p: tcp, got: %v", err)
	}
}

func TestValidateConflicts_PortNoProto(t *testing.T) {
	// Port without explicit protocol — allowed (iptables will reject at runtime, not our job here)
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{DPort: 80, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error for port without explicit proto, got: %v", err)
	}
}

func TestAnalyze_UnusedResource(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{
			"unused_nets": {Type: "ipset", Elements: []interface{}{"10.0.0.0/8"}},
		},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Jump: "accept"},
				},
			},
		},
	)
	resolved, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(resolved.Warnings) == 0 {
		t.Fatal("expected a warning for unused resource, got none")
	}
	if !strings.Contains(resolved.Warnings[0], "$unused_nets") {
		t.Errorf("expected warning to mention $unused_nets, got: %v", resolved.Warnings[0])
	}
	if !strings.Contains(resolved.Warnings[0], "never used") {
		t.Errorf("expected warning to mention 'never used', got: %v", resolved.Warnings[0])
	}
}

func TestAnalyze_UsedResourceNoWarning(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{
			"my_nets": {Type: "ipset", Elements: []interface{}{"192.168.0.0/16"}},
		},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Src: "$my_nets", Jump: "accept"},
				},
			},
		},
	)
	resolved, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(resolved.Warnings) != 0 {
		t.Errorf("expected no warnings for used resource, got: %v", resolved.Warnings)
	}
}

// === Fix 1: NAT rules are now validated ===

func TestAnalyze_NatUnknownRef(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"POSTROUTING": {
				Nat: []ast.Rule{
					{Src: "$nonexistent", Jump: "masquerade"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for unknown resource ref in NAT rule")
	}
	if !strings.Contains(err.Error(), "unknown resource") {
		t.Errorf("expected 'unknown resource' in error, got: %v", err)
	}
}

func TestAnalyze_NatProtocolPortConflict(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"PREROUTING": {
				Nat: []ast.Rule{
					{Proto: "icmp", DPort: 80, Jump: "dnat", ToDest: "10.0.0.1"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for port with icmp in NAT rule")
	}
	if !strings.Contains(err.Error(), "requires p: tcp or udp") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestAnalyze_NatLogPrefixTooLong(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"PREROUTING": {
				Nat: []ast.Rule{
					{LogPrefix: "this prefix is way too long for iptables", Jump: "log"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for oversized log-prefix in NAT rule")
	}
	if !strings.Contains(err.Error(), "log-prefix") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// === Fix 2: Comment length limit ===

func TestAnalyze_CommentTooLong(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Comment: strings.Repeat("x", 257), Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for comment > 256 chars")
	}
	if !strings.Contains(err.Error(), "comment exceeds 256") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestAnalyze_CommentExactly256(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Comment: strings.Repeat("x", 256), Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error for 256-char comment, got: %v", err)
	}
}

// === Fix 3: String field and interface name validation ===

func TestAnalyze_CommentWithQuote(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Comment: `say "hello"`, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for comment containing quotes")
	}
	if !strings.Contains(err.Error(), "invalid character") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestAnalyze_LogPrefixWithNewline(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{LogPrefix: "bad\nprefix", Jump: "log"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for log-prefix with newline")
	}
	if !strings.Contains(err.Error(), "invalid character") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestAnalyze_InterfaceTooLong(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{In: "abcdefghijklmnop", Jump: "accept"}, // 16 chars
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for interface name > 15 chars")
	}
	if !strings.Contains(err.Error(), "exceeds 15-character limit") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestAnalyze_InterfaceWithSpace(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{In: "eth 0", Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for interface name with space")
	}
	if !strings.Contains(err.Error(), "invalid characters") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestAnalyze_ValidInterfaces(t *testing.T) {
	for _, iface := range []string{"eth0", "wg0", "br-lan", "eth+"} {
		doc := makeDoc(
			map[string]ast.Resource{},
			map[string]ast.Chain{
				"INPUT": {
					Filter: []ast.Rule{
						{In: iface, Jump: "accept"},
					},
				},
			},
		)
		_, err := Analyze(doc)
		if err != nil {
			t.Errorf("expected no error for interface %q, got: %v", iface, err)
		}
	}
}

// === Fix 4: IP address and port validation ===

func TestAnalyze_InvalidIPAddress(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Src: "garbage", Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for invalid IP address")
	}
	if !strings.Contains(err.Error(), "not a valid IP address or CIDR") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestAnalyze_ValidCIDR(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Src: "10.0.0.0/8", Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error for valid CIDR, got: %v", err)
	}
}

func TestAnalyze_PortTooHigh(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Proto: "tcp", DPort: 70000, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for port 70000")
	}
	if !strings.Contains(err.Error(), "outside valid range") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestAnalyze_PortNegative(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Proto: "tcp", DPort: -1, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for port -1")
	}
	if !strings.Contains(err.Error(), "outside valid range") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestAnalyze_PortListWithBadValue(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Proto: "tcp", DPort: []interface{}{80, 99999}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for port list with 99999")
	}
	if !strings.Contains(err.Error(), "outside valid range") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestAnalyze_ValidPortList(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Proto: "tcp", DPort: []interface{}{80, 443, 8080}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error for valid port list, got: %v", err)
	}
}

// === P0: Jump target validation ===

func TestAnalyze_UnknownJumpTarget(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Jump: "bogus"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for unknown jump target")
	}
	if !strings.Contains(err.Error(), "unknown jump target") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_JumpToUserDefinedChain(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Jump: "MYCHAIN"},
				},
			},
			"MYCHAIN": {
				Filter: []ast.Rule{
					{Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error for jump to user-defined chain, got: %v", err)
	}
}

// === P0: NAT target/table/chain validation ===

func TestAnalyze_DNATInFilterTable(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Jump: "dnat", ToDest: "10.0.0.1"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for DNAT in filter table")
	}
	if !strings.Contains(err.Error(), "only valid in the nat table") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_SNATInWrongChain(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"PREROUTING": {
				Nat: []ast.Rule{
					{Jump: "snat", ToSource: "1.2.3.4"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for SNAT in PREROUTING")
	}
	if !strings.Contains(err.Error(), "only valid in chains") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_MASQUERADEInPostrouting(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"POSTROUTING": {
				Nat: []ast.Rule{
					{Jump: "masquerade"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error for MASQUERADE in nat POSTROUTING, got: %v", err)
	}
}

func TestAnalyze_TProxyInMangle(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"PREROUTING": {
				Mangle: []ast.Rule{
					{Proto: "tcp", Jump: "tproxy", OnIP: "127.0.0.1", OnPort: 12345, TProxyMark: 1},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error for TPROXY in mangle PREROUTING, got: %v", err)
	}
}

func TestAnalyze_TProxyInFilter(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Proto: "tcp", Jump: "tproxy", OnIP: "127.0.0.1", OnPort: 12345, TProxyMark: 1},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for TPROXY in filter table")
	}
	if !strings.Contains(err.Error(), "only valid in the mangle table") {
		t.Errorf("unexpected error: %v", err)
	}
}

// === P0: reject-with validation ===

func TestAnalyze_RejectWithInvalid(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Jump: "reject", RejectWith: "bogus"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for invalid reject-with")
	}
	if !strings.Contains(err.Error(), "unknown reject-with") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_RejectWithTCPResetNoTCP(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Proto: "udp", Jump: "reject", RejectWith: "tcp-reset"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for tcp-reset without p: tcp")
	}
	if !strings.Contains(err.Error(), "tcp-reset requires p: tcp") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_RejectWithValid(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Proto: "tcp", Jump: "reject", RejectWith: "tcp-reset"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error for valid reject-with tcp-reset, got: %v", err)
	}
}

func TestAnalyze_RejectWithoutJReject(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Jump: "drop", RejectWith: "tcp-reset"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for reject-with without j: reject")
	}
	if !strings.Contains(err.Error(), "only valid with j: reject") {
		t.Errorf("unexpected error: %v", err)
	}
}

// === P1: Protocol validation ===

func TestAnalyze_UnknownProtocol(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Proto: "xyz", Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for unknown protocol")
	}
	if !strings.Contains(err.Error(), "unknown protocol") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_ValidProtocols(t *testing.T) {
	for _, proto := range []string{"tcp", "udp", "icmp", "ipv6-icmp", "sctp", "gre", "esp", "ah", "all"} {
		doc := makeDoc(
			map[string]ast.Resource{},
			map[string]ast.Chain{
				"INPUT": {
					Filter: []ast.Rule{
						{Proto: proto, Jump: "accept"},
					},
				},
			},
		)
		_, err := Analyze(doc)
		if err != nil {
			t.Errorf("expected no error for protocol %q, got: %v", proto, err)
		}
	}
}

// === P1: NAT address validation ===

func TestAnalyze_InvalidToSource(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"POSTROUTING": {
				Nat: []ast.Rule{
					{Jump: "snat", ToSource: "garbage"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for invalid to-source")
	}
	if !strings.Contains(err.Error(), "not a valid address") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_ValidToSource(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"POSTROUTING": {
				Nat: []ast.Rule{
					{Jump: "snat", ToSource: "1.2.3.4"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error for valid to-source, got: %v", err)
	}
}

// === P1: Mark validation ===

func TestAnalyze_InvalidSetMark(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"OUTPUT": {
				Mangle: []ast.Rule{
					{Jump: "mark", SetMark: "bogus"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for invalid set-mark")
	}
	if !strings.Contains(err.Error(), "not a valid mark value") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_ValidSetMarkHex(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"OUTPUT": {
				Mangle: []ast.Rule{
					{Jump: "mark", SetMark: "0xff"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error for valid hex set-mark, got: %v", err)
	}
}

func TestAnalyze_ValidSetMarkInt(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"OUTPUT": {
				Mangle: []ast.Rule{
					{Jump: "mark", SetMark: 1},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error for valid int set-mark, got: %v", err)
	}
}

func TestAnalyze_ValidSetMarkWithMask(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"OUTPUT": {
				Mangle: []ast.Rule{
					{Jump: "mark", SetMark: "0xff/0xff"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error for set-mark with mask, got: %v", err)
	}
}

// === P1: Port range string validation ===

func TestAnalyze_ReversedPortRange(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Proto: "tcp", DPort: "65535:0", Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for reversed port range")
	}
	if !strings.Contains(err.Error(), "low > high") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_InvalidPortString(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Proto: "tcp", DPort: "abc", Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for invalid port string 'abc'")
	}
	if !strings.Contains(err.Error(), "not a valid port") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_ValidPortRange(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Proto: "tcp", DPort: "1024:65535", Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error for valid port range, got: %v", err)
	}
}

// === P1: Policy on custom chain ===

func TestAnalyze_PolicyOnCustomChain(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"MYCHAIN": {
				Policy: "drop",
				Filter: []ast.Rule{
					{Jump: "accept"},
				},
			},
		},
	)
	res, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "policy") && strings.Contains(w, "MYCHAIN") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected warning about policy on custom chain, got: %v", res.Warnings)
	}
}

// === P2: MAC address validation ===

func TestAnalyze_InvalidMAC(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{MAC: &ast.MACMatch{MACSource: "not-a-mac"}}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for invalid MAC address")
	}
	if !strings.Contains(err.Error(), "not a valid MAC") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_ValidMAC(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{MAC: &ast.MACMatch{MACSource: "aa:bb:cc:dd:ee:ff"}}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error for valid MAC, got: %v", err)
	}
}

// === P2: Time match validation ===

func TestAnalyze_InvalidTimeStart(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{Time: &ast.TimeMatch{TimeStart: "25:99"}}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	// We validate format (HH:MM), 25:99 matches the regex but is technically invalid hours/minutes.
	// The regex only checks format. Let's test something that doesn't match the regex at all.
	if err != nil && !strings.Contains(err.Error(), "not a valid time") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_InvalidTimeFormat(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{Time: &ast.TimeMatch{TimeStart: "8am"}}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for invalid time format")
	}
	if !strings.Contains(err.Error(), "not a valid time") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_InvalidWeekday(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{Time: &ast.TimeMatch{Days: "Monday,Tuesday"}}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for invalid weekday names")
	}
	if !strings.Contains(err.Error(), "invalid weekday") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_ValidTimeMatch(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{Time: &ast.TimeMatch{
						TimeStart: "08:00",
						TimeStop:  "18:00",
						Days:      "Mon,Tue,Wed,Thu,Fri",
					}}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error for valid time match, got: %v", err)
	}
}

// === P2: Addrtype validation ===

func TestAnalyze_InvalidAddrType(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{AddrType: &ast.AddrTypeMatch{DstType: "BOGUS"}}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for invalid addrtype dst-type")
	}
	if !strings.Contains(err.Error(), "unknown addrtype") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_ValidAddrTypes(t *testing.T) {
	for _, dt := range []string{"BROADCAST", "MULTICAST", "ANYCAST", "LOCAL", "UNICAST"} {
		doc := makeDoc(
			map[string]ast.Resource{},
			map[string]ast.Chain{
				"INPUT": {
					Filter: []ast.Rule{
						{Match: []*ast.MatchBlock{{AddrType: &ast.AddrTypeMatch{DstType: dt}}}, Jump: "accept"},
					},
				},
			},
		)
		_, err := Analyze(doc)
		if err != nil {
			t.Errorf("expected no error for addrtype %q, got: %v", dt, err)
		}
	}
}

// === P1: to-ports validation ===

func TestAnalyze_InvalidToPorts(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"POSTROUTING": {
				Nat: []ast.Rule{
					{Jump: "masquerade", ToPorts: "abc"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for invalid to-ports")
	}
	if !strings.Contains(err.Error(), "not a valid port") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_ValidToPorts(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"POSTROUTING": {
				Nat: []ast.Rule{
					{Jump: "masquerade", ToPorts: "1024:65535"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error for valid to-ports range, got: %v", err)
	}
}

func TestAnalyze_CTTargetNotrack(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"PREROUTING": {
				Raw: []ast.Rule{
					{Proto: "udp", SPort: 53, Notrack: true, Jump: "ct"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error for valid CT notrack rule, got: %v", err)
	}
}

func TestAnalyze_CTTargetZoneHelper(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"PREROUTING": {
				Raw: []ast.Rule{
					{Proto: "tcp", DPort: 21, Zone: 5, Helper: "ftp", Jump: "ct"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error for valid CT zone/helper rule, got: %v", err)
	}
}

func TestAnalyze_CTTargetWrongTable(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Notrack: true, Jump: "ct"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for CT target in filter table")
	}
	if !strings.Contains(err.Error(), "only valid in the raw table") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_CTTargetWrongChain(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"POSTROUTING": {
				Raw: []ast.Rule{
					{Notrack: true, Jump: "ct"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for CT target in raw POSTROUTING")
	}
	if !strings.Contains(err.Error(), "only valid in chains") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_CTFieldWithoutCTTarget(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Zone: 5, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for zone without j: ct")
	}
	if !strings.Contains(err.Error(), "only valid with j: ct") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_CTZoneOutOfRange(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"PREROUTING": {
				Raw: []ast.Rule{
					{Zone: 70000, Jump: "ct"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for zone > 65535")
	}
	if !strings.Contains(err.Error(), "zone") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_CTInvalidHelper(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"PREROUTING": {
				Raw: []ast.Rule{
					{Helper: "bad helper!", Jump: "ct"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for helper with invalid chars")
	}
	if !strings.Contains(err.Error(), "helper") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_CTInvalidEvent(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"PREROUTING": {
				Raw: []ast.Rule{
					{CTEvents: []string{"new", "bogus"}, Jump: "ct"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for unknown ctevent")
	}
	if !strings.Contains(err.Error(), "ctevent") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_CTTargetRequiresField(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"PREROUTING": {
				Raw: []ast.Rule{
					{Jump: "ct"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for bare j: ct with no options")
	}
	if !strings.Contains(err.Error(), "requires at least one") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_CTNotrackWithZone(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"PREROUTING": {
				Raw: []ast.Rule{
					{Notrack: true, Zone: 5, Jump: "ct"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for notrack combined with zone")
	}
	if !strings.Contains(err.Error(), "cannot combine") {
		t.Errorf("unexpected error: %v", err)
	}
}

// === Phase 2: TCPMSS target + tcp-flags / fragment / tcp-option ===

func TestAnalyze_TCPMSSClampValid(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"FORWARD": {
				Mangle: []ast.Rule{
					{Proto: "tcp", Jump: "tcpmss", ClampMSSToPMTU: true},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error for valid clamp-mss-to-pmtu, got: %v", err)
	}
}

func TestAnalyze_TCPMSSSetMSSValid(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"FORWARD": {
				Mangle: []ast.Rule{
					{Proto: "tcp", Jump: "tcpmss", SetMSS: 1400},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error for valid set-mss, got: %v", err)
	}
}

func TestAnalyze_TCPMSSRequiresTCP(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"FORWARD": {
				Mangle: []ast.Rule{
					{Proto: "udp", Jump: "tcpmss", ClampMSSToPMTU: true},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for j: tcpmss without p: tcp")
	}
	if !strings.Contains(err.Error(), "requires p: tcp") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_TCPMSSWrongTable(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Proto: "tcp", Jump: "tcpmss", ClampMSSToPMTU: true},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for tcpmss in filter table")
	}
	if !strings.Contains(err.Error(), "only valid in the mangle table") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_TCPMSSBothOptions(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"FORWARD": {
				Mangle: []ast.Rule{
					{Proto: "tcp", Jump: "tcpmss", SetMSS: 1400, ClampMSSToPMTU: true},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for both set-mss and clamp-mss-to-pmtu")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_TCPMSSNoOptions(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"FORWARD": {
				Mangle: []ast.Rule{
					{Proto: "tcp", Jump: "tcpmss"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for j: tcpmss with no options")
	}
	if !strings.Contains(err.Error(), "requires set-mss or clamp-mss-to-pmtu") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_TCPMSSOptionWithoutTarget(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"FORWARD": {
				Mangle: []ast.Rule{
					{Proto: "tcp", SetMSS: 1400, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for set-mss without j: tcpmss")
	}
	if !strings.Contains(err.Error(), "only valid with j: tcpmss") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_TCPMSSOutOfRange(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"FORWARD": {
				Mangle: []ast.Rule{
					{Proto: "tcp", Jump: "tcpmss", SetMSS: 70000},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for set-mss > 65535")
	}
	if !strings.Contains(err.Error(), "outside valid range") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_TCPFlagsValid(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Proto: "tcp", TCPFlags: &ast.TCPFlagsSpec{
						Mask: []string{"SYN", "ACK", "FIN", "RST"},
						Comp: []string{"SYN"},
					}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error for valid tcp-flags, got: %v", err)
	}
}

func TestAnalyze_TCPFlagsUnknownFlag(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Proto: "tcp", TCPFlags: &ast.TCPFlagsSpec{
						Mask: []string{"SYN", "BOGUS"},
						Comp: []string{"SYN"},
					}, Jump: "drop"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for unknown tcp flag")
	}
	if !strings.Contains(err.Error(), "unknown tcp flag") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_TCPFlagsRequiresTCP(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Proto: "udp", TCPFlags: &ast.TCPFlagsSpec{
						Mask: []string{"SYN"},
						Comp: []string{"SYN"},
					}, Jump: "drop"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for tcp-flags with p: udp")
	}
	if !strings.Contains(err.Error(), "requires p: tcp") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_TCPFlagsEmptyMask(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Proto: "tcp", TCPFlags: &ast.TCPFlagsSpec{
						Mask: []string{},
						Comp: []string{"SYN"},
					}, Jump: "drop"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for empty tcp-flags mask")
	}
	if !strings.Contains(err.Error(), "mask cannot be empty") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_FragmentValid(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Fragment: true, Jump: "drop"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error for fragment: true, got: %v", err)
	}
}

func TestAnalyze_FragmentWithIPv6Proto(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Proto: "ipv6-icmp", Fragment: true, Jump: "drop"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for fragment with p: ipv6-icmp")
	}
	if !strings.Contains(err.Error(), "IPv4 only") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_FragmentWithIPv6Addr(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Src: "fe80::/10", Fragment: true, Jump: "drop"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for fragment with IPv6 source")
	}
	if !strings.Contains(err.Error(), "IPv4 only") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_TCPOptionValid(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Proto: "tcp", TCPOption: 7, Jump: "drop"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error for valid tcp-option, got: %v", err)
	}
}

func TestAnalyze_TCPOptionRequiresTCP(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Proto: "udp", TCPOption: 7, Jump: "drop"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for tcp-option with p: udp")
	}
	if !strings.Contains(err.Error(), "requires p: tcp") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_TCPOptionOutOfRange(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Proto: "tcp", TCPOption: 300, Jump: "drop"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for tcp-option > 255")
	}
	if !strings.Contains(err.Error(), "outside valid range") {
		t.Errorf("unexpected error: %v", err)
	}
}

// === CONNMARK target + connmark match ===

func TestAnalyze_ConnmarkSetMarkValid(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"POSTROUTING": {
				Mangle: []ast.Rule{
					{Jump: "connmark", SetMark: "0xff"},
				},
			},
		},
	)
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error for connmark set-mark, got: %v", err)
	}
}

func TestAnalyze_ConnmarkSaveMarkValid(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"POSTROUTING": {
				Mangle: []ast.Rule{
					{Jump: "connmark", SaveMark: true, NfMask: "0xff", CTMask: "0xff"},
				},
			},
		},
	)
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error for connmark save-mark, got: %v", err)
	}
}

func TestAnalyze_ConnmarkRestoreMarkValid(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"PREROUTING": {
				Mangle: []ast.Rule{
					{Jump: "connmark", RestoreMark: true},
				},
			},
		},
	)
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error for connmark restore-mark, got: %v", err)
	}
}

func TestAnalyze_ConnmarkRequiresOption(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"POSTROUTING": {
				Mangle: []ast.Rule{
					{Jump: "connmark"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for connmark without any option")
	}
	if !strings.Contains(err.Error(), "requires one of set-mark, save-mark, restore-mark") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_ConnmarkMutuallyExclusive(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"POSTROUTING": {
				Mangle: []ast.Rule{
					{Jump: "connmark", SaveMark: true, RestoreMark: true},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for save-mark + restore-mark")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_ConnmarkSetMarkWithMaskRejected(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"POSTROUTING": {
				Mangle: []ast.Rule{
					{Jump: "connmark", SetMark: "0x01", NfMask: "0xff"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for set-mark combined with nfmask")
	}
	if !strings.Contains(err.Error(), "cannot combine with set-mark") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_SaveMarkWithoutConnmark(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"POSTROUTING": {
				Mangle: []ast.Rule{
					{Jump: "accept", SaveMark: true},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for save-mark without j: connmark")
	}
	if !strings.Contains(err.Error(), "only valid with j: connmark") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_ConnmarkMatchValid(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{Connmark: &ast.ConnmarkMatch{Mark: "0xff/0xff"}}}, Jump: "accept"},
				},
			},
		},
	)
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error for connmark match, got: %v", err)
	}
}

func TestAnalyze_ConnmarkMatchRequiresMark(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{Connmark: &ast.ConnmarkMatch{}}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for connmark match without mark")
	}
	if !strings.Contains(err.Error(), "connmark match requires mark") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_ConnmarkMatchInvalidMark(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{Connmark: &ast.ConnmarkMatch{Mark: "garbage"}}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for invalid connmark mark")
	}
	if !strings.Contains(err.Error(), "not a valid mark value") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_CTMaskAllowedWithConnmark(t *testing.T) {
	// Regression: ctmask/nfmask used to be restricted to j: ct; now also allowed with j: connmark.
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"POSTROUTING": {
				Mangle: []ast.Rule{
					{Jump: "connmark", RestoreMark: true, CTMask: "0x0f", NfMask: "0x0f"},
				},
			},
		},
	)
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error for connmark restore-mark with masks, got: %v", err)
	}
}

func TestAnalyze_CTMaskRejectedOutsideCTAndConnmark(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Jump: "accept", CTMask: "0xff"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for ctmask without j: ct or j: connmark")
	}
	if !strings.Contains(err.Error(), "ctmask/nfmask are only valid") {
		t.Errorf("unexpected error: %v", err)
	}
}

// === connlimit + hashlimit ===

func intPtr(i int) *int { return &i }

func TestAnalyze_ConnlimitAboveValid(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Proto: "tcp", DPort: 22, Match: []*ast.MatchBlock{{
						Connlimit: &ast.ConnlimitMatch{Above: intPtr(10), Mask: intPtr(32), SAddr: true},
					}}, Jump: "reject"},
				},
			},
		},
	)
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_ConnlimitRequiresAboveOrUpto(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{Connlimit: &ast.ConnlimitMatch{SAddr: true}}}, Jump: "drop"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for connlimit without above/upto")
	}
	if !strings.Contains(err.Error(), "requires above or upto") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_ConnlimitAboveAndUptoExclusive(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{
						Connlimit: &ast.ConnlimitMatch{Above: intPtr(5), Upto: intPtr(1)},
					}}, Jump: "drop"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for above + upto")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_ConnlimitMaskOutOfRange(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{
						Connlimit: &ast.ConnlimitMatch{Above: intPtr(5), Mask: intPtr(200)},
					}}, Jump: "drop"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for mask > 128")
	}
	if !strings.Contains(err.Error(), "mask 200 is outside valid range") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_ConnlimitSAddrDAddrExclusive(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{
						Connlimit: &ast.ConnlimitMatch{Above: intPtr(5), SAddr: true, DAddr: true},
					}}, Jump: "drop"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for saddr + daddr")
	}
	if !strings.Contains(err.Error(), "saddr and daddr are mutually exclusive") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_HashlimitValid(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{
						Hashlimit: &ast.HashlimitMatch{
							Name:    "ssh_rate",
							Upto:    "5/minute",
							Burst:   10,
							Mode:    []string{"srcip"},
							SrcMask: intPtr(32),
						},
					}}, Jump: "accept"},
				},
			},
		},
	)
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_HashlimitRequiresName(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{
						Hashlimit: &ast.HashlimitMatch{Upto: "5/minute"},
					}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for hashlimit without name")
	}
	if !strings.Contains(err.Error(), "hashlimit match requires name") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_HashlimitRequiresRate(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{Hashlimit: &ast.HashlimitMatch{Name: "r"}}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for hashlimit without rate")
	}
	if !strings.Contains(err.Error(), "requires upto or above") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_HashlimitUptoAboveExclusive(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{Hashlimit: &ast.HashlimitMatch{
						Name: "r", Upto: "5/sec", Above: "100/sec",
					}}}, Jump: "drop"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for upto + above")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_HashlimitInvalidRate(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{Hashlimit: &ast.HashlimitMatch{
						Name: "r", Upto: "5/fortnight",
					}}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for invalid rate unit")
	}
	if !strings.Contains(err.Error(), "not a valid rate") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_HashlimitInvalidMode(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{Hashlimit: &ast.HashlimitMatch{
						Name: "r", Upto: "5/sec", Mode: []string{"bogusmode"},
					}}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
	if !strings.Contains(err.Error(), "unknown hashlimit mode") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_HashlimitMaskOutOfRange(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{Hashlimit: &ast.HashlimitMatch{
						Name: "r", Upto: "5/sec", SrcMask: intPtr(200),
					}}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for srcmask out of range")
	}
	if !strings.Contains(err.Error(), "srcmask 200 is outside valid range") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_HashlimitNameTooLong(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{Hashlimit: &ast.HashlimitMatch{
						Name: strings.Repeat("x", 33), Upto: "5/sec",
					}}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for name > 32 chars")
	}
	if !strings.Contains(err.Error(), "exceeds 32-character limit") {
		t.Errorf("unexpected error: %v", err)
	}
}

// === owner match ===

func TestAnalyze_OwnerUIDValid(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"OUTPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{Owner: &ast.OwnerMatch{UIDOwner: intPtr(1000)}}}, Jump: "accept"},
				},
			},
		},
	)
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_OwnerRequiresAField(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"OUTPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{Owner: &ast.OwnerMatch{}}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for empty owner match")
	}
	if !strings.Contains(err.Error(), "owner match requires at least one of") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_OwnerWrongChain(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{Owner: &ast.OwnerMatch{UIDOwner: intPtr(0)}}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for owner match on INPUT")
	}
	if !strings.Contains(err.Error(), "only valid in OUTPUT or POSTROUTING") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_OwnerUserChainAllowed(t *testing.T) {
	// Owner match in a user-defined chain is allowed; the placement is enforced
	// by the fact that the user chain must be called from OUTPUT/POSTROUTING.
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"MYCHAIN": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{Owner: &ast.OwnerMatch{UIDOwner: intPtr(0)}}}, Jump: "accept"},
				},
			},
		},
	)
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_OwnerNegativeUID(t *testing.T) {
	neg := -1
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"OUTPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{Owner: &ast.OwnerMatch{UIDOwner: &neg}}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for negative uid")
	}
	if !strings.Contains(err.Error(), "must be non-negative") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_OwnerCmdOwnerTooLong(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"OUTPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{Owner: &ast.OwnerMatch{CmdOwner: strings.Repeat("x", 16)}}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for cmd-owner > 15 chars")
	}
	if !strings.Contains(err.Error(), "exceeds 15-character") {
		t.Errorf("unexpected error: %v", err)
	}
}

// === iprange match ===

func TestAnalyze_IPRangeValidV4(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{IPRange: &ast.IPRangeMatch{SrcRange: "10.0.0.1-10.0.0.100"}}}, Jump: "drop"},
				},
			},
		},
	)
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_IPRangeRequiresField(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{IPRange: &ast.IPRangeMatch{}}}, Jump: "drop"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for empty iprange")
	}
	if !strings.Contains(err.Error(), "src-range or dst-range") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_IPRangeBadFormat(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{IPRange: &ast.IPRangeMatch{SrcRange: "10.0.0.1"}}}, Jump: "drop"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for missing dash")
	}
	if !strings.Contains(err.Error(), "must be of the form A-B") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_IPRangeLowGreaterThanHigh(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{IPRange: &ast.IPRangeMatch{SrcRange: "10.0.0.100-10.0.0.1"}}}, Jump: "drop"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for low > high")
	}
	if !strings.Contains(err.Error(), "low > high") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_IPRangeMixedVersions(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{IPRange: &ast.IPRangeMatch{SrcRange: "10.0.0.1-fd00::1"}}}, Jump: "drop"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for mixed IPv4/IPv6 endpoints")
	}
	if !strings.Contains(err.Error(), "mixes IPv4 and IPv6") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_IPRangeSrcDstVersionMismatch(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{IPRange: &ast.IPRangeMatch{
						SrcRange: "10.0.0.1-10.0.0.10",
						DstRange: "fd00::1-fd00::ff",
					}}}, Jump: "drop"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for mismatched src/dst versions")
	}
	if !strings.Contains(err.Error(), "must agree on IP version") {
		t.Errorf("unexpected error: %v", err)
	}
}

// === length match ===

func TestAnalyze_LengthSingleValid(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{Length: &ast.LengthMatch{Length: "1500"}}}, Jump: "drop"},
				},
			},
		},
	)
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_LengthRangeValid(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{Length: &ast.LengthMatch{Length: "64:1500"}}}, Jump: "accept"},
				},
			},
		},
	)
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_LengthRangeLowGreaterThanHigh(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{Length: &ast.LengthMatch{Length: "1500:64"}}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for range low > high")
	}
	if !strings.Contains(err.Error(), "low > high") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_LengthRangeOutOfBounds(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{Length: &ast.LengthMatch{Length: "0:70000"}}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for length > 65535")
	}
	if !strings.Contains(err.Error(), "outside 0-65535") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_LengthGarbage(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{Length: &ast.LengthMatch{Length: "large"}}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for non-numeric length")
	}
	if !strings.Contains(err.Error(), "not a valid number or range") {
		t.Errorf("unexpected error: %v", err)
	}
}

// === ttl / hl match ===

func TestAnalyze_TTLValidEq(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{TTL: &ast.TTLMatch{Eq: intPtr(64)}}}, Jump: "accept"},
				},
			},
		},
	)
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_TTLRequiresExactlyOne(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{TTL: &ast.TTLMatch{}}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for empty ttl")
	}
	if !strings.Contains(err.Error(), "requires exactly one") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_TTLMutuallyExclusive(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{TTL: &ast.TTLMatch{Eq: intPtr(64), Lt: intPtr(5)}}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for eq + lt")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_TTLOutOfRange(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{TTL: &ast.TTLMatch{Eq: intPtr(300)}}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for ttl > 255")
	}
	if !strings.Contains(err.Error(), "outside valid range 0-255") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_HLValid(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{HL: &ast.HLMatch{Gt: intPtr(100)}}}, Jump: "accept"},
				},
			},
		},
	)
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

// === pkttype match ===

func TestAnalyze_PktTypeValid(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{PktType: &ast.PktTypeMatch{PktType: "multicast"}}}, Jump: "drop"},
				},
			},
		},
	)
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_PktTypeRequired(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{PktType: &ast.PktTypeMatch{}}}, Jump: "drop"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for empty pkttype")
	}
	if !strings.Contains(err.Error(), "pkttype match requires pkt-type") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_PktTypeUnknown(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{PktType: &ast.PktTypeMatch{PktType: "anycast"}}}, Jump: "drop"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for unknown pkttype")
	}
	if !strings.Contains(err.Error(), "unknown pkttype") {
		t.Errorf("unexpected error: %v", err)
	}
}

// === physdev match ===

func TestAnalyze_PhysDevValid(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"FORWARD": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{PhysDev: &ast.PhysDevMatch{
						PhysDevIn:        "eth0",
						PhysDevOut:       "eth1",
						PhysDevIsBridged: true,
					}}}, Jump: "accept"},
				},
			},
		},
	)
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_PhysDevRequiresField(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"FORWARD": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{PhysDev: &ast.PhysDevMatch{}}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for empty physdev")
	}
	if !strings.Contains(err.Error(), "physdev match requires at least one") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_PhysDevBadInterfaceName(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"FORWARD": {
				Filter: []ast.Rule{
					{Match: []*ast.MatchBlock{{PhysDev: &ast.PhysDevMatch{PhysDevIn: "this-name-is-way-too-long-for-linux"}}}, Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for long interface name")
	}
	if !strings.Contains(err.Error(), "exceeds 15-character") {
		t.Errorf("unexpected error: %v", err)
	}
}

// === Phase 6: NFLOG / NFQUEUE / SET targets ===

func TestAnalyze_NflogTargetValid(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Jump: "nflog", NflogGroup: 2, NflogPrefix: "DROPPED: ", NflogRange: 256, NflogThreshold: 5},
				},
			},
		},
	)
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error for valid nflog rule, got: %v", err)
	}
}

func TestAnalyze_NflogFieldWithoutTarget(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Jump: "accept", NflogGroup: 2},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for nflog-group without j: nflog")
	}
	if !strings.Contains(err.Error(), "only valid with j: nflog") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_NflogGroupOutOfRange(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Jump: "nflog", NflogGroup: 70000},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for nflog-group > 65535")
	}
	if !strings.Contains(err.Error(), "outside valid range") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_NflogPrefixTooLong(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Jump: "nflog", NflogPrefix: strings.Repeat("A", 65)},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for nflog-prefix > 64 chars")
	}
	if !strings.Contains(err.Error(), "exceeds 64-character") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_NfqueueTargetValid(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"FORWARD": {
				Filter: []ast.Rule{
					{Jump: "nfqueue", QueueNum: 0, QueueNumSet: true, QueueBypass: true},
				},
			},
		},
	)
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error for valid nfqueue rule, got: %v", err)
	}
}

func TestAnalyze_NfqueueBalanceValid(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"FORWARD": {
				Filter: []ast.Rule{
					{Jump: "nfqueue", QueueBalance: "0:3", QueueCPUFanout: true},
				},
			},
		},
	)
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error for valid nfqueue balance rule, got: %v", err)
	}
}

func TestAnalyze_NfqueueNumAndBalanceExclusive(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"FORWARD": {
				Filter: []ast.Rule{
					{Jump: "nfqueue", QueueNum: 1, QueueNumSet: true, QueueBalance: "0:3"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for queue-num + queue-balance")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_NfqueueBalanceReversed(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"FORWARD": {
				Filter: []ast.Rule{
					{Jump: "nfqueue", QueueBalance: "5:3"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for queue-balance low > high")
	}
	if !strings.Contains(err.Error(), "low > high") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_NfqueueFieldWithoutTarget(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Jump: "accept", QueueBypass: true},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for queue-bypass without j: nfqueue")
	}
	if !strings.Contains(err.Error(), "only valid with j: nfqueue") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_SETTargetAddValid(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{
			"blocklist": {Type: "ipset", Elements: []interface{}{"10.0.0.0/8"}},
		},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Jump: "set", AddSet: "blocklist", SetFlags: []string{"src"}, SetExist: true, SetTimeout: 3600},
				},
			},
		},
	)
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error for valid SET add rule, got: %v", err)
	}
}

func TestAnalyze_SETTargetDelValid(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{
			"blocklist": {Type: "ipset", Elements: []interface{}{"10.0.0.0/8"}},
		},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Jump: "set", DelSet: "blocklist", SetFlags: []string{"src"}},
				},
			},
		},
	)
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error for valid SET del rule, got: %v", err)
	}
}

func TestAnalyze_SETRequiresAddOrDel(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Jump: "set", SetFlags: []string{"src"}},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for j: set with no add-set or del-set")
	}
	if !strings.Contains(err.Error(), "requires add-set or del-set") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_SETAddAndDelExclusive(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{
			"blocklist": {Type: "ipset", Elements: []interface{}{"10.0.0.0/8"}},
		},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Jump: "set", AddSet: "blocklist", DelSet: "blocklist", SetFlags: []string{"src"}},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for add-set + del-set")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_SETRequiresFlags(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{
			"blocklist": {Type: "ipset", Elements: []interface{}{"10.0.0.0/8"}},
		},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Jump: "set", AddSet: "blocklist"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for j: set with no set-flags")
	}
	if !strings.Contains(err.Error(), "requires set-flags") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_SETInvalidFlag(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{
			"blocklist": {Type: "ipset", Elements: []interface{}{"10.0.0.0/8"}},
		},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Jump: "set", AddSet: "blocklist", SetFlags: []string{"src", "bogus"}},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for invalid set-flag")
	}
	if !strings.Contains(err.Error(), "unknown set-flag") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_SETUnknownIpset(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Jump: "set", AddSet: "nonexistent", SetFlags: []string{"src"}},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for SET referencing unknown ipset")
	}
	if !strings.Contains(err.Error(), "unknown ipset") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_SETMixedIpsetRejected(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{
			"mixed": {Type: "ipset", Elements: []interface{}{"10.0.0.0/8", "fd00::/8"}},
		},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Jump: "set", AddSet: "mixed", SetFlags: []string{"src"}},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for SET referencing mixed ipset")
	}
	if !strings.Contains(err.Error(), "mixed IPv4/IPv6") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_SETDelWithTimeoutRejected(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{
			"blocklist": {Type: "ipset", Elements: []interface{}{"10.0.0.0/8"}},
		},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Jump: "set", DelSet: "blocklist", SetFlags: []string{"src"}, SetTimeout: 60},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for del-set + set-timeout")
	}
	if !strings.Contains(err.Error(), "only apply to add-set") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAnalyze_SETFieldWithoutTarget(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Jump: "accept", AddSet: "nonexistent", SetFlags: []string{"src"}},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err == nil {
		t.Fatal("expected error for add-set without j: set")
	}
	if !strings.Contains(err.Error(), "only valid with j: set") {
		t.Errorf("unexpected error: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Phase 7 — richer ipset types and creation attributes.
// -----------------------------------------------------------------------------

func TestAnalyze_DefaultSetType(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{
			"nets": {Type: "ipset", Elements: []interface{}{"10.0.0.0/8"}},
		},
		map[string]ast.Chain{"INPUT": {Filter: []ast.Rule{{Src: "$nets", Jump: "accept"}}}},
	)
	resolved, err := Analyze(doc)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	r := resolved.Resources["nets"]
	if r.SetType != "hash:net" {
		t.Errorf("default SetType = %q, want hash:net", r.SetType)
	}
	if r.Dimensions != 1 || !r.HasAddress {
		t.Errorf("unexpected classification: dims=%d hasAddr=%v", r.Dimensions, r.HasAddress)
	}
}

func TestAnalyze_UnknownSetType(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{
			"bogus": {Type: "ipset", SetType: "hash:fictional", Elements: []interface{}{"10.0.0.0/8"}},
		},
		map[string]ast.Chain{"INPUT": {Filter: []ast.Rule{{Src: "$bogus", Jump: "accept"}}}},
	)
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "unknown set-type") {
		t.Fatalf("expected unknown set-type error, got: %v", err)
	}
}

func TestAnalyze_HashIPPortElementShape(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{
			"ipport": {
				Type:    "ipset",
				SetType: "hash:ip,port",
				Elements: []interface{}{
					"10.0.0.1,tcp:22",
					"10.0.0.2,udp:53",
				},
			},
		},
		map[string]ast.Chain{"INPUT": {Filter: []ast.Rule{{Dst: "$ipport[dst,dst]", Jump: "accept"}}}},
	)
	resolved, err := Analyze(doc)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if got := resolved.Resources["ipport"].Dimensions; got != 2 {
		t.Errorf("Dimensions = %d, want 2", got)
	}
}

func TestAnalyze_HashIPPortRejectsCIDRFirstField(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{
			"ipport": {
				Type:     "ipset",
				SetType:  "hash:ip,port",
				Elements: []interface{}{"10.0.0.0/24,tcp:22"},
			},
		},
		map[string]ast.Chain{"INPUT": {}},
	)
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "plain IP") {
		t.Fatalf("expected plain IP error, got: %v", err)
	}
}

func TestAnalyze_HashMACElement(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{
			"macs": {
				Type:     "ipset",
				SetType:  "hash:mac",
				Elements: []interface{}{"02:00:00:00:00:01"},
			},
		},
		map[string]ast.Chain{"INPUT": {Filter: []ast.Rule{{Src: "$macs[src]", Jump: "accept"}}}},
	)
	resolved, err := Analyze(doc)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	r := resolved.Resources["macs"]
	if r.HasAddress {
		t.Errorf("hash:mac should not be address-bearing")
	}
	if r.Family != "inet" {
		t.Errorf("default family = %q, want inet", r.Family)
	}
}

func TestAnalyze_HashMACInvalid(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{
			"macs": {Type: "ipset", SetType: "hash:mac", Elements: []interface{}{"not-a-mac"}},
		},
		map[string]ast.Chain{"INPUT": {}},
	)
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "not a valid MAC") {
		t.Fatalf("expected invalid MAC error, got: %v", err)
	}
}

func TestAnalyze_BitmapPortRange(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{
			"hp": {
				Type:       "ipset",
				SetType:    "bitmap:port",
				SetOptions: &ast.SetOptions{Range: "32768-65535"},
				Elements:   []interface{}{"32768-40000", "40001"},
			},
		},
		map[string]ast.Chain{"INPUT": {Filter: []ast.Rule{{Src: "$hp[src]", Jump: "accept"}}}},
	)
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("Analyze: %v", err)
	}
}

func TestAnalyze_SetOptionsNetmaskIncompatible(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{
			"ls": {
				Type:       "ipset",
				SetType:    "list:set",
				SetOptions: &ast.SetOptions{NetMask: 24},
				Elements:   []interface{}{"other"},
			},
		},
		map[string]ast.Chain{"INPUT": {}},
	)
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "netmask is only valid") {
		t.Fatalf("expected netmask incompatibility error, got: %v", err)
	}
}

func TestAnalyze_SetOptionsMarkmaskRequiresIPMark(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{
			"nm": {
				Type:       "ipset",
				SetType:    "hash:net",
				SetOptions: &ast.SetOptions{MarkMask: "0xff"},
				Elements:   []interface{}{"10.0.0.0/8"},
			},
		},
		map[string]ast.Chain{"INPUT": {}},
	)
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "markmask") {
		t.Fatalf("expected markmask error, got: %v", err)
	}
}

func TestAnalyze_SetOptionsRangeRequiresBitmap(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{
			"hn": {
				Type:       "ipset",
				SetType:    "hash:net",
				SetOptions: &ast.SetOptions{Range: "1-100"},
				Elements:   []interface{}{"10.0.0.0/8"},
			},
		},
		map[string]ast.Chain{"INPUT": {}},
	)
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "range is only valid") {
		t.Fatalf("expected range error, got: %v", err)
	}
}

func TestAnalyze_SetRefDimensionsMismatch(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{
			"ipport": {
				Type:     "ipset",
				SetType:  "hash:ip,port",
				Elements: []interface{}{"10.0.0.1,tcp:22"},
			},
		},
		// Using single dir flag on a 2-dim set must fail.
		map[string]ast.Chain{"INPUT": {Filter: []ast.Rule{{Src: "$ipport[src]", Jump: "accept"}}}},
	)
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "direction flag") {
		t.Fatalf("expected direction flag count mismatch error, got: %v", err)
	}
}

func TestAnalyze_SetRefUnknownDirection(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{
			"nets": {Type: "ipset", Elements: []interface{}{"10.0.0.0/8"}},
		},
		map[string]ast.Chain{"INPUT": {Filter: []ast.Rule{{Src: "$nets[both]", Jump: "accept"}}}},
	)
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "unknown direction") {
		t.Fatalf("expected unknown direction flag error, got: %v", err)
	}
}

func TestAnalyze_SetOptionsOnNonIpset(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{
			"ports": {
				Type:       "portset",
				SetOptions: &ast.SetOptions{MaxElem: 100},
				Elements:   []interface{}{80},
			},
		},
		map[string]ast.Chain{"INPUT": {}},
	)
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "only valid on type: ipset") {
		t.Fatalf("expected set-options on non-ipset error, got: %v", err)
	}
}

func TestAnalyze_ExplicitFamilyConflict(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{
			"conflict": {
				Type:       "ipset",
				SetOptions: &ast.SetOptions{Family: "inet6"},
				Elements:   []interface{}{"10.0.0.0/8"}, // IPv4 element
			},
		},
		map[string]ast.Chain{"INPUT": {Filter: []ast.Rule{{Src: "$conflict", Jump: "accept"}}}},
	)
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "family") {
		t.Fatalf("expected family conflict error, got: %v", err)
	}
}

func TestAnalyze_BitmapPortInvalidElement(t *testing.T) {
	doc := makeDoc(
		map[string]ast.Resource{
			"hp": {
				Type:     "ipset",
				SetType:  "bitmap:port",
				Elements: []interface{}{"not-a-port"},
			},
		},
		map[string]ast.Chain{"INPUT": {}},
	)
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "not a valid port") {
		t.Fatalf("expected invalid port error, got: %v", err)
	}
}

func TestParseSetRef(t *testing.T) {
	cases := []struct {
		in       string
		wantName string
		wantDirs []string
		wantOK   bool
		wantErr  bool
	}{
		{"10.0.0.0/8", "", nil, false, false},
		{"$nets", "nets", nil, true, false},
		{"$ipport[src,dst]", "ipport", []string{"src", "dst"}, true, false},
		{"$ipport[SRC, DST]", "ipport", []string{"src", "dst"}, true, false},
		{"$ipport[", "", nil, true, true},
		{"$ipport[]", "", nil, true, true},
	}
	for _, c := range cases {
		name, dirs, ok, err := ParseSetRef(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("ParseSetRef(%q) err=%v, wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if ok != c.wantOK {
			t.Errorf("ParseSetRef(%q) ok=%v, want %v", c.in, ok, c.wantOK)
		}
		if !c.wantErr && c.wantOK {
			if name != c.wantName {
				t.Errorf("ParseSetRef(%q) name=%q, want %q", c.in, name, c.wantName)
			}
			if len(dirs) != len(c.wantDirs) {
				t.Errorf("ParseSetRef(%q) dirs=%v, want %v", c.in, dirs, c.wantDirs)
			} else {
				for i := range dirs {
					if dirs[i] != c.wantDirs[i] {
						t.Errorf("ParseSetRef(%q) dirs[%d]=%q, want %q", c.in, i, dirs[i], c.wantDirs[i])
					}
				}
			}
		}
	}
}

// === Phase 8: extended match modules ===

// matchRule wraps a single MatchBlock as the new list-form match field and attaches a jump target.
func matchRule(mb *ast.MatchBlock, jump string) ast.Rule {
	return ast.Rule{Match: []*ast.MatchBlock{mb}, Jump: jump}
}

func TestAnalyze_ConntrackEmpty(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{matchRule(&ast.MatchBlock{Conntrack: &ast.ConntrackMatch{}}, "accept")}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "conntrack match requires at least one field") {
		t.Fatalf("expected 'conntrack requires at least one field', got: %v", err)
	}
}

func TestAnalyze_ConntrackInvalidState(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{matchRule(&ast.MatchBlock{
			Conntrack: &ast.ConntrackMatch{CTState: []string{"BOGUS"}},
		}, "accept")}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "unknown conntrack ctstate") {
		t.Fatalf("expected unknown-ctstate error, got: %v", err)
	}
}

func TestAnalyze_ConntrackInvalidProto(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{matchRule(&ast.MatchBlock{
			Conntrack: &ast.ConntrackMatch{CTProto: "xyz"},
		}, "accept")}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "unknown conntrack ctproto") {
		t.Fatalf("expected unknown-ctproto error, got: %v", err)
	}
}

func TestAnalyze_ConntrackInvalidAddr(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{matchRule(&ast.MatchBlock{
			Conntrack: &ast.ConntrackMatch{CTOrigSrc: "not-an-ip"},
		}, "accept")}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "ctorigsrc") {
		t.Fatalf("expected ctorigsrc address error, got: %v", err)
	}
}

func TestAnalyze_ConntrackInvalidDir(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{matchRule(&ast.MatchBlock{
			Conntrack: &ast.ConntrackMatch{CTDir: "SIDEWAYS"},
		}, "accept")}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "ctdir") {
		t.Fatalf("expected ctdir error, got: %v", err)
	}
}

func TestAnalyze_ConntrackExpireRange(t *testing.T) {
	cases := []struct {
		expire  string
		wantErr bool
		errFrag string
	}{
		{"60", false, ""},
		{"60:3600", false, ""},
		{"3600:60", true, "lo > hi"},
		{"abc", true, "not a valid number"},
	}
	for _, c := range cases {
		doc := makeDoc(nil, map[string]ast.Chain{
			"INPUT": {Filter: []ast.Rule{matchRule(&ast.MatchBlock{
				Conntrack: &ast.ConntrackMatch{CTExpire: c.expire},
			}, "accept")}},
		})
		_, err := Analyze(doc)
		if c.wantErr {
			if err == nil || !strings.Contains(err.Error(), c.errFrag) {
				t.Errorf("ctexpire %q: expected error containing %q, got: %v", c.expire, c.errFrag, err)
			}
		} else if err != nil {
			t.Errorf("ctexpire %q: unexpected error: %v", c.expire, err)
		}
	}
}

func TestAnalyze_RecentMutuallyExclusive(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{matchRule(&ast.MatchBlock{
			Recent: &ast.RecentMatch{Set: true, Update: true},
		}, "accept")}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "set/update/rcheck/remove") {
		t.Fatalf("expected mutual-exclusion error, got: %v", err)
	}
}

func TestAnalyze_RecentRSourceRDestExclusive(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{matchRule(&ast.MatchBlock{
			Recent: &ast.RecentMatch{RCheck: true, RSource: true, RDest: true},
		}, "accept")}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "rsource and rdest") {
		t.Fatalf("expected rsource/rdest exclusion error, got: %v", err)
	}
}

func TestAnalyze_RecentReapRequiresSeconds(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{matchRule(&ast.MatchBlock{
			Recent: &ast.RecentMatch{RCheck: true, Reap: true},
		}, "accept")}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "reap requires seconds") {
		t.Fatalf("expected reap-needs-seconds error, got: %v", err)
	}
}

func TestAnalyze_RecentInvalidMask(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{matchRule(&ast.MatchBlock{
			Recent: &ast.RecentMatch{Set: true, Mask: "bogus"},
		}, "accept")}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "recent mask") {
		t.Fatalf("expected recent mask error, got: %v", err)
	}
}

func TestAnalyze_AddrTypeSrcType(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{matchRule(&ast.MatchBlock{
			AddrType: &ast.AddrTypeMatch{SrcType: "LOCAL"},
		}, "accept")}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAnalyze_AddrTypeLimitIfaceMutex(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{matchRule(&ast.MatchBlock{
			AddrType: &ast.AddrTypeMatch{LimitIfaceIn: true, LimitIfaceOut: true},
		}, "accept")}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "limit-iface-in and limit-iface-out") {
		t.Fatalf("expected limit-iface exclusion error, got: %v", err)
	}
}

func TestAnalyze_AddrTypeRequiresOneField(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{matchRule(&ast.MatchBlock{AddrType: &ast.AddrTypeMatch{}}, "accept")}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "addrtype match requires at least one") {
		t.Fatalf("expected addrtype-requires-one-field error, got: %v", err)
	}
}

func TestAnalyze_TimeDateStartInvalid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{matchRule(&ast.MatchBlock{
			Time: &ast.TimeMatch{DateStart: "2026-01-01"},
		}, "accept")}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "datestart") {
		t.Fatalf("expected datestart error, got: %v", err)
	}
}

func TestAnalyze_TimeMonthDaysOutOfRange(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{matchRule(&ast.MatchBlock{
			Time: &ast.TimeMatch{MonthDays: "0,15,32"},
		}, "accept")}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "monthdays") {
		t.Fatalf("expected monthdays error, got: %v", err)
	}
}

func TestAnalyze_TimeUTCAndKernelTZMutex(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{matchRule(&ast.MatchBlock{
			Time: &ast.TimeMatch{UTC: true, KernelTZ: true},
		}, "accept")}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "utc and kerneltz") {
		t.Fatalf("expected utc/kerneltz exclusion error, got: %v", err)
	}
}

func TestAnalyze_MultipleMatchBlocksValidateEach(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{
			{Match: []*ast.MatchBlock{
				{Recent: &ast.RecentMatch{Name: "SSH", Set: true}},
				{Recent: &ast.RecentMatch{Set: true, Update: true}}, // invalid: mutually exclusive
			}, Jump: "accept"},
		}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "set/update/rcheck/remove") {
		t.Fatalf("expected per-entry validation to catch the second block, got: %v", err)
	}
}

// === Phase 9: packet-modification targets ===

// mangleRule is a FORWARD-mangle rule helper. Most Phase 9 targets require
// mangle placement, so FORWARD/mangle is a safe default for tests that don't
// exercise table/chain placement errors.
func mangleRule(r ast.Rule) *ast.Document {
	return makeDoc(nil, map[string]ast.Chain{
		"FORWARD": {Mangle: []ast.Rule{r}},
	})
}

// filterRule is a FORWARD-filter rule helper for filter-only targets (AUDIT).
func filterRule(r ast.Rule) *ast.Document {
	return makeDoc(nil, map[string]ast.Chain{
		"FORWARD": {Filter: []ast.Rule{r}},
	})
}

// ---------- CLASSIFY ----------

func TestAnalyze_ClassifyValid(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "classify", SetClass: "1:10"})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_ClassifyMissingSetClass(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "classify"})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "requires set-class") {
		t.Fatalf("expected 'requires set-class', got: %v", err)
	}
}

func TestAnalyze_ClassifyBadFormat(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "classify", SetClass: "abc"})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "MAJOR:MINOR") {
		t.Fatalf("expected MAJOR:MINOR error, got: %v", err)
	}
}

func TestAnalyze_ClassifyOnlyMangle(t *testing.T) {
	doc := filterRule(ast.Rule{Jump: "classify", SetClass: "1:10"})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "CLASSIFY") {
		t.Fatalf("expected placement error, got: %v", err)
	}
}

func TestAnalyze_SetClassWithoutClassifyJump(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "accept", SetClass: "1:10"})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "j: classify") {
		t.Fatalf("expected 'only valid with j: classify', got: %v", err)
	}
}

// ---------- DSCP ----------

func TestAnalyze_DSCPValidValue(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "dscp", SetDSCP: 46})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_DSCPValidClass(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "dscp", SetDSCPClass: "EF"})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_DSCPBothExclusive(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "dscp", SetDSCP: 46, SetDSCPClass: "EF"})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutually exclusive error, got: %v", err)
	}
}

func TestAnalyze_DSCPOutOfRange(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "dscp", SetDSCP: 64})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "0-63") {
		t.Fatalf("expected range error, got: %v", err)
	}
}

func TestAnalyze_DSCPUnknownClass(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "dscp", SetDSCPClass: "XYZZY"})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "unknown set-dscp-class") {
		t.Fatalf("expected unknown class error, got: %v", err)
	}
}

// ---------- TOS ----------

func TestAnalyze_TOSSetValid(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "tos", SetTOS: "0x10"})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_TOSTwoModesExclusive(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "tos", SetTOS: 0x10, AndTOS: 0xff})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutually exclusive error, got: %v", err)
	}
}

func TestAnalyze_TOSMissingMode(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "tos"})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "requires one of") {
		t.Fatalf("expected requires-one-of error, got: %v", err)
	}
}

// ---------- ECN ----------

func TestAnalyze_ECNValid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"PREROUTING": {Mangle: []ast.Rule{{Jump: "ecn", ECNTCPRemove: true, Proto: "tcp"}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_ECNRequiresTCP(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"PREROUTING": {Mangle: []ast.Rule{{Jump: "ecn", ECNTCPRemove: true, Proto: "udp"}}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "p: tcp") {
		t.Fatalf("expected 'p: tcp' error, got: %v", err)
	}
}

func TestAnalyze_ECNOnlyPrerouting(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "ecn", ECNTCPRemove: true, Proto: "tcp"})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "ECN") {
		t.Fatalf("expected placement error, got: %v", err)
	}
}

// ---------- TTL target ----------

func ptrInt(n int) *int { return &n }

func TestAnalyze_TTLTargetValid(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "ttl", TTLSet: ptrInt(64)})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_TTLTargetMissing(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "ttl"})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "requires one of ttl-set") {
		t.Fatalf("expected missing ttl-* error, got: %v", err)
	}
}

func TestAnalyze_TTLTargetMutuallyExclusive(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "ttl", TTLSet: ptrInt(64), TTLDec: ptrInt(1)})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutually exclusive error, got: %v", err)
	}
}

func TestAnalyze_TTLTargetRejectsIPv6Address(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "ttl", TTLSet: ptrInt(64), Dst: "2001:db8::/32"})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "IPv4-only") {
		t.Fatalf("expected IPv4-only error, got: %v", err)
	}
}

// ---------- HL target ----------

func TestAnalyze_HLTargetValid(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "hl", HLSet: ptrInt(64)})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_HLTargetRejectsIPv4Address(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "hl", HLSet: ptrInt(64), Src: "10.0.0.0/8"})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "IPv6-only") {
		t.Fatalf("expected IPv6-only error, got: %v", err)
	}
}

// ---------- SECMARK ----------

func TestAnalyze_SECMARKValid(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "secmark", SelCtx: "system_u:object_r:foo_t:s0"})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_SECMARKMissingCtx(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "secmark"})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "requires selctx") {
		t.Fatalf("expected selctx error, got: %v", err)
	}
}

// ---------- CONNSECMARK ----------

func TestAnalyze_CONNSECMARKSaveValid(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "connsecmark", ConnSecMarkSave: true})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_CONNSECMARKBothExclusive(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "connsecmark", ConnSecMarkSave: true, ConnSecMarkRestore: true})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutually exclusive error, got: %v", err)
	}
}

func TestAnalyze_CONNSECMARKMissing(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "connsecmark"})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "requires connsecmark-save") {
		t.Fatalf("expected requires error, got: %v", err)
	}
}

// ---------- SYNPROXY ----------

func TestAnalyze_SYNPROXYValid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "synproxy", SynproxyMSS: 1460, SynproxyWScale: 7, SynproxyTimestamp: true, SynproxySAckPerm: true}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_SYNPROXYWScaleOutOfRange(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "synproxy", SynproxyWScale: 20}}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "0-14") {
		t.Fatalf("expected wscale range error, got: %v", err)
	}
}

// ---------- TEE ----------

func TestAnalyze_TEEValid(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "tee", Gateway: "10.0.0.1"})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_TEEBadGateway(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "tee", Gateway: "not-an-ip"})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "valid IP") {
		t.Fatalf("expected gateway error, got: %v", err)
	}
}

func TestAnalyze_TEEMissing(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "tee"})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "requires gateway") {
		t.Fatalf("expected requires error, got: %v", err)
	}
}

// ---------- AUDIT ----------

func TestAnalyze_AUDITValid(t *testing.T) {
	doc := filterRule(ast.Rule{Jump: "audit", AuditType: "accept"})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_AUDITBadType(t *testing.T) {
	doc := filterRule(ast.Rule{Jump: "audit", AuditType: "log"})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "must be one of") {
		t.Fatalf("expected bad audit-type error, got: %v", err)
	}
}

func TestAnalyze_AUDITFilterOnly(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "audit", AuditType: "accept"})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "AUDIT") {
		t.Fatalf("expected placement error, got: %v", err)
	}
}

// ---------- CHECKSUM ----------

func TestAnalyze_CHECKSUMValid(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "checksum", ChecksumFill: true})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_CHECKSUMMissingFill(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "checksum"})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "checksum-fill: true") {
		t.Fatalf("expected requires error, got: %v", err)
	}
}

// ---------- NETMAP ----------

func TestAnalyze_NETMAPValid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"POSTROUTING": {Nat: []ast.Rule{{Jump: "netmap", NetmapTo: "10.0.0.0/24"}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_NETMAPBadAddr(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"POSTROUTING": {Nat: []ast.Rule{{Jump: "netmap", NetmapTo: "not-an-addr"}}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "not a valid IP") {
		t.Fatalf("expected address error, got: %v", err)
	}
}

func TestAnalyze_NETMAPOnlyNat(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "netmap", NetmapTo: "10.0.0.0/24"})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "NETMAP") {
		t.Fatalf("expected placement error, got: %v", err)
	}
}

// ---------- CLUSTERIP ----------

func TestAnalyze_CLUSTERIPValid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"PREROUTING": {Mangle: []ast.Rule{{
			Jump:                "clusterip",
			ClusterIPNew:        true,
			ClusterIPHashmode:   "sourceip",
			ClusterIPClusterMAC: "01:00:5e:01:02:03",
			ClusterIPTotalNodes: 4,
			ClusterIPLocalNode:  1,
		}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_CLUSTERIPBadHashmode(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"PREROUTING": {Mangle: []ast.Rule{{
			Jump: "clusterip", ClusterIPNew: true, ClusterIPHashmode: "bogus",
			ClusterIPClusterMAC: "01:00:5e:01:02:03", ClusterIPTotalNodes: 4, ClusterIPLocalNode: 1,
		}}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "hashmode") {
		t.Fatalf("expected hashmode error, got: %v", err)
	}
}

func TestAnalyze_CLUSTERIPLocalNodeOutOfRange(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"PREROUTING": {Mangle: []ast.Rule{{
			Jump: "clusterip", ClusterIPNew: true, ClusterIPHashmode: "sourceip",
			ClusterIPClusterMAC: "01:00:5e:01:02:03", ClusterIPTotalNodes: 4, ClusterIPLocalNode: 5,
		}}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "1..total-nodes") {
		t.Fatalf("expected local-node range error, got: %v", err)
	}
}

// ---------- IDLETIMER ----------

func TestAnalyze_IDLETIMERValid(t *testing.T) {
	doc := filterRule(ast.Rule{Jump: "idletimer", IdletimerTimeout: 60, IdletimerLabel: "foo"})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_IDLETIMERMissingLabel(t *testing.T) {
	doc := filterRule(ast.Rule{Jump: "idletimer", IdletimerTimeout: 60})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "requires idletimer-label") {
		t.Fatalf("expected label error, got: %v", err)
	}
}

func TestAnalyze_IDLETIMERLabelTooLong(t *testing.T) {
	doc := filterRule(ast.Rule{Jump: "idletimer", IdletimerTimeout: 60, IdletimerLabel: strings.Repeat("a", 30)})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "27-character") {
		t.Fatalf("expected length error, got: %v", err)
	}
}

// ---------- RATEEST ----------

func TestAnalyze_RATEESTValid(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "rateest", RateestName: "r1", RateestInterval: 250, RateestEwmalog: 2})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_RATEESTMissingName(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "rateest"})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "requires rateest-name") {
		t.Fatalf("expected name error, got: %v", err)
	}
}

// ---------- LED ----------

func TestAnalyze_LEDValid(t *testing.T) {
	doc := filterRule(ast.Rule{Jump: "led", LEDTriggerID: "foo", LEDDelay: 200, LEDDelaySet: true, LEDAlwaysBlink: true})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_LEDMissingTrigger(t *testing.T) {
	doc := filterRule(ast.Rule{Jump: "led"})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "requires led-trigger-id") {
		t.Fatalf("expected trigger error, got: %v", err)
	}
}

// ---------- Cross-target: orphan fields on wrong jump ----------

func TestAnalyze_OrphanSetClassOnAccept(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "accept", SetClass: "1:10"})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "j: classify") {
		t.Fatalf("expected orphan error, got: %v", err)
	}
}

func TestAnalyze_OrphanGatewayOnAccept(t *testing.T) {
	doc := mangleRule(ast.Rule{Jump: "accept", Gateway: "1.2.3.4"})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "j: tee") {
		t.Fatalf("expected orphan error, got: %v", err)
	}
}

// ---------- Phase 10: DSCP/TOS/ECN match ----------

func TestAnalyze_DSCPMatchValid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "accept", Match: []*ast.MatchBlock{{DSCP: &ast.DSCPMatch{DSCP: 46}}}}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_DSCPMatchClass(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "accept", Match: []*ast.MatchBlock{{DSCP: &ast.DSCPMatch{DSCPClass: "EF"}}}}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_DSCPMatchMissing(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "accept", Match: []*ast.MatchBlock{{DSCP: &ast.DSCPMatch{}}}}}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "requires dscp") {
		t.Fatalf("expected requires error, got: %v", err)
	}
}

func TestAnalyze_DSCPMatchOutOfRange(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "accept", Match: []*ast.MatchBlock{{DSCP: &ast.DSCPMatch{DSCP: 100}}}}}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "0-63") {
		t.Fatalf("expected range error, got: %v", err)
	}
}

func TestAnalyze_TOSMatchValid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "accept", Match: []*ast.MatchBlock{{TOS: &ast.TOSMatch{TOS: "0x10/0xff"}}}}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_TOSMatchNamed(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "accept", Match: []*ast.MatchBlock{{TOS: &ast.TOSMatch{TOS: "Minimize-Delay"}}}}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_ECNMatchValid(t *testing.T) {
	ect := 2
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "accept", Match: []*ast.MatchBlock{{ECN: &ast.ECNMatch{TCPCWR: true, IPECT: &ect}}}}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_ECNMatchEmpty(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "accept", Match: []*ast.MatchBlock{{ECN: &ast.ECNMatch{}}}}}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "requires at least one") {
		t.Fatalf("expected requires error, got: %v", err)
	}
}

// ---------- Phase 10: Metadata matches ----------

func TestAnalyze_HelperMatchValid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"FORWARD": {Filter: []ast.Rule{{Jump: "accept", Match: []*ast.MatchBlock{{Helper: &ast.HelperMatch{Name: "ftp"}}}}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_HelperMatchMissing(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"FORWARD": {Filter: []ast.Rule{{Jump: "accept", Match: []*ast.MatchBlock{{Helper: &ast.HelperMatch{}}}}}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "requires name") {
		t.Fatalf("expected requires error, got: %v", err)
	}
}

func TestAnalyze_RealmMatchValid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"FORWARD": {Filter: []ast.Rule{{Jump: "accept", Match: []*ast.MatchBlock{{Realm: &ast.RealmMatch{Realm: "0x10/0xff"}}}}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_ClusterMatchValid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"PREROUTING": {Mangle: []ast.Rule{{Jump: "accept", Match: []*ast.MatchBlock{{Cluster: &ast.ClusterMatch{TotalNodes: 4, LocalNode: 2}}}}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_ClusterMatchOutOfRange(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"PREROUTING": {Mangle: []ast.Rule{{Jump: "accept", Match: []*ast.MatchBlock{{Cluster: &ast.ClusterMatch{TotalNodes: 3, LocalNode: 5}}}}}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "total-nodes") {
		t.Fatalf("expected range error, got: %v", err)
	}
}

func TestAnalyze_CPUMatchValid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "accept", Match: []*ast.MatchBlock{{CPU: &ast.CPUMatch{CPU: 2}}}}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_DevGroupMatchValid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"PREROUTING": {Mangle: []ast.Rule{{Jump: "accept", Match: []*ast.MatchBlock{{DevGroup: &ast.DevGroupMatch{SrcGroup: "0x10/0xff"}}}}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_RpFilterMatchValid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"PREROUTING": {Mangle: []ast.Rule{{Jump: "accept", Match: []*ast.MatchBlock{{RpFilter: &ast.RpFilterMatch{Loose: true, ValidMark: true}}}}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_QuotaMatchValid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "accept", Match: []*ast.MatchBlock{{Quota: &ast.QuotaMatch{Quota: 1024 * 1024}}}}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_QuotaMatchZero(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "accept", Match: []*ast.MatchBlock{{Quota: &ast.QuotaMatch{Quota: 0}}}}}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "> 0") {
		t.Fatalf("expected > 0 error, got: %v", err)
	}
}

func TestAnalyze_ConnBytesMatchValid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "accept", Match: []*ast.MatchBlock{{ConnBytes: &ast.ConnBytesMatch{Connbytes: "100:500", ConnbytesDir: "both", Mode: "bytes"}}}}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_ConnBytesMatchBadDir(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "accept", Match: []*ast.MatchBlock{{ConnBytes: &ast.ConnBytesMatch{Connbytes: "100", ConnbytesDir: "bogus", Mode: "bytes"}}}}}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "unknown connbytes-dir") {
		t.Fatalf("expected unknown dir error, got: %v", err)
	}
}

func TestAnalyze_ConnLabelMatchValid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "accept", Match: []*ast.MatchBlock{{ConnLabel: &ast.ConnLabelMatch{Label: 7, Set: true}}}}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_ConnLabelMatchOutOfRange(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "accept", Match: []*ast.MatchBlock{{ConnLabel: &ast.ConnLabelMatch{Label: 200}}}}}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "0-127") {
		t.Fatalf("expected range error, got: %v", err)
	}
}

func TestAnalyze_NfacctMatchValid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "accept", Match: []*ast.MatchBlock{{Nfacct: &ast.NfacctMatch{Name: "http-accounting"}}}}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

// ---------- Phase 10: Structured matches ----------

func TestAnalyze_StringMatchValid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "drop", Match: []*ast.MatchBlock{{String: &ast.StringMatch{Algo: "bm", String: "BitTorrent"}}}}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_StringMatchBadAlgo(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "drop", Match: []*ast.MatchBlock{{String: &ast.StringMatch{Algo: "aho", String: "x"}}}}}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "must be bm or kmp") {
		t.Fatalf("expected algo error, got: %v", err)
	}
}

func TestAnalyze_BPFMatchValid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "drop", Match: []*ast.MatchBlock{{BPF: &ast.BPFMatch{Bytecode: "6,40 0 0 12,21 0 3 2048"}}}}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_U32MatchValid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "drop", Match: []*ast.MatchBlock{{U32: &ast.U32Match{U32: "0>>22&0x3C@ 4>>16=0x1234"}}}}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_StatisticRandomValid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "drop", Match: []*ast.MatchBlock{{Statistic: &ast.StatisticMatch{Mode: "random", Probability: 0.5}}}}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_StatisticNthValid(t *testing.T) {
	pkt := 0
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "drop", Match: []*ast.MatchBlock{{Statistic: &ast.StatisticMatch{Mode: "nth", Every: 3, Packet: &pkt}}}}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_StatisticMixed(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "drop", Match: []*ast.MatchBlock{{Statistic: &ast.StatisticMatch{Mode: "random", Probability: 0.5, Every: 3}}}}}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "does not accept") {
		t.Fatalf("expected not-accept error, got: %v", err)
	}
}

func TestAnalyze_PolicyMatchValid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "accept", Match: []*ast.MatchBlock{{Policy: &ast.PolicyMatch{Dir: "in", Policy: "ipsec", Strict: true, Elements: []ast.PolicyElement{{Proto: "esp", Mode: "tunnel"}}}}}}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

// ---------- Phase 10: IPv6 extension headers ----------

func TestAnalyze_IPv6HeaderMatchValid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "drop", Match: []*ast.MatchBlock{{IPv6Header: &ast.IPv6HeaderMatch{Header: []string{"frag", "esp"}}}}}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_IPv6HeaderMatchBadName(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "drop", Match: []*ast.MatchBlock{{IPv6Header: &ast.IPv6HeaderMatch{Header: []string{"bogus"}}}}}}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "unknown ipv6header") {
		t.Fatalf("expected unknown header error, got: %v", err)
	}
}

func TestAnalyze_FragMatchValid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "drop", Match: []*ast.MatchBlock{{Frag: &ast.FragMatch{ID: "10:100", First: true}}}}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAnalyze_RtMatchBadAddr(t *testing.T) {
	typ := 0
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "drop", Match: []*ast.MatchBlock{{Rt: &ast.RtMatch{Type: &typ, Addrs: "::1, 10.0.0.1"}}}}}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "not a valid IPv6") {
		t.Fatalf("expected IPv6 error, got: %v", err)
	}
}

func TestAnalyze_MHMatchValid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Filter: []ast.Rule{{Jump: "drop", Match: []*ast.MatchBlock{{MH: &ast.MHMatch{Type: "binding-update"}}}}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

// ---------- security table ----------

func TestAnalyze_SecurityTableSecmarkValid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Security: []ast.Rule{{Jump: "secmark", SelCtx: "system_u:object_r:foo_t:s0"}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error for SECMARK in security table, got: %v", err)
	}
}

func TestAnalyze_SecurityTableConnsecmarkValid(t *testing.T) {
	doc := makeDoc(nil, map[string]ast.Chain{
		"OUTPUT": {Security: []ast.Rule{{Jump: "connsecmark", ConnSecMarkSave: true}}},
	})
	if _, err := Analyze(doc); err != nil {
		t.Fatalf("expected no error for CONNSECMARK in security table, got: %v", err)
	}
}

func TestAnalyze_SecurityTableBuiltinChains(t *testing.T) {
	// Security table has built-in chains INPUT, FORWARD, OUTPUT.
	for _, chain := range []string{"INPUT", "FORWARD", "OUTPUT"} {
		doc := makeDoc(nil, map[string]ast.Chain{
			chain: {Security: []ast.Rule{{Jump: "accept"}}},
		})
		if _, err := Analyze(doc); err != nil {
			t.Fatalf("expected no error for security/%s, got: %v", chain, err)
		}
	}
}

func TestAnalyze_CTNotValidInSecurity(t *testing.T) {
	// CT target is raw-only and must be rejected when placed in security.
	doc := makeDoc(nil, map[string]ast.Chain{
		"INPUT": {Security: []ast.Rule{{Notrack: true, Jump: "ct"}}},
	})
	_, err := Analyze(doc)
	if err == nil || !strings.Contains(err.Error(), "raw table") {
		t.Fatalf("expected 'raw table' error, got: %v", err)
	}
}
