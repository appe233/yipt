package sema

import (
	"strings"
	"testing"

	"yipt/internal/ast"
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
