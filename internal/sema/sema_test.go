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
			"nets": {Type: "ipset", Elements: []interface{}{"10.0.0.0/8", "192.168.0.0/16"}},
			"ports": {Type: "portset", Elements: []interface{}{80, 443}},
			"icmptypes": {Type: "icmp_typeset", Elements: []interface{}{0, 3, 11}},
			"icmpv6types": {Type: "icmpv6_typeset", Elements: []interface{}{1, 2, 3}},
		},
		map[string]ast.Chain{
			"INPUT": {
				Filter: []ast.Rule{
					{Src: "$nets", Jump: "accept"},
					{DPort: "$ports", Jump: "accept"},
				},
			},
		},
	)
	_, err := Analyze(doc)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
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
