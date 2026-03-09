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
