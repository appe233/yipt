package ir

import (
	"testing"

	"github.com/appe233/yipt/internal/ast"
	"github.com/appe233/yipt/internal/sema"
)

func makeResources(t *testing.T) map[string]*sema.ResolvedResource {
	t.Helper()
	return map[string]*sema.ResolvedResource{
		"mixed": {
			Name:         "mixed",
			Type:         "ipset",
			IsMixed:      true,
			IPv4Elements: []string{"10.0.0.0/8"},
			IPv6Elements: []string{"fd00::/8"},
		},
		"v4only": {
			Name:         "v4only",
			Type:         "ipset",
			IPv4Elements: []string{"192.168.0.0/16"},
		},
		"myports": {
			Name:     "myports",
			Type:     "portset",
			Elements: []interface{}{80, 443},
		},
		"icmptypes": {
			Name:     "icmptypes",
			Type:     "icmp_typeset",
			Elements: []interface{}{0, 3, 11, 12},
		},
	}
}

func TestExpandRule_ProtoList(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{
		Proto: []interface{}{"tcp", "udp"},
		Jump:  "accept",
	}
	rules, err := expandRule("INPUT", rule, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules from proto list, got %d", len(rules))
	}
	if rules[0].Proto != "tcp" {
		t.Errorf("expected first proto=tcp, got %q", rules[0].Proto)
	}
	if rules[1].Proto != "udp" {
		t.Errorf("expected second proto=udp, got %q", rules[1].Proto)
	}
}

func TestExpandRule_ICMPTypeset(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{
		Proto:    "icmp",
		ICMPType: "$icmptypes",
		Jump:     "accept",
	}
	rules, err := expandRule("INPUT", rule, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 4 {
		t.Fatalf("expected 4 rules from icmp typeset (4 elements), got %d", len(rules))
	}
	types := []string{"0", "3", "11", "12"}
	for i, r := range rules {
		if r.ICMPType != types[i] {
			t.Errorf("rule[%d] ICMPType = %q, want %q", i, r.ICMPType, types[i])
		}
	}
}

func TestExpandRule_MixedIPSet(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{
		Src:  "$mixed",
		Jump: "accept",
	}
	rules, err := expandRule("INPUT", rule, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules from mixed ipset, got %d", len(rules))
	}
	// Check v4 rule
	if rules[0].Src != "mixed_v4" {
		t.Errorf("expected mixed_v4, got %q", rules[0].Src)
	}
	if rules[0].IPVersion != 4 {
		t.Errorf("expected IPVersion=4, got %d", rules[0].IPVersion)
	}
	if !rules[0].SrcIsSet {
		t.Error("expected SrcIsSet=true for ipset ref")
	}
	// Check v6 rule
	if rules[1].Src != "mixed_v6" {
		t.Errorf("expected mixed_v6, got %q", rules[1].Src)
	}
	if rules[1].IPVersion != 6 {
		t.Errorf("expected IPVersion=6, got %d", rules[1].IPVersion)
	}
}

func TestExpandRule_PortMulti(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{
		Proto: "tcp",
		DPort: []interface{}{80, 443},
		Jump:  "accept",
	}
	rules, err := expandRule("INPUT", rule, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if !rules[0].DPortMulti {
		t.Error("expected DPortMulti=true for multi-port list")
	}
	if rules[0].DPort != "80,443" {
		t.Errorf("expected DPort=80,443, got %q", rules[0].DPort)
	}
}

func TestExpandRule_PortSingle(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{
		Proto: "tcp",
		DPort: 22,
		Jump:  "accept",
	}
	rules, err := expandRule("INPUT", rule, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rules[0].DPortMulti {
		t.Error("expected DPortMulti=false for single port")
	}
	if rules[0].DPort != "22" {
		t.Errorf("expected DPort=22, got %q", rules[0].DPort)
	}
}

func TestExpandRule_SingleElementList(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{
		Proto: "tcp",
		DPort: []interface{}{22},
		Jump:  "accept",
	}
	rules, err := expandRule("INPUT", rule, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rules[0].DPortMulti {
		t.Error("expected DPortMulti=false for single-element list")
	}
}

func TestExpandRule_CommentPropagates(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{
		Proto:   []interface{}{"tcp", "udp"},
		DPort:   80,
		Jump:    "accept",
		Comment: "my comment",
	}
	rules, err := expandRule("INPUT", rule, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	for i, r := range rules {
		if r.Comment != "my comment" {
			t.Errorf("rule[%d] Comment = %q, want %q", i, r.Comment, "my comment")
		}
	}
}
