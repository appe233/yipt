package ast

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestUnmarshalYAML_UnknownField(t *testing.T) {
	input := `{dpo: 80, j: accept}`
	var r Rule
	err := yaml.Unmarshal([]byte(input), &r)
	if err == nil {
		t.Fatal("expected error for unknown field 'dpo'")
	}
	if !strings.Contains(err.Error(), "unknown rule field") {
		t.Errorf("expected 'unknown rule field' in error, got: %v", err)
	}
}

func TestUnmarshalYAML_UnknownFieldTypo(t *testing.T) {
	input := `{dp: 80, jj: accept}`
	var r Rule
	err := yaml.Unmarshal([]byte(input), &r)
	if err == nil {
		t.Fatal("expected error for unknown field 'jj'")
	}
}

func TestUnmarshalYAML_ValidFields(t *testing.T) {
	input := `{i: eth0, o: eth1, s: 10.0.0.1, d: 10.0.0.2, p: tcp, sp: 1234, dp: 80, j: accept, comment: test}`
	var r Rule
	err := yaml.Unmarshal([]byte(input), &r)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if r.In != "eth0" || r.Out != "eth1" || r.Jump != "accept" {
		t.Errorf("unexpected values: %+v", r)
	}
}

func TestUnmarshalYAML_AllNegatedFields(t *testing.T) {
	input := `{"i!": eth0, "o!": eth1, "s!": 10.0.0.1, "d!": 10.0.0.2, "sp!": 80, "dp!": 443}`
	var r Rule
	err := yaml.Unmarshal([]byte(input), &r)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestUnmarshalYAML_MatchBlock(t *testing.T) {
	input := `{match: {conntrack: {ctstate: [ESTABLISHED]}}, j: accept}`
	var r Rule
	err := yaml.Unmarshal([]byte(input), &r)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if r.Match == nil || r.Match.Conntrack == nil {
		t.Fatal("expected match.conntrack to be set")
	}
}

func TestUnmarshalYAML_NATFields(t *testing.T) {
	input := `{j: dnat, to-destination: "10.0.0.1", to-ports: "8080"}`
	var r Rule
	err := yaml.Unmarshal([]byte(input), &r)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if r.ToDest != "10.0.0.1" || r.ToPorts != "8080" {
		t.Errorf("unexpected NAT values: %+v", r)
	}
}
