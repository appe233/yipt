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
	if len(r.Match) != 1 || r.Match[0].Conntrack == nil {
		t.Fatal("expected match.conntrack to be set")
	}
}

func TestUnmarshalYAML_MatchBlockList(t *testing.T) {
	input := `{match: [{recent: {name: SSH, set: true}}, {recent: {name: SSH, update: true, seconds: 60}}], j: drop}`
	var r Rule
	if err := yaml.Unmarshal([]byte(input), &r); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(r.Match) != 2 {
		t.Fatalf("expected 2 match blocks, got %d", len(r.Match))
	}
	if r.Match[0].Recent == nil || !r.Match[0].Recent.Set {
		t.Errorf("first match should have recent.set=true")
	}
	if r.Match[1].Recent == nil || !r.Match[1].Recent.Update || r.Match[1].Recent.Seconds != 60 {
		t.Errorf("second match should have recent.update=true seconds=60")
	}
}

func TestUnmarshalYAML_MACSourceNegation(t *testing.T) {
	input := `{match: {mac: {"mac-source!": "aa:bb:cc:dd:ee:ff"}}, j: drop}`
	var r Rule
	if err := yaml.Unmarshal([]byte(input), &r); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(r.Match) != 1 || r.Match[0].MAC == nil {
		t.Fatal("expected mac match")
	}
	if !r.Match[0].MAC.Neg {
		t.Errorf("expected Neg=true from mac-source! key")
	}
	if r.Match[0].MAC.MACSource != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("MACSource = %q, want aa:bb:cc:dd:ee:ff", r.Match[0].MAC.MACSource)
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

// === Phase 9 — YAML surface for packet-modification targets ===

func TestUnmarshalYAML_ClassifyFields(t *testing.T) {
	input := `{j: classify, set-class: "1:10"}`
	var r Rule
	if err := yaml.Unmarshal([]byte(input), &r); err != nil {
		t.Fatalf("%v", err)
	}
	if r.Jump != "classify" || r.SetClass != "1:10" {
		t.Errorf("got %+v", r)
	}
}

func TestUnmarshalYAML_DSCPFields(t *testing.T) {
	input := `{j: dscp, set-dscp-class: "EF"}`
	var r Rule
	if err := yaml.Unmarshal([]byte(input), &r); err != nil {
		t.Fatalf("%v", err)
	}
	if r.SetDSCPClass != "EF" {
		t.Errorf("got %+v", r)
	}
}

func TestUnmarshalYAML_TOSFields(t *testing.T) {
	input := `{j: tos, set-tos: "0x10"}`
	var r Rule
	if err := yaml.Unmarshal([]byte(input), &r); err != nil {
		t.Fatalf("%v", err)
	}
	if r.SetTOS != "0x10" {
		t.Errorf("got %+v", r)
	}
}

func TestUnmarshalYAML_TTLTargetFields(t *testing.T) {
	input := `{j: ttl, ttl-set: 64}`
	var r Rule
	if err := yaml.Unmarshal([]byte(input), &r); err != nil {
		t.Fatalf("%v", err)
	}
	if r.TTLSet == nil || *r.TTLSet != 64 {
		t.Errorf("got %+v", r)
	}
}

func TestUnmarshalYAML_HLTargetFields(t *testing.T) {
	input := `{j: hl, hl-dec: 1}`
	var r Rule
	if err := yaml.Unmarshal([]byte(input), &r); err != nil {
		t.Fatalf("%v", err)
	}
	if r.HLDec == nil || *r.HLDec != 1 {
		t.Errorf("got %+v", r)
	}
}

func TestUnmarshalYAML_SYNPROXYFields(t *testing.T) {
	input := `{j: synproxy, synproxy-mss: 1460, synproxy-wscale: 7, synproxy-timestamp: true, synproxy-sack-perm: true}`
	var r Rule
	if err := yaml.Unmarshal([]byte(input), &r); err != nil {
		t.Fatalf("%v", err)
	}
	if r.SynproxyMSS != 1460 || r.SynproxyWScale != 7 || !r.SynproxyTimestamp || !r.SynproxySAckPerm {
		t.Errorf("got %+v", r)
	}
}

func TestUnmarshalYAML_CLUSTERIPFields(t *testing.T) {
	input := `{j: clusterip, clusterip-new: true, clusterip-hashmode: sourceip, clusterip-clustermac: "01:00:5e:01:02:03", clusterip-total-nodes: 4, clusterip-local-node: 1, clusterip-hash-init: 12345}`
	var r Rule
	if err := yaml.Unmarshal([]byte(input), &r); err != nil {
		t.Fatalf("%v", err)
	}
	if !r.ClusterIPNew || r.ClusterIPHashmode != "sourceip" || r.ClusterIPTotalNodes != 4 || r.ClusterIPLocalNode != 1 {
		t.Errorf("got %+v", r)
	}
}

func TestUnmarshalYAML_LEDFields(t *testing.T) {
	input := `{j: led, led-trigger-id: "foo", led-delay: 0, led-always-blink: true}`
	var r Rule
	if err := yaml.Unmarshal([]byte(input), &r); err != nil {
		t.Fatalf("%v", err)
	}
	if r.LEDTriggerID != "foo" || r.LEDDelay != 0 || !r.LEDDelaySet {
		t.Errorf("got %+v", r)
	}
}

func TestUnmarshalYAML_Phase9UnknownField(t *testing.T) {
	// Unknown fields are still rejected after Phase 9 additions.
	input := `{j: classify, set-clasz: "1:10"}`
	var r Rule
	if err := yaml.Unmarshal([]byte(input), &r); err == nil {
		t.Fatalf("expected unknown field error")
	}
}
