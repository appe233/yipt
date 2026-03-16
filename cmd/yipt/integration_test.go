package main

import (
	"strings"
	"testing"

	"github.com/appe233/yipt/internal/codegen"
	"github.com/appe233/yipt/internal/ir"
	"github.com/appe233/yipt/internal/parser"
	"github.com/appe233/yipt/internal/sema"
)

const allFeaturesYAML = "../../rule_files/all_features.yaml"
const natExampleYAML = "../../rule_files/nat_example.yaml"
const multiportSplitYAML = "../../rule_files/multiport_split.yaml"

func buildOutput(t *testing.T) (iptables, ipset string) {
	t.Helper()
	doc, err := parser.ParseFile(allFeaturesYAML)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	resolved, err := sema.Analyze(doc)
	if err != nil {
		t.Fatalf("sema: %v", err)
	}
	prog, err := ir.Build(resolved)
	if err != nil {
		t.Fatalf("ir: %v", err)
	}
	return codegen.RenderIptablesRestore(prog), codegen.RenderIpsetScript(prog)
}

func TestIntegration_FilterAndMangleTables(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "*filter") {
		t.Error("expected *filter block")
	}
	if !strings.Contains(ipt, "*mangle") {
		t.Error("expected *mangle block")
	}
}

func TestIntegration_InputDropPolicy(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, ":INPUT DROP [0:0]") {
		t.Error("expected ':INPUT DROP [0:0]'")
	}
}

func TestIntegration_UserDefinedChains(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-N SSHBRUTE") {
		t.Error("expected '-N SSHBRUTE'")
	}
	if !strings.Contains(ipt, "-N DOCKER-USER") {
		t.Error("expected '-N DOCKER-USER'")
	}
	if !strings.Contains(ipt, "-N ICMPFLOOD") {
		t.Error("expected '-N ICMPFLOOD'")
	}
}

func TestIntegration_ICMPTypesetExpansion(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-4 -A INPUT -p icmp --icmp-type 0 -j ACCEPT") {
		t.Errorf("expected ICMP typeset expansion with type 0\nOutput:\n%s", ipt)
	}
}

func TestIntegration_IPSetMatchSet(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-m set --match-set bgp_peers_v4 src") {
		t.Errorf("expected bgp_peers_v4 ipset match\nOutput:\n%s", ipt)
	}
}

func TestIntegration_MultiportDports(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-m multiport --dports 80,443") {
		t.Errorf("expected multiport --dports 80,443\nOutput:\n%s", ipt)
	}
}

func TestIntegration_Comment(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, `-m comment --comment "WireGuard peers"`) {
		t.Errorf("expected comment for WireGuard peers rule\nOutput:\n%s", ipt)
	}
}

func TestIntegration_IpsetCreateExist(t *testing.T) {
	_, ipset := buildOutput(t)
	if !strings.Contains(ipset, "ipset create -exist trusted_networks hash:net family inet") {
		t.Errorf("expected 'ipset create -exist trusted_networks'\\nOutput:\\n%s", ipset)
	}
}

func buildNATOutput(t *testing.T) string {
	t.Helper()
	doc, err := parser.ParseFile(natExampleYAML)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	resolved, err := sema.Analyze(doc)
	if err != nil {
		t.Fatalf("sema: %v", err)
	}
	prog, err := ir.Build(resolved)
	if err != nil {
		t.Fatalf("ir: %v", err)
	}
	return codegen.RenderIptablesRestore(prog)
}

func TestIntegration_NATTable(t *testing.T) {
	ipt := buildNATOutput(t)
	if !strings.Contains(ipt, "*nat") {
		t.Errorf("expected *nat block\\nOutput:\\n%s", ipt)
	}
}

func TestIntegration_NATMasquerade(t *testing.T) {
	ipt := buildNATOutput(t)
	if !strings.Contains(ipt, "-j MASQUERADE") {
		t.Errorf("expected -j MASQUERADE\\nOutput:\\n%s", ipt)
	}
}

func TestIntegration_NATSNAT(t *testing.T) {
	ipt := buildNATOutput(t)
	if !strings.Contains(ipt, "-j SNAT --to-source 203.0.113.1") {
		t.Errorf("expected -j SNAT --to-source 203.0.113.1\\nOutput:\\n%s", ipt)
	}
}

func TestIntegration_NATDNAT(t *testing.T) {
	ipt := buildNATOutput(t)
	if !strings.Contains(ipt, "-j DNAT --to-destination 192.168.1.100 --to-ports 8080") {
		t.Errorf("expected -j DNAT --to-destination ...\\nOutput:\\n%s", ipt)
	}
}

func TestIntegration_NATRedirect(t *testing.T) {
	ipt := buildNATOutput(t)
	if !strings.Contains(ipt, "-j REDIRECT --to-ports 80") {
		t.Errorf("expected -j REDIRECT --to-ports 80\\nOutput:\\n%s", ipt)
	}
}

func buildMultiportSplitOutput(t *testing.T) string {
	t.Helper()
	doc, err := parser.ParseFile(multiportSplitYAML)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	resolved, err := sema.Analyze(doc)
	if err != nil {
		t.Fatalf("sema: %v", err)
	}
	prog, err := ir.Build(resolved)
	if err != nil {
		t.Fatalf("ir: %v", err)
	}
	return codegen.RenderIptablesRestore(prog)
}

func TestIntegration_MultiportSplit(t *testing.T) {
	ipt := buildMultiportSplitOutput(t)
	// 16 ports should produce 2 rules (15 + 1)
	count := strings.Count(ipt, "-m multiport --dports")
	if count != 2 {
		t.Errorf("expected 2 multiport rules (split from 16 ports), got %d\nOutput:\n%s", count, ipt)
	}
	// Both rules should have the ACCEPT jump
	acceptCount := strings.Count(ipt, "-j ACCEPT")
	if acceptCount != 2 {
		t.Errorf("expected 2 ACCEPT jumps, got %d\nOutput:\n%s", acceptCount, ipt)
	}
}

func TestIntegration_FormatIPv4Only(t *testing.T) {
	doc, err := parser.ParseFile(allFeaturesYAML)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	resolved, err := sema.Analyze(doc)
	if err != nil {
		t.Fatalf("sema: %v", err)
	}
	prog, err := ir.Build(resolved)
	if err != nil {
		t.Fatalf("ir: %v", err)
	}

	output := codegen.RenderIptablesRestoreIPv4(prog)

	// Should not have -4 or -6 prefixes
	if strings.Contains(output, "-4 -A") {
		t.Error("IPv4-only output should not contain -4 prefix")
	}
	if strings.Contains(output, "-6 -A") {
		t.Error("IPv4-only output should not contain -6 prefix")
	}

	// Should contain IPv4-specific rules
	if !strings.Contains(output, "*filter") {
		t.Error("expected *filter table")
	}
}

func TestIntegration_FormatIPv6Only(t *testing.T) {
	doc, err := parser.ParseFile(allFeaturesYAML)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	resolved, err := sema.Analyze(doc)
	if err != nil {
		t.Fatalf("sema: %v", err)
	}
	prog, err := ir.Build(resolved)
	if err != nil {
		t.Fatalf("ir: %v", err)
	}

	output := codegen.RenderIptablesRestoreIPv6(prog)

	// Should not have -4 or -6 prefixes
	if strings.Contains(output, "-4 -A") {
		t.Error("IPv6-only output should not contain -4 prefix")
	}
	if strings.Contains(output, "-6 -A") {
		t.Error("IPv6-only output should not contain -6 prefix")
	}

	// Should contain IPv6-specific rules
	if !strings.Contains(output, "*filter") {
		t.Error("expected *filter table")
	}
}

func TestIntegration_FormatCombined(t *testing.T) {
	doc, err := parser.ParseFile(allFeaturesYAML)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	resolved, err := sema.Analyze(doc)
	if err != nil {
		t.Fatalf("sema: %v", err)
	}
	prog, err := ir.Build(resolved)
	if err != nil {
		t.Fatalf("ir: %v", err)
	}

	output := codegen.RenderIptablesRestore(prog)

	// Should have -4 and -6 prefixes in combined mode
	if !strings.Contains(output, "-4 -A") {
		t.Error("combined output should contain -4 prefix")
	}
}

func TestIntegration_FormatIpset(t *testing.T) {
	doc, err := parser.ParseFile(allFeaturesYAML)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	resolved, err := sema.Analyze(doc)
	if err != nil {
		t.Fatalf("sema: %v", err)
	}
	prog, err := ir.Build(resolved)
	if err != nil {
		t.Fatalf("ir: %v", err)
	}

	output := codegen.RenderIpsetScript(prog)

	// Should contain ipset commands
	if !strings.Contains(output, "ipset create -exist") {
		t.Error("expected ipset create commands")
	}
	if !strings.Contains(output, "ipset add") {
		t.Error("expected ipset add commands")
	}
}
