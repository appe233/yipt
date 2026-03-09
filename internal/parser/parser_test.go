package parser

import (
	"testing"
)

const allFeaturesPath = "../../rule_files/all_features.yaml"

func TestParseFile_AllFeatures(t *testing.T) {
	doc, err := ParseFile(allFeaturesPath)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	// Check resources exist.
	if _, ok := doc.Resources["trusted_networks"]; !ok {
		t.Error("expected resource 'trusted_networks'")
	}
	if _, ok := doc.Resources["wg_ports"]; !ok {
		t.Error("expected resource 'wg_ports'")
	}
	if _, ok := doc.Resources["basic_icmp_types"]; !ok {
		t.Error("expected resource 'basic_icmp_types'")
	}

	// Check chains exist.
	if _, ok := doc.Chains["INPUT"]; !ok {
		t.Error("expected chain 'INPUT'")
	}
	if _, ok := doc.Chains["SSHBRUTE"]; !ok {
		t.Error("expected chain 'SSHBRUTE'")
	}
	if _, ok := doc.Chains["DOCKER-USER"]; !ok {
		t.Error("expected chain 'DOCKER-USER'")
	}

	// Check INPUT policy.
	inputChain := doc.Chains["INPUT"]
	if inputChain.Policy != "drop" {
		t.Errorf("expected INPUT policy=drop, got %q", inputChain.Policy)
	}

	// Check INPUT has filter rules.
	if len(inputChain.Filter) == 0 {
		t.Error("expected INPUT to have filter rules")
	}
}
