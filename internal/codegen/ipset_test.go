package codegen

import (
	"strings"
	"testing"

	"github.com/appe233/yipt/internal/ir"
)

func TestRenderIpsetScript_IPv4Only(t *testing.T) {
	prog := &ir.Program{
		IPv4Ipsets: []ir.Ipset{
			{Name: "trusted_networks", Family: "inet", Elements: []string{"192.168.1.0/24", "10.0.0.0/24"}},
		},
	}
	got := RenderIpsetScript(prog)
	if !strings.Contains(got, "ipset create -exist trusted_networks hash:net family inet") {
		t.Errorf("expected create line with -exist and family inet, got:\n%s", got)
	}
	if !strings.Contains(got, "ipset add trusted_networks 192.168.1.0/24") {
		t.Errorf("expected add line for element, got:\n%s", got)
	}
	// Must not have inet6 for IPv4-only set
	if strings.Contains(got, "inet6") {
		t.Errorf("unexpected inet6 for IPv4-only set, got:\n%s", got)
	}
}

func TestRenderIpsetScript_IPv6Only(t *testing.T) {
	prog := &ir.Program{
		IPv6Ipsets: []ir.Ipset{
			{Name: "v6_nets", Family: "inet6", Elements: []string{"fd00::/8"}},
		},
	}
	got := RenderIpsetScript(prog)
	if !strings.Contains(got, "ipset create -exist v6_nets hash:net family inet6") {
		t.Errorf("expected create line with -exist and family inet6, got:\n%s", got)
	}
}

func TestRenderIpsetScript_ExistFlag(t *testing.T) {
	prog := &ir.Program{
		IPv4Ipsets: []ir.Ipset{
			{Name: "myset", Family: "inet", Elements: []string{"1.2.3.4"}},
		},
	}
	got := RenderIpsetScript(prog)
	if !strings.Contains(got, "create -exist ") {
		t.Errorf("expected '-exist' flag in ipset create, got:\n%s", got)
	}
}
