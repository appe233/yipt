package codegen

import (
	"strings"
	"testing"

	"github.com/appe233/yipt/internal/ast"
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
	if !strings.Contains(got, "ipset add -exist trusted_networks 192.168.1.0/24") {
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

// -----------------------------------------------------------------------------
// Phase 7 — richer set types and creation attributes.
// -----------------------------------------------------------------------------

func TestRenderIpsetScript_HashIPPortWithTimeout(t *testing.T) {
	timeout := 3600
	prog := &ir.Program{
		IPv4Ipsets: []ir.Ipset{{
			Name:     "svc",
			Family:   "inet",
			SetType:  "hash:ip,port",
			Options:  &ast.SetOptions{Timeout: &timeout, MaxElem: 8192, Counters: true},
			Elements: []string{"10.0.0.1,tcp:22"},
		}},
	}
	got := RenderIpsetScript(prog)
	want := "ipset create -exist svc hash:ip,port family inet maxelem 8192 timeout 3600 counters"
	if !strings.Contains(got, want) {
		t.Errorf("missing %q in:\n%s", want, got)
	}
	if !strings.Contains(got, "ipset add -exist svc 10.0.0.1,tcp:22") {
		t.Errorf("missing tuple add line in:\n%s", got)
	}
}

func TestRenderIpsetScript_BitmapPortUsesRangeNotFamily(t *testing.T) {
	prog := &ir.Program{
		IPv4Ipsets: []ir.Ipset{{
			Name:     "hp",
			Family:   "inet",
			SetType:  "bitmap:port",
			Options:  &ast.SetOptions{Range: "1024-65535"},
			Elements: []string{"1024-2048", "2049"},
		}},
	}
	got := RenderIpsetScript(prog)
	if !strings.Contains(got, "ipset create -exist hp bitmap:port range 1024-65535") {
		t.Errorf("expected bitmap:port create line with range, got:\n%s", got)
	}
	if strings.Contains(got, "bitmap:port family") {
		t.Errorf("bitmap:port must not include family, got:\n%s", got)
	}
}

func TestRenderIpsetScript_HashMACNoAddress(t *testing.T) {
	prog := &ir.Program{
		IPv4Ipsets: []ir.Ipset{{
			Name:     "macs",
			Family:   "inet",
			SetType:  "hash:mac",
			Elements: []string{"02:00:00:00:00:01"},
		}},
	}
	got := RenderIpsetScript(prog)
	if !strings.Contains(got, "ipset create -exist macs hash:mac") {
		t.Errorf("expected hash:mac create line, got:\n%s", got)
	}
	if strings.Contains(got, "macs hash:mac family") {
		t.Errorf("hash:mac must not include family, got:\n%s", got)
	}
}

func TestRenderIpsetScript_NetmaskOption(t *testing.T) {
	prog := &ir.Program{
		IPv4Ipsets: []ir.Ipset{{
			Name:     "offices",
			Family:   "inet",
			SetType:  "hash:ip",
			Options:  &ast.SetOptions{NetMask: 24},
			Elements: []string{"198.51.100.10"},
		}},
	}
	got := RenderIpsetScript(prog)
	if !strings.Contains(got, "ipset create -exist offices hash:ip family inet netmask 24") {
		t.Errorf("expected netmask in create line, got:\n%s", got)
	}
}
