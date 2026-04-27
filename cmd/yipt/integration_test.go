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

func TestIntegration_RawTableNOTRACK(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "*raw") {
		t.Errorf("expected *raw table in output\nOutput:\n%s", ipt)
	}
	if !strings.Contains(ipt, "-j NOTRACK") {
		t.Errorf("expected NOTRACK emission for notrack:true CT rule\nOutput:\n%s", ipt)
	}
}

func TestIntegration_RawTableCTZoneHelper(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-j CT --zone 5 --helper ftp") {
		t.Errorf("expected CT --zone 5 --helper ftp rule\nOutput:\n%s", ipt)
	}
}

func TestIntegration_TCPMSSClamp(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-j TCPMSS --clamp-mss-to-pmtu") {
		t.Errorf("expected -j TCPMSS --clamp-mss-to-pmtu\nOutput:\n%s", ipt)
	}
}

func TestIntegration_TCPMSSSetMSS(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-j TCPMSS --set-mss 1360") {
		t.Errorf("expected -j TCPMSS --set-mss 1360\nOutput:\n%s", ipt)
	}
}

func TestIntegration_TCPFlags(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "--tcp-flags SYN,ACK,FIN,RST FIN") {
		t.Errorf("expected --tcp-flags SYN,ACK,FIN,RST FIN\nOutput:\n%s", ipt)
	}
	if !strings.Contains(ipt, "--tcp-flags ALL NONE") {
		t.Errorf("expected --tcp-flags ALL NONE\nOutput:\n%s", ipt)
	}
}

func TestIntegration_Fragment(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-4 -A INPUT -f") {
		t.Errorf("expected IPv4 fragment rule with -f\nOutput:\n%s", ipt)
	}
}

func TestIntegration_TCPOption(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "--tcp-option 7") {
		t.Errorf("expected --tcp-option 7\nOutput:\n%s", ipt)
	}
}

func TestIntegration_ConnmarkRestoreMark(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-j CONNMARK --restore-mark") {
		t.Errorf("expected -j CONNMARK --restore-mark\nOutput:\n%s", ipt)
	}
}

func TestIntegration_ConnmarkSaveMark(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-j CONNMARK --save-mark --nfmask 0xff --ctmask 0xff") {
		t.Errorf("expected -j CONNMARK --save-mark --nfmask 0xff --ctmask 0xff\nOutput:\n%s", ipt)
	}
}

func TestIntegration_ConnmarkSetMark(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-j CONNMARK --set-mark 0x42") {
		t.Errorf("expected -j CONNMARK --set-mark 0x42\nOutput:\n%s", ipt)
	}
}

func TestIntegration_ConnmarkMatch(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-m connmark --mark 0xff") {
		t.Errorf("expected -m connmark --mark 0xff\nOutput:\n%s", ipt)
	}
}

func TestIntegration_ConnlimitMatch(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-m connlimit --connlimit-above 10 --connlimit-mask 32 --connlimit-saddr") {
		t.Errorf("expected connlimit above/mask/saddr rendering\nOutput:\n%s", ipt)
	}
}

func TestIntegration_HashlimitMatch(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-m hashlimit --hashlimit-upto 100/second --hashlimit-burst 200 --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-name http_rate --hashlimit-htable-expire 60000") {
		t.Errorf("expected full hashlimit rendering\nOutput:\n%s", ipt)
	}
}

func TestIntegration_OwnerMatch(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-m owner --uid-owner 65534") {
		t.Errorf("expected owner --uid-owner rendering\nOutput:\n%s", ipt)
	}
	if !strings.Contains(ipt, "-m owner --socket-exists") {
		t.Errorf("expected owner --socket-exists rendering\nOutput:\n%s", ipt)
	}
}

func TestIntegration_IPRangeMatch(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-m iprange --src-range 198.18.0.0-198.19.255.255") {
		t.Errorf("expected iprange src-range rendering\nOutput:\n%s", ipt)
	}
}

func TestIntegration_LengthMatch(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-m length --length 1000:65535") {
		t.Errorf("expected length range rendering\nOutput:\n%s", ipt)
	}
}

func TestIntegration_TTLMatch(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-4 -A INPUT -m ttl --ttl-lt 5") {
		t.Errorf("expected ttl rendering as IPv4-only rule\nOutput:\n%s", ipt)
	}
}

func TestIntegration_HLMatch(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-6 -A INPUT -m hl --hl-lt 5") {
		t.Errorf("expected hl rendering as IPv6-only rule\nOutput:\n%s", ipt)
	}
}

func TestIntegration_PktTypeMatch(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-m pkttype --pkt-type broadcast") {
		t.Errorf("expected pkttype rendering\nOutput:\n%s", ipt)
	}
}

func TestIntegration_PhysDevMatch(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-m physdev --physdev-in eth0 --physdev-out eth1 --physdev-is-bridged") {
		t.Errorf("expected physdev rendering\nOutput:\n%s", ipt)
	}
}

func TestIntegration_IpsetCreateExist(t *testing.T) {
	_, ipset := buildOutput(t)
	if !strings.Contains(ipset, "ipset create -exist trusted_networks hash:net family inet") {
		t.Errorf("expected 'ipset create -exist trusted_networks'\\nOutput:\\n%s", ipset)
	}
}

func TestIntegration_NFLOGTarget(t *testing.T) {
	ipt, _ := buildOutput(t)
	want := `-j NFLOG --nflog-group 2 --nflog-prefix "DROPPED: " --nflog-range 256 --nflog-threshold 5`
	if !strings.Contains(ipt, want) {
		t.Errorf("expected NFLOG rendering %q\nOutput:\n%s", want, ipt)
	}
}

func TestIntegration_NFQUEUENum(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-j NFQUEUE --queue-num 0 --queue-bypass") {
		t.Errorf("expected -j NFQUEUE --queue-num 0 --queue-bypass\nOutput:\n%s", ipt)
	}
}

func TestIntegration_NFQUEUEBalance(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-j NFQUEUE --queue-balance 0:3 --queue-cpu-fanout") {
		t.Errorf("expected -j NFQUEUE --queue-balance 0:3 --queue-cpu-fanout\nOutput:\n%s", ipt)
	}
}

func TestIntegration_SETAddTarget(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-j SET --add-set dynamic_blocklist src --exist --timeout 3600") {
		t.Errorf("expected SET add-set rendering\nOutput:\n%s", ipt)
	}
}

func TestIntegration_SETDelTarget(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-j SET --del-set dynamic_blocklist src") {
		t.Errorf("expected SET del-set rendering\nOutput:\n%s", ipt)
	}
}

// -----------------------------------------------------------------------------
// Phase 7 — richer ipset types and multi-dim match direction flags.
// -----------------------------------------------------------------------------

func TestIntegration_HashIPPortMultiDim(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-m set --match-set allowed_services dst,dst") {
		t.Errorf("expected multi-dim dst,dst rendering\nOutput:\n%s", ipt)
	}
}

func TestIntegration_HashMACMatch(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-m set --match-set guest_macs src") {
		t.Errorf("expected hash:mac set match\nOutput:\n%s", ipt)
	}
}

func TestIntegration_BitmapPortMatch(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-m set --match-set high_ports dst") {
		t.Errorf("expected bitmap:port set match\nOutput:\n%s", ipt)
	}
}

func TestIntegration_IpsetHashIPPortEmission(t *testing.T) {
	_, ipsetScript := buildOutput(t)
	if !strings.Contains(ipsetScript, "ipset create -exist allowed_services hash:ip,port family inet") {
		t.Errorf("expected hash:ip,port create line\nOutput:\n%s", ipsetScript)
	}
	if !strings.Contains(ipsetScript, "timeout 3600") {
		t.Errorf("expected timeout 3600 option\nOutput:\n%s", ipsetScript)
	}
	if !strings.Contains(ipsetScript, "counters") {
		t.Errorf("expected counters option\nOutput:\n%s", ipsetScript)
	}
	if !strings.Contains(ipsetScript, "ipset add -exist allowed_services 10.0.0.1,tcp:22") {
		t.Errorf("expected tuple element\nOutput:\n%s", ipsetScript)
	}
}

func TestIntegration_IpsetBitmapPortEmission(t *testing.T) {
	_, ipsetScript := buildOutput(t)
	if !strings.Contains(ipsetScript, "ipset create -exist high_ports bitmap:port range 32768-65535") {
		t.Errorf("expected bitmap:port create with range\nOutput:\n%s", ipsetScript)
	}
	if strings.Contains(ipsetScript, "high_ports bitmap:port family") {
		t.Errorf("bitmap:port must not carry family\nOutput:\n%s", ipsetScript)
	}
}

func TestIntegration_IpsetHashMACEmission(t *testing.T) {
	_, ipsetScript := buildOutput(t)
	if !strings.Contains(ipsetScript, "ipset create -exist guest_macs hash:mac") {
		t.Errorf("expected hash:mac create line\nOutput:\n%s", ipsetScript)
	}
	if strings.Contains(ipsetScript, "guest_macs hash:mac family") {
		t.Errorf("hash:mac must not carry family\nOutput:\n%s", ipsetScript)
	}
}

func TestIntegration_IpsetNetmaskEmission(t *testing.T) {
	_, ipsetScript := buildOutput(t)
	if !strings.Contains(ipsetScript, "netmask 24") {
		t.Errorf("expected netmask 24 in office_ips\nOutput:\n%s", ipsetScript)
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

// === Phase 8 integration assertions ===

func TestIntegration_Phase8_AddrTypeSrcTypeAndLimitIface(t *testing.T) {
	ipt, _ := buildOutput(t)
	want := "-m addrtype --src-type LOCAL --limit-iface-in"
	if !strings.Contains(ipt, want) {
		t.Errorf("expected %q\nOutput:\n%s", want, ipt)
	}
}

func TestIntegration_Phase8_ConntrackCTStatusCTDir(t *testing.T) {
	ipt, _ := buildOutput(t)
	want := "-m conntrack --ctstatus ASSURED --ctdir ORIGINAL"
	if !strings.Contains(ipt, want) {
		t.Errorf("expected %q\nOutput:\n%s", want, ipt)
	}
}

func TestIntegration_Phase8_TimeDateStartMonthDays(t *testing.T) {
	ipt, _ := buildOutput(t)
	want := "--datestart 2026-01-01T00:00:00 --datestop 2026-12-31T23:59:59 --monthdays 1,15 --utc"
	if !strings.Contains(ipt, want) {
		t.Errorf("expected %q\nOutput:\n%s", want, ipt)
	}
}

func TestIntegration_Phase8_MACSourceNegation(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-m mac ! --mac-source aa:bb:cc:dd:ee:ff") {
		t.Errorf("expected negated MAC source match\nOutput:\n%s", ipt)
	}
}

func TestIntegration_Phase8_SocketTransparent(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-m socket --transparent") {
		t.Errorf("expected -m socket --transparent\nOutput:\n%s", ipt)
	}
}

func TestIntegration_Phase8_RecentExtendedOptions(t *testing.T) {
	ipt, _ := buildOutput(t)
	want := "-m recent --name SSH_CHECK --rcheck --seconds 600 --reap --hitcount 3 --rsource --mask 255.255.255.0"
	if !strings.Contains(ipt, want) {
		t.Errorf("expected extended recent rendering %q\nOutput:\n%s", want, ipt)
	}
}

func TestIntegration_Phase8_MatchListMultipleRecentEntries(t *testing.T) {
	ipt, _ := buildOutput(t)
	// The list-form match combines two recent entries into one rule line.
	// Verify both fragments appear in the same SSHBRUTE DROP rule.
	want := "-m recent --name SSH_CHECK --rcheck --seconds 600 --reap --hitcount 3 --rsource --mask 255.255.255.0 -m recent --name SSH_CHECK --remove"
	if !strings.Contains(ipt, want) {
		t.Errorf("expected chained match-list rendering\nOutput:\n%s", ipt)
	}
}

// === Phase 9 integration assertions ===

func TestIntegration_Phase9_CLASSIFY(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-j CLASSIFY --set-class 1:10") {
		t.Errorf("expected CLASSIFY\nOutput:\n%s", ipt)
	}
}

func TestIntegration_Phase9_DSCPClass(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-j DSCP --set-dscp-class EF") {
		t.Errorf("expected DSCP --set-dscp-class EF\nOutput:\n%s", ipt)
	}
}

func TestIntegration_Phase9_TOSSet(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-j TOS --set-tos 0x10") {
		t.Errorf("expected TOS --set-tos\nOutput:\n%s", ipt)
	}
}

func TestIntegration_Phase9_ECN(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-j ECN --ecn-tcp-remove") {
		t.Errorf("expected ECN --ecn-tcp-remove\nOutput:\n%s", ipt)
	}
}

func TestIntegration_Phase9_TTLTargetIPv4Only(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-4 -A FORWARD -p tcp -m comment --comment \"Decrement TTL\" -j TTL --ttl-dec 1") {
		t.Errorf("expected IPv4-only TTL target rule\nOutput:\n%s", ipt)
	}
}

func TestIntegration_Phase9_HLTargetIPv6Only(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-6 -A FORWARD -d 2001:db8::/32") {
		t.Errorf("expected IPv6-only HL target rule\nOutput:\n%s", ipt)
	}
	if !strings.Contains(ipt, "-j HL --hl-set 64") {
		t.Errorf("expected HL --hl-set 64\nOutput:\n%s", ipt)
	}
}

func TestIntegration_Phase9_SECMARK(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-j SECMARK --selctx system_u:object_r:https_t:s0") {
		t.Errorf("expected SECMARK --selctx\nOutput:\n%s", ipt)
	}
}

func TestIntegration_Phase9_CONNSECMARK(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-j CONNSECMARK --save") {
		t.Errorf("expected CONNSECMARK --save\nOutput:\n%s", ipt)
	}
}

func TestIntegration_Phase9_SYNPROXY(t *testing.T) {
	ipt, _ := buildOutput(t)
	want := "-j SYNPROXY --mss 1460 --wscale 7 --timestamp --sack-perm"
	if !strings.Contains(ipt, want) {
		t.Errorf("expected %q\nOutput:\n%s", want, ipt)
	}
}

func TestIntegration_Phase9_TEE(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-j TEE --gateway 10.10.10.2") {
		t.Errorf("expected TEE --gateway\nOutput:\n%s", ipt)
	}
}

func TestIntegration_Phase9_TRACE(t *testing.T) {
	ipt, _ := buildOutput(t)
	// TRACE is rendered in the raw table.
	if !strings.Contains(ipt, "-j TRACE") {
		t.Errorf("expected TRACE target\nOutput:\n%s", ipt)
	}
}

func TestIntegration_Phase9_AUDIT(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-j AUDIT --type accept") {
		t.Errorf("expected AUDIT --type accept\nOutput:\n%s", ipt)
	}
}

func TestIntegration_Phase9_CHECKSUM(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-j CHECKSUM --checksum-fill") {
		t.Errorf("expected CHECKSUM --checksum-fill\nOutput:\n%s", ipt)
	}
}

func TestIntegration_Phase9_NETMAP(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-j NETMAP --to 192.168.100.0/24") {
		t.Errorf("expected NETMAP --to\nOutput:\n%s", ipt)
	}
}

func TestIntegration_Phase9_CLUSTERIP(t *testing.T) {
	ipt, _ := buildOutput(t)
	want := "-j CLUSTERIP --new --hashmode sourceip --clustermac 01:00:5e:01:02:03 --total-nodes 4 --local-node 1 --hash-init 12345"
	if !strings.Contains(ipt, want) {
		t.Errorf("expected full CLUSTERIP rendering\nOutput:\n%s", ipt)
	}
}

func TestIntegration_Phase9_IDLETIMER(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-j IDLETIMER --timeout 600 --label metrics_idle") {
		t.Errorf("expected IDLETIMER full rendering\nOutput:\n%s", ipt)
	}
}

func TestIntegration_Phase9_RATEEST(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-j RATEEST --rateest-name eth0_tcp --rateest-interval 250ms --rateest-ewmalog 2s") {
		t.Errorf("expected RATEEST full rendering\nOutput:\n%s", ipt)
	}
}

func TestIntegration_Phase9_LED(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "-j LED --led-trigger-id http-activity --led-delay 200 --led-always-blink") {
		t.Errorf("expected LED full rendering\nOutput:\n%s", ipt)
	}
}

// === Phase 10 integration assertions ===

func TestIntegration_Phase10_SecurityTable(t *testing.T) {
	ipt, _ := buildOutput(t)
	if !strings.Contains(ipt, "*security") {
		t.Errorf("expected security table\nOutput:\n%s", ipt)
	}
	if !strings.Contains(ipt, "-A INPUT -p tcp --dport 443") {
		t.Errorf("expected security-table INPUT rule\nOutput:\n%s", ipt)
	}
	if !strings.Contains(ipt, "system_u:object_r:https_security_t:s0") {
		t.Errorf("expected security-table SECMARK context\nOutput:\n%s", ipt)
	}
}

func TestIntegration_Phase10_PacketModificationMatches(t *testing.T) {
	ipt, _ := buildOutput(t)
	for _, want := range []string{
		"-m dscp --dscp-class AF41",
		"-m tos --tos 0x10/0x3f",
		"-m ecn --ecn-tcp-ece --ecn-ip-ect 1",
	} {
		if !strings.Contains(ipt, want) {
			t.Errorf("expected %q\nOutput:\n%s", want, ipt)
		}
	}
}

func TestIntegration_Phase10_MetadataMatches(t *testing.T) {
	ipt, _ := buildOutput(t)
	for _, want := range []string{
		"-m helper --helper ftp",
		"-m realm --realm 0x10/0xff",
		"-m cluster --cluster-total-nodes 4 --cluster-local-node 2 --cluster-hash-seed 12345",
		"-m cpu --cpu 1",
		"-m devgroup --src-group 10/0xff --dst-group 20",
		"-m rpfilter --loose --validmark --accept-local",
		"-m quota --quota 1048576",
		"-m connbytes --connbytes 10:100 --connbytes-dir both --connbytes-mode bytes",
		"-m connlabel --label 10 --set",
		"-m nfacct --nfacct-name http",
	} {
		if !strings.Contains(ipt, want) {
			t.Errorf("expected %q\nOutput:\n%s", want, ipt)
		}
	}
}

func TestIntegration_Phase10_StructuredMatches(t *testing.T) {
	ipt, _ := buildOutput(t)
	for _, want := range []string{
		`-m string --algo bm --icase --string "BitTorrent"`,
		`-m bpf --bytecode "4,48 0 0 9,21 0 1 6,6 0 0 1,6 0 0 0"`,
		`-m u32 --u32 "0>>22&0x3C@12>>26&0x3F=0x10"`,
		"-m statistic --mode random --probability 0.5",
		"-m statistic --mode nth --every 3 --packet 0",
		"-m policy --dir in --pol ipsec --strict --proto esp --mode tunnel --tunnel-src 2001:db8::1 --tunnel-dst 2001:db8::2",
	} {
		if !strings.Contains(ipt, want) {
			t.Errorf("expected %q\nOutput:\n%s", want, ipt)
		}
	}
}

func TestIntegration_Phase10_IPv6ExtensionHeaderMatches(t *testing.T) {
	ipt, _ := buildOutput(t)
	for _, want := range []string{
		"-6 -A INPUT -m ipv6header --header hop,dst --soft",
		"-6 -A INPUT -m frag --fragid 1:10 --fragfirst",
		"-6 -A INPUT -m hbh --hbh-len 8 --hbh-opts 1:2",
		"-6 -A INPUT -m dst --dst-len 8 --dst-opts 1:2",
		"-6 -A INPUT -m rt --rt-type 0 --rt-segsleft 0:2 --rt-len 16 --rt-0-res --rt-0-addrs 2001:db8::1,2001:db8::2 --rt-0-not-strict",
		"-6 -A INPUT -m mh --mh-type binding-update",
	} {
		if !strings.Contains(ipt, want) {
			t.Errorf("expected %q\nOutput:\n%s", want, ipt)
		}
	}
}
