package ir

import (
	"strings"
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
			SetType:      "hash:net",
			Dimensions:   1,
			HasAddress:   true,
			IsMixed:      true,
			IPv4Elements: []string{"10.0.0.0/8"},
			IPv6Elements: []string{"fd00::/8"},
		},
		"v4only": {
			Name:         "v4only",
			Type:         "ipset",
			SetType:      "hash:net",
			Dimensions:   1,
			HasAddress:   true,
			Family:       "inet",
			IPv4Elements: []string{"192.168.0.0/16"},
		},
		"ipport": {
			Name:         "ipport",
			Type:         "ipset",
			SetType:      "hash:ip,port",
			Dimensions:   2,
			HasAddress:   true,
			Family:       "inet",
			IPv4Elements: []string{"10.0.0.1,tcp:22"},
		},
		"macs": {
			Name:         "macs",
			Type:         "ipset",
			SetType:      "hash:mac",
			Dimensions:   1,
			HasAddress:   false,
			Family:       "inet",
			IPv4Elements: []string{"02:00:00:00:00:01"},
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

func TestExpandRule_CTNotrackNormalizesToNOTRACK(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{
		Proto:   "udp",
		SPort:   53,
		Notrack: true,
		Jump:    "ct",
	}
	rules, err := expandRule("PREROUTING", rule, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Jump != "NOTRACK" {
		t.Errorf("expected Jump=NOTRACK for notrack:true, got %q", rules[0].Jump)
	}
}

func TestExpandRule_CTZoneHelper(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{
		Proto:  "tcp",
		DPort:  21,
		Zone:   5,
		Helper: "ftp",
		Jump:   "ct",
	}
	rules, err := expandRule("PREROUTING", rule, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Jump != "CT" {
		t.Errorf("expected Jump=CT, got %q", rules[0].Jump)
	}
	if rules[0].Zone != 5 {
		t.Errorf("expected Zone=5, got %d", rules[0].Zone)
	}
	if rules[0].Helper != "ftp" {
		t.Errorf("expected Helper=ftp, got %q", rules[0].Helper)
	}
}

func TestExpandRule_TCPMSSClamp(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{
		Proto:          "tcp",
		Jump:           "tcpmss",
		ClampMSSToPMTU: true,
	}
	rules, err := expandRule("FORWARD", rule, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Jump != "TCPMSS" {
		t.Errorf("expected Jump=TCPMSS, got %q", rules[0].Jump)
	}
	if !rules[0].ClampMSSToPMTU {
		t.Error("expected ClampMSSToPMTU=true")
	}
}

func TestExpandRule_TCPMSSSetMSS(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{
		Proto:  "tcp",
		Jump:   "tcpmss",
		SetMSS: 1400,
	}
	rules, err := expandRule("FORWARD", rule, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rules[0].SetMSS != 1400 {
		t.Errorf("expected SetMSS=1400, got %d", rules[0].SetMSS)
	}
}

func TestExpandRule_TCPFlags(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{
		Proto: "tcp",
		TCPFlags: &ast.TCPFlagsSpec{
			Mask: []string{"SYN", "ACK", "FIN", "RST"},
			Comp: []string{"SYN"},
		},
		Jump: "accept",
	}
	rules, err := expandRule("INPUT", rule, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rules[0].TCPFlagsMask != "SYN,ACK,FIN,RST" {
		t.Errorf("expected TCPFlagsMask=SYN,ACK,FIN,RST, got %q", rules[0].TCPFlagsMask)
	}
	if rules[0].TCPFlagsComp != "SYN" {
		t.Errorf("expected TCPFlagsComp=SYN, got %q", rules[0].TCPFlagsComp)
	}
}

func TestExpandRule_FragmentForcesIPv4(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{
		Fragment: true,
		Jump:     "drop",
	}
	rules, err := expandRule("INPUT", rule, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rules[0].Fragment {
		t.Error("expected Fragment=true")
	}
	if rules[0].IPVersion != 4 {
		t.Errorf("expected IPVersion=4 (fragment is IPv4-only), got %d", rules[0].IPVersion)
	}
}

func TestExpandRule_TCPOption(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{
		Proto:     "tcp",
		TCPOption: 7,
		Jump:      "drop",
	}
	rules, err := expandRule("INPUT", rule, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rules[0].TCPOption != 7 {
		t.Errorf("expected TCPOption=7, got %d", rules[0].TCPOption)
	}
}

func TestExpandRule_ConnmarkSaveMark(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{
		Jump:     "connmark",
		SaveMark: true,
		NfMask:   "0xff",
		CTMask:   "0xff",
	}
	rules, err := expandRule("POSTROUTING", rule, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Jump != "CONNMARK" {
		t.Errorf("expected Jump=CONNMARK, got %q", rules[0].Jump)
	}
	if !rules[0].SaveMark {
		t.Error("expected SaveMark=true")
	}
	if rules[0].NfMask != "0xff" {
		t.Errorf("expected NfMask=0xff, got %q", rules[0].NfMask)
	}
	if rules[0].CTMask != "0xff" {
		t.Errorf("expected CTMask=0xff, got %q", rules[0].CTMask)
	}
}

func TestExpandRule_ConnmarkSetMark(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{
		Jump:    "connmark",
		SetMark: "0x42",
	}
	rules, err := expandRule("POSTROUTING", rule, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rules[0].Jump != "CONNMARK" {
		t.Errorf("expected Jump=CONNMARK, got %q", rules[0].Jump)
	}
	if rules[0].SetMark != "0x42" {
		t.Errorf("expected SetMark=0x42, got %q", rules[0].SetMark)
	}
	if rules[0].SaveMark || rules[0].RestoreMark {
		t.Error("expected SaveMark/RestoreMark=false")
	}
}

func TestBuildMatchFragments_Connmark(t *testing.T) {
	mb := &ast.MatchBlock{
		Connmark: &ast.ConnmarkMatch{Mark: "0xff/0xff"},
	}
	frags, _, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(frags) != 1 {
		t.Fatalf("expected 1 fragment, got %d", len(frags))
	}
	if frags[0] != "-m connmark --mark 0xff/0xff" {
		t.Errorf("unexpected fragment: %q", frags[0])
	}
}

func intPtr(i int) *int { return &i }

func TestBuildMatchFragments_ConnlimitAbove(t *testing.T) {
	mb := &ast.MatchBlock{
		Connlimit: &ast.ConnlimitMatch{Above: intPtr(10), Mask: intPtr(32), SAddr: true},
	}
	frags, _, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(frags) != 1 {
		t.Fatalf("expected 1 fragment, got %d", len(frags))
	}
	want := "-m connlimit --connlimit-above 10 --connlimit-mask 32 --connlimit-saddr"
	if frags[0] != want {
		t.Errorf("fragment\n  got:  %q\n  want: %q", frags[0], want)
	}
}

func TestBuildMatchFragments_ConnlimitUptoDAddr(t *testing.T) {
	mb := &ast.MatchBlock{
		Connlimit: &ast.ConnlimitMatch{Upto: intPtr(5), DAddr: true},
	}
	frags, _, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "-m connlimit --connlimit-upto 5 --connlimit-daddr"
	if frags[0] != want {
		t.Errorf("fragment\n  got:  %q\n  want: %q", frags[0], want)
	}
}

func TestBuildMatchFragments_HashlimitFull(t *testing.T) {
	mb := &ast.MatchBlock{
		Hashlimit: &ast.HashlimitMatch{
			Name:             "ssh_rate",
			Upto:             "5/minute",
			Burst:            10,
			Mode:             []string{"srcip", "dstport"},
			SrcMask:          intPtr(32),
			HTableSize:       1024,
			HTableMax:        8192,
			HTableExpire:     60000,
			HTableGCInterval: 1000,
		},
	}
	frags, _, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(frags) != 1 {
		t.Fatalf("expected 1 fragment, got %d", len(frags))
	}
	want := "-m hashlimit --hashlimit-upto 5/minute --hashlimit-burst 10 --hashlimit-mode srcip,dstport --hashlimit-srcmask 32 --hashlimit-name ssh_rate --hashlimit-htable-size 1024 --hashlimit-htable-max 8192 --hashlimit-htable-expire 60000 --hashlimit-htable-gcinterval 1000"
	if frags[0] != want {
		t.Errorf("fragment\n  got:  %q\n  want: %q", frags[0], want)
	}
}

func TestBuildMatchFragments_HashlimitMinimal(t *testing.T) {
	mb := &ast.MatchBlock{
		Hashlimit: &ast.HashlimitMatch{
			Name: "r",
			Upto: "100/sec",
		},
	}
	frags, _, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "-m hashlimit --hashlimit-upto 100/sec --hashlimit-name r"
	if frags[0] != want {
		t.Errorf("fragment\n  got:  %q\n  want: %q", frags[0], want)
	}
}

func TestBuildMatchFragments_OwnerFull(t *testing.T) {
	mb := &ast.MatchBlock{
		Owner: &ast.OwnerMatch{
			UIDOwner:     intPtr(1000),
			GIDOwner:     intPtr(100),
			CmdOwner:     "sshd",
			SocketExists: true,
		},
	}
	frags, _, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "-m owner --uid-owner 1000 --gid-owner 100 --cmd-owner sshd --socket-exists"
	if frags[0] != want {
		t.Errorf("fragment\n  got:  %q\n  want: %q", frags[0], want)
	}
}

func TestBuildMatchFragments_IPRangeV4(t *testing.T) {
	mb := &ast.MatchBlock{
		IPRange: &ast.IPRangeMatch{SrcRange: "10.0.0.1-10.0.0.100"},
	}
	frags, ipv, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ipv != 4 {
		t.Errorf("expected IPv4 forcing, got ipv=%d", ipv)
	}
	want := "-m iprange --src-range 10.0.0.1-10.0.0.100"
	if frags[0] != want {
		t.Errorf("fragment\n  got:  %q\n  want: %q", frags[0], want)
	}
}

func TestBuildMatchFragments_IPRangeV6(t *testing.T) {
	mb := &ast.MatchBlock{
		IPRange: &ast.IPRangeMatch{DstRange: "fd00::1-fd00::ff"},
	}
	_, ipv, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ipv != 6 {
		t.Errorf("expected IPv6 forcing, got ipv=%d", ipv)
	}
}

func TestBuildMatchFragments_Length(t *testing.T) {
	mb := &ast.MatchBlock{
		Length: &ast.LengthMatch{Length: "64:1500"},
	}
	frags, _, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "-m length --length 64:1500"
	if frags[0] != want {
		t.Errorf("fragment\n  got:  %q\n  want: %q", frags[0], want)
	}
}

func TestBuildMatchFragments_TTLForcesIPv4(t *testing.T) {
	mb := &ast.MatchBlock{TTL: &ast.TTLMatch{Lt: intPtr(5)}}
	frags, ipv, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ipv != 4 {
		t.Errorf("expected ipv=4 for ttl, got %d", ipv)
	}
	if frags[0] != "-m ttl --ttl-lt 5" {
		t.Errorf("unexpected fragment: %q", frags[0])
	}
}

func TestBuildMatchFragments_HLForcesIPv6(t *testing.T) {
	mb := &ast.MatchBlock{HL: &ast.HLMatch{Eq: intPtr(64)}}
	frags, ipv, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ipv != 6 {
		t.Errorf("expected ipv=6 for hl, got %d", ipv)
	}
	if frags[0] != "-m hl --hl-eq 64" {
		t.Errorf("unexpected fragment: %q", frags[0])
	}
}

func TestBuildMatchFragments_PktTypeLowercased(t *testing.T) {
	mb := &ast.MatchBlock{PktType: &ast.PktTypeMatch{PktType: "BROADCAST"}}
	frags, _, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if frags[0] != "-m pkttype --pkt-type broadcast" {
		t.Errorf("unexpected fragment: %q", frags[0])
	}
}

func TestBuildMatchFragments_PhysDev(t *testing.T) {
	mb := &ast.MatchBlock{
		PhysDev: &ast.PhysDevMatch{
			PhysDevIn:        "eth0",
			PhysDevOut:       "eth1",
			PhysDevIsBridged: true,
		},
	}
	frags, _, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "-m physdev --physdev-in eth0 --physdev-out eth1 --physdev-is-bridged"
	if frags[0] != want {
		t.Errorf("fragment\n  got:  %q\n  want: %q", frags[0], want)
	}
}

// === Phase 6: NFLOG / NFQUEUE / SET targets ===

func TestExpandRule_NflogFieldsCopied(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{
		Jump:           "nflog",
		NflogGroup:     2,
		NflogPrefix:    "DROPPED: ",
		NflogRange:     256,
		NflogThreshold: 5,
	}
	rules, err := expandRule("INPUT", rule, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rules[0].Jump != "NFLOG" {
		t.Errorf("expected Jump=NFLOG, got %q", rules[0].Jump)
	}
	if rules[0].NflogGroup != 2 || rules[0].NflogPrefix != "DROPPED: " ||
		rules[0].NflogRange != 256 || rules[0].NflogThreshold != 5 {
		t.Errorf("nflog fields not copied: %+v", rules[0])
	}
}

func TestExpandRule_NfqueueNum(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{
		Jump:        "nfqueue",
		QueueNum:    0,
		QueueNumSet: true,
		QueueBypass: true,
	}
	rules, err := expandRule("FORWARD", rule, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rules[0].Jump != "NFQUEUE" {
		t.Errorf("expected Jump=NFQUEUE, got %q", rules[0].Jump)
	}
	if !rules[0].QueueNumSet || !rules[0].QueueBypass {
		t.Errorf("nfqueue fields not copied: %+v", rules[0])
	}
}

func TestExpandRule_NfqueueBalance(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{
		Jump:           "nfqueue",
		QueueBalance:   "0:3",
		QueueCPUFanout: true,
	}
	rules, err := expandRule("FORWARD", rule, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rules[0].QueueBalance != "0:3" || !rules[0].QueueCPUFanout {
		t.Errorf("queue-balance fields not copied: %+v", rules[0])
	}
}

func TestExpandRule_SETAddForcesIPv4(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{
		Jump:       "set",
		AddSet:     "v4only",
		SetFlags:   []string{"src"},
		SetExist:   true,
		SetTimeout: 3600,
	}
	rules, err := expandRule("INPUT", rule, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rules[0].Jump != "SET" {
		t.Errorf("expected Jump=SET, got %q", rules[0].Jump)
	}
	if rules[0].AddSet != "v4only" || rules[0].SetExist != true || rules[0].SetTimeout != 3600 {
		t.Errorf("SET fields not copied: %+v", rules[0])
	}
	if rules[0].IPVersion != 4 {
		t.Errorf("expected IPVersion=4 (v4-only ipset), got %d", rules[0].IPVersion)
	}
}

func TestExpandRule_SETDel(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{
		Jump:     "set",
		DelSet:   "v4only",
		SetFlags: []string{"src", "dst"},
	}
	rules, err := expandRule("INPUT", rule, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rules[0].DelSet != "v4only" || len(rules[0].SetFlags) != 2 {
		t.Errorf("SET del fields not copied: %+v", rules[0])
	}
}

// -----------------------------------------------------------------------------
// Phase 7 — richer ipset types and multi-dim match direction flags.
// -----------------------------------------------------------------------------

func TestExpandRule_MultiDimSetRefSrc(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{
		Src:  "$ipport[src,src]",
		Jump: "accept",
	}
	rules, err := expandRule("INPUT", rule, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Src != "ipport" {
		t.Errorf("expected Src=ipport, got %q", rules[0].Src)
	}
	if !rules[0].SrcIsSet {
		t.Error("expected SrcIsSet=true")
	}
	if rules[0].SrcSetDir != "src,src" {
		t.Errorf("expected SrcSetDir=\"src,src\", got %q", rules[0].SrcSetDir)
	}
	if rules[0].IPVersion != 4 {
		t.Errorf("expected IPVersion=4 from inet family, got %d", rules[0].IPVersion)
	}
}

func TestExpandRule_MultiDimSetRefDst(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{
		Dst:  "$ipport[dst,dst]",
		Jump: "accept",
	}
	rules, err := expandRule("INPUT", rule, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rules[0].DstSetDir != "dst,dst" {
		t.Errorf("expected DstSetDir=\"dst,dst\", got %q", rules[0].DstSetDir)
	}
}

func TestExpandRule_SetRefNoBracket(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{
		Src:  "$v4only",
		Jump: "accept",
	}
	rules, err := expandRule("INPUT", rule, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rules[0].SrcSetDir != "" {
		t.Errorf("expected empty SrcSetDir for single-dim default, got %q", rules[0].SrcSetDir)
	}
}

func TestExpandRule_NonAddressSet(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{
		Src:  "$macs[src]",
		Jump: "accept",
	}
	rules, err := expandRule("INPUT", rule, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Src != "macs" || !rules[0].SrcIsSet {
		t.Errorf("expected Src=macs with SrcIsSet=true, got %+v", rules[0])
	}
	if rules[0].IPVersion != 4 {
		t.Errorf("expected IPVersion=4 (family=inet), got %d", rules[0].IPVersion)
	}
}

func TestBuild_PropagatesSetTypeAndOptions(t *testing.T) {
	timeout := 3600
	resources := map[string]*sema.ResolvedResource{
		"withopts": {
			Name:         "withopts",
			Type:         "ipset",
			SetType:      "hash:ip,port",
			Dimensions:   2,
			HasAddress:   true,
			Family:       "inet",
			IPv4Elements: []string{"10.0.0.1,tcp:22"},
			SetOptions: &ast.SetOptions{
				Timeout:  &timeout,
				MaxElem:  8192,
				Counters: true,
			},
		},
	}
	resolved := &sema.Resolved{
		Doc:       &ast.Document{Chains: map[string]ast.Chain{}},
		Resources: resources,
	}
	prog, err := Build(resolved)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(prog.IPv4Ipsets) != 1 {
		t.Fatalf("expected 1 IPv4 ipset, got %d", len(prog.IPv4Ipsets))
	}
	got := prog.IPv4Ipsets[0]
	if got.SetType != "hash:ip,port" {
		t.Errorf("SetType = %q, want hash:ip,port", got.SetType)
	}
	if got.Options == nil || got.Options.MaxElem != 8192 || !got.Options.Counters {
		t.Errorf("Options not propagated: %+v", got.Options)
	}
	if got.Options.Timeout == nil || *got.Options.Timeout != 3600 {
		t.Errorf("Timeout pointer not propagated: %+v", got.Options)
	}
}

func TestBuild_NonAddressSetEmittedOnce(t *testing.T) {
	resources := map[string]*sema.ResolvedResource{
		"macs": {
			Name:         "macs",
			Type:         "ipset",
			SetType:      "hash:mac",
			Dimensions:   1,
			HasAddress:   false,
			Family:       "inet",
			IPv4Elements: []string{"02:00:00:00:00:01"},
		},
	}
	resolved := &sema.Resolved{
		Doc:       &ast.Document{Chains: map[string]ast.Chain{}},
		Resources: resources,
	}
	prog, err := Build(resolved)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(prog.IPv4Ipsets) != 1 || len(prog.IPv6Ipsets) != 0 {
		t.Fatalf("expected 1 IPv4 set and 0 IPv6 sets, got v4=%d v6=%d",
			len(prog.IPv4Ipsets), len(prog.IPv6Ipsets))
	}
	if prog.IPv4Ipsets[0].Name != "macs" || prog.IPv4Ipsets[0].SetType != "hash:mac" {
		t.Errorf("unexpected ipset: %+v", prog.IPv4Ipsets[0])
	}
}

// === Phase 8: extended match modules ===

func TestBuildMatchFragments_ConntrackExtended(t *testing.T) {
	mb := &ast.MatchBlock{
		Conntrack: &ast.ConntrackMatch{
			CTState:       []string{"NEW"},
			CTProto:       "tcp",
			CTOrigSrc:     "10.0.0.0/8",
			CTOrigDstPort: "80",
			CTStatus:      []string{"ASSURED", "CONFIRMED"},
			CTExpire:      "60:3600",
			CTDir:         "ORIGINAL",
		},
	}
	frags, ipv, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ipv != 4 {
		t.Errorf("expected ipv=4 from CTOrigSrc, got %d", ipv)
	}
	want := "-m conntrack --ctstate NEW --ctproto tcp --ctorigsrc 10.0.0.0/8 --ctorigdstport 80 --ctstatus ASSURED,CONFIRMED --ctexpire 60:3600 --ctdir ORIGINAL"
	if frags[0] != want {
		t.Errorf("fragment\n  got:  %q\n  want: %q", frags[0], want)
	}
}

func TestBuildMatchFragments_ConntrackV6FromReply(t *testing.T) {
	mb := &ast.MatchBlock{
		Conntrack: &ast.ConntrackMatch{CTReplDst: "fd00::1"},
	}
	_, ipv, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ipv != 6 {
		t.Errorf("expected ipv=6 from CTReplDst, got %d", ipv)
	}
}

func TestBuildMatchFragments_RecentRCheckMaskReap(t *testing.T) {
	mb := &ast.MatchBlock{
		Recent: &ast.RecentMatch{
			Name:    "SSH",
			RCheck:  true,
			Seconds: 60,
			Reap:    true,
			RDest:   true,
			Mask:    "255.255.255.0",
		},
	}
	frags, _, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "-m recent --name SSH --rcheck --seconds 60 --reap --rdest --mask 255.255.255.0"
	if frags[0] != want {
		t.Errorf("fragment\n  got:  %q\n  want: %q", frags[0], want)
	}
}

func TestBuildMatchFragments_RecentRemove(t *testing.T) {
	mb := &ast.MatchBlock{
		Recent: &ast.RecentMatch{Name: "SSH", Remove: true},
	}
	frags, _, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if frags[0] != "-m recent --name SSH --remove" {
		t.Errorf("unexpected fragment: %q", frags[0])
	}
}

func TestBuildMatchFragments_AddrTypeSrcAndLimitIface(t *testing.T) {
	mb := &ast.MatchBlock{
		AddrType: &ast.AddrTypeMatch{
			SrcType:      "LOCAL",
			DstType:      "UNICAST",
			LimitIfaceIn: true,
		},
	}
	frags, ipv, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ipv != 4 {
		t.Errorf("expected ipv=4 (addrtype), got %d", ipv)
	}
	want := "-m addrtype --src-type LOCAL --dst-type UNICAST --limit-iface-in"
	if frags[0] != want {
		t.Errorf("fragment\n  got:  %q\n  want: %q", frags[0], want)
	}
}

func TestBuildMatchFragments_TimeWithDateAndFlags(t *testing.T) {
	mb := &ast.MatchBlock{
		Time: &ast.TimeMatch{
			TimeStart:  "22:00",
			TimeStop:   "06:00",
			DateStart:  "2026-01-01T00:00:00",
			DateStop:   "2026-12-31T23:59:59",
			MonthDays:  "1,15,28",
			UTC:        true,
			Contiguous: true,
		},
	}
	frags, _, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "-m time --timestart 22:00 --timestop 06:00 --datestart 2026-01-01T00:00:00 --datestop 2026-12-31T23:59:59 --monthdays 1,15,28 --utc --contiguous"
	if frags[0] != want {
		t.Errorf("fragment\n  got:  %q\n  want: %q", frags[0], want)
	}
}

func TestBuildMatchFragments_SocketWithFlags(t *testing.T) {
	mb := &ast.MatchBlock{
		Socket: &ast.SocketMatch{
			Transparent:   true,
			NoWildcard:    true,
			RestoreSKMark: true,
		},
	}
	frags, _, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if frags[0] != "-m socket --transparent --nowildcard --restore-skmark" {
		t.Errorf("unexpected fragment: %q", frags[0])
	}
}

func TestBuildMatchFragments_SocketBareKeepsWorking(t *testing.T) {
	mb := &ast.MatchBlock{Socket: &ast.SocketMatch{}}
	frags, _, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if frags[0] != "-m socket" {
		t.Errorf("unexpected fragment: %q", frags[0])
	}
}

func TestBuildMatchFragments_MACNegation(t *testing.T) {
	mb := &ast.MatchBlock{
		MAC: &ast.MACMatch{MACSource: "aa:bb:cc:dd:ee:ff", Neg: true},
	}
	frags, _, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if frags[0] != "-m mac ! --mac-source aa:bb:cc:dd:ee:ff" {
		t.Errorf("unexpected fragment: %q", frags[0])
	}
}

func TestExpandRule_MultipleMatchBlocksCombine(t *testing.T) {
	rule := ast.Rule{
		Match: []*ast.MatchBlock{
			{Recent: &ast.RecentMatch{Name: "SSH", Set: true}},
			{Recent: &ast.RecentMatch{Name: "SSH", Update: true, Seconds: 60, HitCount: 10}},
		},
		Jump: "drop",
	}
	rules, err := expandRule("CHK", rule, nil)
	if err != nil {
		t.Fatalf("expandRule: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 expanded rule, got %d", len(rules))
	}
	frags := rules[0].MatchFragments
	if len(frags) != 2 {
		t.Fatalf("expected 2 match fragments, got %d: %v", len(frags), frags)
	}
	if frags[0] != "-m recent --name SSH --set" {
		t.Errorf("frag[0] = %q", frags[0])
	}
	if frags[1] != "-m recent --name SSH --update --seconds 60 --hitcount 10" {
		t.Errorf("frag[1] = %q", frags[1])
	}
}

// === Phase 9 — packet-modification targets ===

func TestExpandRule_TTLTargetForcesIPv4(t *testing.T) {
	resources := makeResources(t)
	ttl := 64
	rule := ast.Rule{Jump: "ttl", TTLSet: &ttl}
	rules, err := expandRule("FORWARD", rule, resources)
	if err != nil {
		t.Fatalf("expandRule: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].IPVersion != 4 {
		t.Errorf("TTL target must force IPv4, got IPVersion=%d", rules[0].IPVersion)
	}
	if rules[0].Jump != "TTL" {
		t.Errorf("Jump = %q, want TTL", rules[0].Jump)
	}
	if rules[0].TTLSet == nil || *rules[0].TTLSet != 64 {
		t.Errorf("TTLSet propagation wrong: %+v", rules[0].TTLSet)
	}
}

func TestExpandRule_HLTargetForcesIPv6(t *testing.T) {
	resources := makeResources(t)
	hl := 32
	rule := ast.Rule{Jump: "hl", HLDec: &hl}
	rules, err := expandRule("FORWARD", rule, resources)
	if err != nil {
		t.Fatalf("expandRule: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].IPVersion != 6 {
		t.Errorf("HL target must force IPv6, got IPVersion=%d", rules[0].IPVersion)
	}
	if rules[0].Jump != "HL" {
		t.Errorf("Jump = %q, want HL", rules[0].Jump)
	}
}

func TestExpandRule_ECNTargetForcesIPv4(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{Jump: "ecn", ECNTCPRemove: true}
	rules, err := expandRule("PREROUTING", rule, resources)
	if err != nil {
		t.Fatalf("expandRule: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].IPVersion != 4 {
		t.Errorf("ECN target must force IPv4, got IPVersion=%d", rules[0].IPVersion)
	}
	if rules[0].Jump != "ECN" {
		t.Errorf("Jump = %q, want ECN", rules[0].Jump)
	}
}

func TestExpandRule_NETMAPClassifiesFromCIDR(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{Jump: "netmap", NetmapTo: "192.168.100.0/24"}
	rules, err := expandRule("POSTROUTING", rule, resources)
	if err != nil {
		t.Fatalf("expandRule: %v", err)
	}
	if rules[0].IPVersion != 4 {
		t.Errorf("expected IPv4 from IPv4 CIDR, got %d", rules[0].IPVersion)
	}
	if rules[0].NetmapTo != "192.168.100.0/24" {
		t.Errorf("NetmapTo = %q", rules[0].NetmapTo)
	}
}

func TestExpandRule_TEEClassifiesFromGateway(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{Jump: "tee", Gateway: "2001:db8::2"}
	rules, err := expandRule("FORWARD", rule, resources)
	if err != nil {
		t.Fatalf("expandRule: %v", err)
	}
	if rules[0].IPVersion != 6 {
		t.Errorf("expected IPv6 from IPv6 gateway, got %d", rules[0].IPVersion)
	}
	if rules[0].Jump != "TEE" {
		t.Errorf("Jump = %q, want TEE", rules[0].Jump)
	}
}

func TestExpandRule_TOSPropagatesOne(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{Jump: "tos", SetTOS: "0x10"}
	rules, err := expandRule("FORWARD", rule, resources)
	if err != nil {
		t.Fatalf("expandRule: %v", err)
	}
	if rules[0].SetTOS != "0x10" {
		t.Errorf("SetTOS = %q", rules[0].SetTOS)
	}
	if rules[0].AndTOS != "" || rules[0].OrTOS != "" || rules[0].XorTOS != "" {
		t.Errorf("only set-tos should be populated, got +%v", rules[0])
	}
}

func TestExpandRule_CLASSIFYPropagates(t *testing.T) {
	resources := makeResources(t)
	rule := ast.Rule{Jump: "classify", SetClass: "1:10"}
	rules, err := expandRule("FORWARD", rule, resources)
	if err != nil {
		t.Fatalf("expandRule: %v", err)
	}
	if rules[0].Jump != "CLASSIFY" || rules[0].SetClass != "1:10" {
		t.Errorf("expected CLASSIFY 1:10, got jump=%q setclass=%q", rules[0].Jump, rules[0].SetClass)
	}
}

// ---------- Phase 10: match fragments ----------

func TestBuildMatchFragments_DSCPValue(t *testing.T) {
	mb := &ast.MatchBlock{DSCP: &ast.DSCPMatch{DSCP: 46}}
	frags, _, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("buildMatchFragments: %v", err)
	}
	if frags[0] != "-m dscp --dscp 46" {
		t.Errorf("got: %q", frags[0])
	}
}

func TestBuildMatchFragments_DSCPClass(t *testing.T) {
	mb := &ast.MatchBlock{DSCP: &ast.DSCPMatch{DSCPClass: "EF"}}
	frags, _, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("buildMatchFragments: %v", err)
	}
	if frags[0] != "-m dscp --dscp-class EF" {
		t.Errorf("got: %q", frags[0])
	}
}

func TestBuildMatchFragments_TOS(t *testing.T) {
	mb := &ast.MatchBlock{TOS: &ast.TOSMatch{TOS: "0x10/0xff"}}
	frags, _, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("buildMatchFragments: %v", err)
	}
	if frags[0] != "-m tos --tos 0x10/0xff" {
		t.Errorf("got: %q", frags[0])
	}
}

func TestBuildMatchFragments_ECN(t *testing.T) {
	ect := 2
	mb := &ast.MatchBlock{ECN: &ast.ECNMatch{TCPCWR: true, IPECT: &ect}}
	frags, _, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("buildMatchFragments: %v", err)
	}
	if frags[0] != "-m ecn --ecn-tcp-cwr --ecn-ip-ect 2" {
		t.Errorf("got: %q", frags[0])
	}
}

func TestBuildMatchFragments_Helper(t *testing.T) {
	mb := &ast.MatchBlock{Helper: &ast.HelperMatch{Name: "ftp"}}
	frags, _, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("buildMatchFragments: %v", err)
	}
	if frags[0] != "-m helper --helper ftp" {
		t.Errorf("got: %q", frags[0])
	}
}

func TestBuildMatchFragments_Realm(t *testing.T) {
	mb := &ast.MatchBlock{Realm: &ast.RealmMatch{Realm: "0x10/0xff"}}
	frags, ipv, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("buildMatchFragments: %v", err)
	}
	if frags[0] != "-m realm --realm 0x10/0xff" {
		t.Errorf("got: %q", frags[0])
	}
	if ipv != 4 {
		t.Fatalf("expected realm to force ipv=4, got %d", ipv)
	}
}

func TestBuildMatchFragments_Cluster(t *testing.T) {
	mb := &ast.MatchBlock{Cluster: &ast.ClusterMatch{TotalNodes: 4, LocalNode: 2, HashSeed: 0xdeadbeef}}
	frags, _, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("buildMatchFragments: %v", err)
	}
	if !strings.Contains(frags[0], "--cluster-total-nodes 4") ||
		!strings.Contains(frags[0], "--cluster-local-node 2") {
		t.Errorf("got: %q", frags[0])
	}
}

func TestBuildMatchFragments_CPU(t *testing.T) {
	mb := &ast.MatchBlock{CPU: &ast.CPUMatch{CPU: 3}}
	frags, _, _ := buildMatchFragments(mb)
	if frags[0] != "-m cpu --cpu 3" {
		t.Errorf("got: %q", frags[0])
	}
}

func TestBuildMatchFragments_Quota(t *testing.T) {
	mb := &ast.MatchBlock{Quota: &ast.QuotaMatch{Quota: 1000000}}
	frags, _, _ := buildMatchFragments(mb)
	if frags[0] != "-m quota --quota 1000000" {
		t.Errorf("got: %q", frags[0])
	}
}

func TestBuildMatchFragments_ConnBytes(t *testing.T) {
	mb := &ast.MatchBlock{ConnBytes: &ast.ConnBytesMatch{Connbytes: "10:100", ConnbytesDir: "both", Mode: "bytes"}}
	frags, _, _ := buildMatchFragments(mb)
	if frags[0] != "-m connbytes --connbytes 10:100 --connbytes-dir both --connbytes-mode bytes" {
		t.Errorf("got: %q", frags[0])
	}
}

func TestBuildMatchFragments_Nfacct(t *testing.T) {
	mb := &ast.MatchBlock{Nfacct: &ast.NfacctMatch{Name: "http"}}
	frags, _, _ := buildMatchFragments(mb)
	if frags[0] != "-m nfacct --nfacct-name http" {
		t.Errorf("got: %q", frags[0])
	}
}

func TestBuildMatchFragments_String(t *testing.T) {
	mb := &ast.MatchBlock{String: &ast.StringMatch{Algo: "bm", String: "BitTorrent"}}
	frags, _, _ := buildMatchFragments(mb)
	want := `-m string --algo bm --string "BitTorrent"`
	if frags[0] != want {
		t.Errorf("got: %q, want: %q", frags[0], want)
	}
}

func TestBuildMatchFragments_U32(t *testing.T) {
	mb := &ast.MatchBlock{U32: &ast.U32Match{U32: "0>>22&0x3C@ 4>>16=0x1234"}}
	frags, _, _ := buildMatchFragments(mb)
	if !strings.Contains(frags[0], `-m u32 --u32 "0>>22`) {
		t.Errorf("got: %q", frags[0])
	}
}

func TestBuildMatchFragments_StatisticRandom(t *testing.T) {
	mb := &ast.MatchBlock{Statistic: &ast.StatisticMatch{Mode: "random", Probability: 0.5}}
	frags, _, _ := buildMatchFragments(mb)
	if frags[0] != "-m statistic --mode random --probability 0.5" {
		t.Errorf("got: %q", frags[0])
	}
}

func TestBuildMatchFragments_StatisticNth(t *testing.T) {
	pkt := 0
	mb := &ast.MatchBlock{Statistic: &ast.StatisticMatch{Mode: "nth", Every: 3, Packet: &pkt}}
	frags, _, _ := buildMatchFragments(mb)
	if frags[0] != "-m statistic --mode nth --every 3 --packet 0" {
		t.Errorf("got: %q", frags[0])
	}
}

func TestBuildMatchFragments_Policy(t *testing.T) {
	mb := &ast.MatchBlock{Policy: &ast.PolicyMatch{
		Dir: "in", Policy: "ipsec", Strict: true,
		Elements: []ast.PolicyElement{{Proto: "esp", Mode: "tunnel"}, {ReqID: 7}},
	}}
	frags, _, _ := buildMatchFragments(mb)
	if !strings.Contains(frags[0], "--dir in --pol ipsec --strict") ||
		!strings.Contains(frags[0], "--proto esp --mode tunnel") ||
		!strings.Contains(frags[0], "--next --reqid 7") {
		t.Errorf("got: %q", frags[0])
	}
}

func TestBuildMatchFragments_PolicyTunnelForcesIPv6(t *testing.T) {
	mb := &ast.MatchBlock{Policy: &ast.PolicyMatch{
		Dir: "in", Policy: "ipsec",
		Elements: []ast.PolicyElement{{
			Proto:     "esp",
			Mode:      "tunnel",
			TunnelSrc: "2001:db8::1",
			TunnelDst: "2001:db8::2",
		}},
	}}
	_, ipv, err := buildMatchFragments(mb)
	if err != nil {
		t.Fatalf("buildMatchFragments: %v", err)
	}
	if ipv != 6 {
		t.Fatalf("expected IPv6 policy tunnel to force ipv=6, got %d", ipv)
	}
}

func TestBuildMatchFragments_IPv6HeaderForcesV6(t *testing.T) {
	mb := &ast.MatchBlock{IPv6Header: &ast.IPv6HeaderMatch{Header: []string{"frag", "esp"}, Soft: true}}
	frags, ipv, _ := buildMatchFragments(mb)
	if ipv != 6 {
		t.Errorf("expected ipv=6, got %d", ipv)
	}
	if !strings.Contains(frags[0], "--header frag,esp") || !strings.Contains(frags[0], "--soft") {
		t.Errorf("got: %q", frags[0])
	}
}

func TestBuildMatchFragments_FragForcesV6(t *testing.T) {
	mb := &ast.MatchBlock{Frag: &ast.FragMatch{ID: "10:100", First: true}}
	_, ipv, _ := buildMatchFragments(mb)
	if ipv != 6 {
		t.Errorf("expected ipv=6, got %d", ipv)
	}
}

func TestBuildMatchFragments_MHForcesV6(t *testing.T) {
	mb := &ast.MatchBlock{MH: &ast.MHMatch{Type: "binding-update"}}
	frags, ipv, _ := buildMatchFragments(mb)
	if ipv != 6 {
		t.Errorf("expected ipv=6, got %d", ipv)
	}
	if frags[0] != "-m mh --mh-type binding-update" {
		t.Errorf("got: %q", frags[0])
	}
}

// ---------- Phase 10: security table ----------

func TestBuild_SecurityTable(t *testing.T) {
	doc := &ast.Document{
		Chains: map[string]ast.Chain{
			"INPUT": {
				Security: []ast.Rule{{Jump: "secmark", SelCtx: "system_u:object_r:http_t:s0"}},
			},
		},
	}
	resolved, err := sema.Analyze(doc)
	if err != nil {
		t.Fatalf("sema: %v", err)
	}
	prog, err := Build(resolved)
	if err != nil {
		t.Fatalf("ir.Build: %v", err)
	}
	t2, ok := prog.Tables["security"]
	if !ok {
		t.Fatal("security table missing from program")
	}
	// INPUT must be listed as a built-in.
	found := false
	for _, c := range t2.Chains {
		if c.Name == "INPUT" {
			found = true
			if !c.BuiltIn {
				t.Errorf("INPUT should be BuiltIn in security table")
			}
			if len(c.IRRules) != 1 || c.IRRules[0].Jump != "SECMARK" {
				t.Errorf("expected SECMARK rule, got: %+v", c.IRRules)
			}
		}
	}
	if !found {
		t.Error("INPUT chain missing from security table")
	}
}
