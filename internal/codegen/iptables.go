package codegen

import (
	"fmt"
	"strings"

	"github.com/appe233/yipt/internal/ir"
)

// tableOrder defines which tables to emit and in what order.
// raw runs first in the packet flow, then filter/nat/mangle, with security
// at the end (MAC rules are checked just before the final ACCEPT verdict).
var tableOrder = []string{"raw", "filter", "nat", "mangle", "security"}

// RenderIptablesRestore renders the iptables-restore compatible output.
func RenderIptablesRestore(prog *ir.Program) string {
	return renderIptablesRestoreInternal(prog, 0, true)
}

// RenderIptablesRestoreIPv4 renders only IPv4 rules without version prefix.
func RenderIptablesRestoreIPv4(prog *ir.Program) string {
	return renderIptablesRestoreInternal(prog, 4, false)
}

// RenderIptablesRestoreIPv6 renders only IPv6 rules without version prefix.
func RenderIptablesRestoreIPv6(prog *ir.Program) string {
	return renderIptablesRestoreInternal(prog, 6, false)
}

// filterRulesByVersion filters rules by IP version.
// version=0 means all rules, version=4 or 6 includes rules with that version or IPVersion=0.
func filterRulesByVersion(rules []*ir.IRRule, version int) []*ir.IRRule {
	if version == 0 {
		return rules
	}
	var filtered []*ir.IRRule
	for _, r := range rules {
		if r.IPVersion == 0 || r.IPVersion == version {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// renderIptablesRestoreInternal renders iptables-restore output with optional filtering.
// version=0 means all rules, version=4 or 6 filters to that IP version.
// includeVersionPrefix controls whether -4/-6 prefixes are included.
func renderIptablesRestoreInternal(prog *ir.Program, version int, includeVersionPrefix bool) string {
	var sb strings.Builder

	for _, tableName := range tableOrder {
		t, ok := prog.Tables[tableName]
		if !ok {
			continue
		}

		// Filter chains to only those with rules matching the version.
		var chainsWithRules []*ir.Chain
		for _, chain := range t.Chains {
			filtered := filterRulesByVersion(chain.IRRules, version)
			if len(filtered) > 0 || chain.BuiltIn {
				chainsWithRules = append(chainsWithRules, chain)
			}
		}

		if len(chainsWithRules) == 0 {
			continue
		}

		sb.WriteString("*")
		sb.WriteString(tableName)
		sb.WriteString("\n")

		// Policy lines for built-in chains.
		for _, chain := range chainsWithRules {
			if chain.BuiltIn {
				policy := chain.Policy
				if policy == "" {
					policy = "ACCEPT"
				}
				sb.WriteString(fmt.Sprintf(":%s %s [0:0]\n", chain.Name, policy))
			}
		}

		// -N declarations for user-defined chains.
		for _, chain := range chainsWithRules {
			if !chain.BuiltIn {
				sb.WriteString(fmt.Sprintf("-N %s\n", chain.Name))
			}
		}

		// Rules.
		for _, chain := range chainsWithRules {
			filtered := filterRulesByVersion(chain.IRRules, version)
			for _, rule := range filtered {
				for _, line := range renderRulesWithPrefix(rule, includeVersionPrefix) {
					sb.WriteString(line)
					sb.WriteString("\n")
				}
			}
		}

		sb.WriteString("COMMIT\n")
	}

	return sb.String()
}

// multiportLimit is the maximum number of port slots allowed per multiport rule.
const multiportLimit = 15

// multiportCost returns how many "slots" a port entry uses.
// A range like "1024:65535" costs 2; a single port costs 1.
func multiportCost(entry string) int {
	if strings.Contains(entry, ":") {
		return 2
	}
	return 1
}

// splitMultiportEntries splits a comma-separated port string into chunks,
// each fitting within the iptables 15-port multiport limit.
func splitMultiportEntries(ports string) []string {
	entries := strings.Split(ports, ",")
	var chunks []string
	var current []string
	cost := 0

	for _, e := range entries {
		c := multiportCost(e)
		if len(current) > 0 && cost+c > multiportLimit {
			chunks = append(chunks, strings.Join(current, ","))
			current = current[:0]
			cost = 0
		}
		current = append(current, e)
		cost += c
	}
	if len(current) > 0 {
		chunks = append(chunks, strings.Join(current, ","))
	}
	return chunks
}

// renderRules renders an IR rule into one or more iptables-restore lines.
// Multiple lines are produced when multiport entries exceed the 15-port limit.
func renderRules(r *ir.IRRule) []string {
	return renderRulesWithPrefix(r, true)
}

// renderRulesWithPrefix renders an IR rule with optional version prefix.
func renderRulesWithPrefix(r *ir.IRRule, includeVersionPrefix bool) []string {
	// Determine sport/dport chunks for splitting.
	sportChunks := []string{""}
	dportChunks := []string{""}
	if r.SPort != "" && r.SPortMulti {
		sportChunks = splitMultiportEntries(r.SPort)
	}
	if r.DPort != "" && r.DPortMulti {
		dportChunks = splitMultiportEntries(r.DPort)
	}

	var lines []string
	for _, sp := range sportChunks {
		for _, dp := range dportChunks {
			lines = append(lines, renderRuleLine(r, sp, dp, includeVersionPrefix))
		}
	}
	return lines
}

// renderRuleLine renders a single iptables-restore line with the given
// sport/dport chunks. Empty string means use the original non-multi value.
// If includeVersionPrefix is false, the -4/-6 prefix is omitted.
func renderRuleLine(r *ir.IRRule, sportOverride, dportOverride string, includeVersionPrefix bool) string {
	var parts []string

	// IP version prefix.
	if includeVersionPrefix {
		switch r.IPVersion {
		case 4:
			parts = append(parts, "-4")
		case 6:
			parts = append(parts, "-6")
		}
	}

	// Chain.
	parts = append(parts, "-A", r.Chain)

	// Interface matches.
	if r.In != "" {
		if r.InNeg {
			parts = append(parts, "!", "-i", r.In)
		} else {
			parts = append(parts, "-i", r.In)
		}
	}
	if r.Out != "" {
		if r.OutNeg {
			parts = append(parts, "!", "-o", r.Out)
		} else {
			parts = append(parts, "-o", r.Out)
		}
	}

	// Source address / set.
	if r.Src != "" {
		if r.SrcIsSet {
			dir := r.SrcSetDir
			if dir == "" {
				dir = "src"
			}
			if r.SrcNeg {
				parts = append(parts, "-m", "set", "!", "--match-set", r.Src, dir)
			} else {
				parts = append(parts, "-m", "set", "--match-set", r.Src, dir)
			}
		} else {
			if r.SrcNeg {
				parts = append(parts, "!", "-s", r.Src)
			} else {
				parts = append(parts, "-s", r.Src)
			}
		}
	}

	// Destination address / set.
	if r.Dst != "" {
		if r.DstIsSet {
			dir := r.DstSetDir
			if dir == "" {
				dir = "dst"
			}
			if r.DstNeg {
				parts = append(parts, "-m", "set", "!", "--match-set", r.Dst, dir)
			} else {
				parts = append(parts, "-m", "set", "--match-set", r.Dst, dir)
			}
		} else {
			if r.DstNeg {
				parts = append(parts, "!", "-d", r.Dst)
			} else {
				parts = append(parts, "-d", r.Dst)
			}
		}
	}

	// Protocol.
	if r.Proto != "" {
		parts = append(parts, "-p", r.Proto)
	}

	// Source port.
	if r.SPort != "" {
		if r.SPortMulti {
			parts = append(parts, "-m", "multiport")
			if r.SPortNeg {
				parts = append(parts, "!", "--sports", sportOverride)
			} else {
				parts = append(parts, "--sports", sportOverride)
			}
		} else {
			if r.SPortNeg {
				parts = append(parts, "!", "--sport", r.SPort)
			} else {
				parts = append(parts, "--sport", r.SPort)
			}
		}
	}

	// Destination port.
	if r.DPort != "" {
		if r.DPortMulti {
			parts = append(parts, "-m", "multiport")
			if r.DPortNeg {
				parts = append(parts, "!", "--dports", dportOverride)
			} else {
				parts = append(parts, "--dports", dportOverride)
			}
		} else {
			if r.DPortNeg {
				parts = append(parts, "!", "--dport", r.DPort)
			} else {
				parts = append(parts, "--dport", r.DPort)
			}
		}
	}

	// SYN flag.
	if r.Syn {
		parts = append(parts, "--syn")
	}

	// TCP flags match.
	if r.TCPFlagsMask != "" {
		parts = append(parts, "--tcp-flags", r.TCPFlagsMask, r.TCPFlagsComp)
	}

	// TCP option match.
	if r.TCPOption != 0 {
		parts = append(parts, "--tcp-option", fmt.Sprintf("%d", r.TCPOption))
	}

	// IPv4 fragment match.
	if r.Fragment {
		parts = append(parts, "-f")
	}

	// ICMP type.
	if r.ICMPType != "" {
		parts = append(parts, "--icmp-type", r.ICMPType)
	}

	// ICMPv6 type.
	if r.ICMPv6Type != "" {
		parts = append(parts, "--icmpv6-type", r.ICMPv6Type)
	}

	// Match fragments (conntrack, recent, limit, mark, socket, addrtype).
	for _, frag := range r.MatchFragments {
		parts = append(parts, frag)
	}

	// Comment.
	if r.Comment != "" {
		parts = append(parts, "-m", "comment", "--comment", `"`+r.Comment+`"`)
	}

	// Jump target.
	switch r.Jump {
	case "":
		// No -j
	case "REJECT":
		if r.RejectWith != "" {
			parts = append(parts, "-j", "REJECT", "--reject-with", r.RejectWith)
		} else {
			parts = append(parts, "-j", "REJECT")
		}
	case "LOG":
		if r.LogPrefix != "" {
			parts = append(parts, "-j", "LOG", "--log-prefix", `"`+r.LogPrefix+`"`)
		} else {
			parts = append(parts, "-j", "LOG")
		}
	case "MARK":
		parts = append(parts, "-j", "MARK", "--set-mark", r.SetMark)
	case "MASQUERADE":
		if r.ToPorts != "" {
			parts = append(parts, "-j", "MASQUERADE", "--to-ports", r.ToPorts)
		} else {
			parts = append(parts, "-j", "MASQUERADE")
		}
	case "SNAT":
		args := []string{"-j", "SNAT"}
		if r.ToSource != "" {
			args = append(args, "--to-source", r.ToSource)
		}
		if r.ToPorts != "" {
			args = append(args, "--to-ports", r.ToPorts)
		}
		parts = append(parts, args...)
	case "DNAT":
		args := []string{"-j", "DNAT"}
		if r.ToDest != "" {
			args = append(args, "--to-destination", r.ToDest)
		}
		if r.ToPorts != "" {
			args = append(args, "--to-ports", r.ToPorts)
		}
		parts = append(parts, args...)
	case "REDIRECT":
		if r.ToPorts != "" {
			parts = append(parts, "-j", "REDIRECT", "--to-ports", r.ToPorts)
		} else {
			parts = append(parts, "-j", "REDIRECT")
		}
	case "TPROXY":
		tArgs := []string{"-j", "TPROXY"}
		if r.OnIP != "" {
			tArgs = append(tArgs, "--on-ip", r.OnIP)
		}
		if r.OnPort != 0 {
			tArgs = append(tArgs, "--on-port", fmt.Sprintf("%d", r.OnPort))
		}
		if r.TProxyMark != "" {
			tArgs = append(tArgs, "--tproxy-mark", r.TProxyMark)
		}
		parts = append(parts, tArgs...)
	case "CT":
		ctArgs := []string{"-j", "CT"}
		if r.Zone != 0 {
			ctArgs = append(ctArgs, "--zone", fmt.Sprintf("%d", r.Zone))
		}
		if r.Helper != "" {
			ctArgs = append(ctArgs, "--helper", r.Helper)
		}
		if len(r.CTEvents) > 0 {
			ctArgs = append(ctArgs, "--ctevents", strings.Join(r.CTEvents, ","))
		}
		if r.CTMask != "" {
			ctArgs = append(ctArgs, "--ctmask", r.CTMask)
		}
		if r.NfMask != "" {
			ctArgs = append(ctArgs, "--nfmask", r.NfMask)
		}
		parts = append(parts, ctArgs...)
	case "NOTRACK":
		parts = append(parts, "-j", "NOTRACK")
	case "TCPMSS":
		tArgs := []string{"-j", "TCPMSS"}
		if r.SetMSS > 0 {
			tArgs = append(tArgs, "--set-mss", fmt.Sprintf("%d", r.SetMSS))
		} else if r.ClampMSSToPMTU {
			tArgs = append(tArgs, "--clamp-mss-to-pmtu")
		}
		parts = append(parts, tArgs...)
	case "CONNMARK":
		cArgs := []string{"-j", "CONNMARK"}
		switch {
		case r.SaveMark:
			cArgs = append(cArgs, "--save-mark")
		case r.RestoreMark:
			cArgs = append(cArgs, "--restore-mark")
		case r.SetMark != "":
			cArgs = append(cArgs, "--set-mark", r.SetMark)
		}
		if r.NfMask != "" {
			cArgs = append(cArgs, "--nfmask", r.NfMask)
		}
		if r.CTMask != "" {
			cArgs = append(cArgs, "--ctmask", r.CTMask)
		}
		parts = append(parts, cArgs...)
	case "NFLOG":
		nArgs := []string{"-j", "NFLOG"}
		if r.NflogGroup != 0 {
			nArgs = append(nArgs, "--nflog-group", fmt.Sprintf("%d", r.NflogGroup))
		}
		if r.NflogPrefix != "" {
			nArgs = append(nArgs, "--nflog-prefix", `"`+r.NflogPrefix+`"`)
		}
		if r.NflogRange != 0 {
			nArgs = append(nArgs, "--nflog-range", fmt.Sprintf("%d", r.NflogRange))
		}
		if r.NflogThreshold != 0 {
			nArgs = append(nArgs, "--nflog-threshold", fmt.Sprintf("%d", r.NflogThreshold))
		}
		parts = append(parts, nArgs...)
	case "NFQUEUE":
		qArgs := []string{"-j", "NFQUEUE"}
		switch {
		case r.QueueBalance != "":
			qArgs = append(qArgs, "--queue-balance", r.QueueBalance)
		case r.QueueNumSet:
			qArgs = append(qArgs, "--queue-num", fmt.Sprintf("%d", r.QueueNum))
		}
		if r.QueueBypass {
			qArgs = append(qArgs, "--queue-bypass")
		}
		if r.QueueCPUFanout {
			qArgs = append(qArgs, "--queue-cpu-fanout")
		}
		parts = append(parts, qArgs...)
	case "SET":
		sArgs := []string{"-j", "SET"}
		if r.AddSet != "" {
			sArgs = append(sArgs, "--add-set", r.AddSet, strings.Join(r.SetFlags, ","))
		} else if r.DelSet != "" {
			sArgs = append(sArgs, "--del-set", r.DelSet, strings.Join(r.SetFlags, ","))
		}
		if r.SetExist {
			sArgs = append(sArgs, "--exist")
		}
		if r.SetTimeout != 0 {
			sArgs = append(sArgs, "--timeout", fmt.Sprintf("%d", r.SetTimeout))
		}
		parts = append(parts, sArgs...)
	case "CLASSIFY":
		parts = append(parts, "-j", "CLASSIFY", "--set-class", r.SetClass)
	case "DSCP":
		if r.SetDSCP != "" {
			parts = append(parts, "-j", "DSCP", "--set-dscp", r.SetDSCP)
		} else {
			parts = append(parts, "-j", "DSCP", "--set-dscp-class", strings.ToUpper(r.SetDSCPClass))
		}
	case "TOS":
		tArgs := []string{"-j", "TOS"}
		switch {
		case r.SetTOS != "":
			tArgs = append(tArgs, "--set-tos", r.SetTOS)
		case r.AndTOS != "":
			tArgs = append(tArgs, "--and-tos", r.AndTOS)
		case r.OrTOS != "":
			tArgs = append(tArgs, "--or-tos", r.OrTOS)
		case r.XorTOS != "":
			tArgs = append(tArgs, "--xor-tos", r.XorTOS)
		}
		parts = append(parts, tArgs...)
	case "ECN":
		parts = append(parts, "-j", "ECN")
		if r.ECNTCPRemove {
			parts = append(parts, "--ecn-tcp-remove")
		}
	case "TTL":
		tArgs := []string{"-j", "TTL"}
		switch {
		case r.TTLSet != nil:
			tArgs = append(tArgs, "--ttl-set", fmt.Sprintf("%d", *r.TTLSet))
		case r.TTLDec != nil:
			tArgs = append(tArgs, "--ttl-dec", fmt.Sprintf("%d", *r.TTLDec))
		case r.TTLInc != nil:
			tArgs = append(tArgs, "--ttl-inc", fmt.Sprintf("%d", *r.TTLInc))
		}
		parts = append(parts, tArgs...)
	case "HL":
		tArgs := []string{"-j", "HL"}
		switch {
		case r.HLSet != nil:
			tArgs = append(tArgs, "--hl-set", fmt.Sprintf("%d", *r.HLSet))
		case r.HLDec != nil:
			tArgs = append(tArgs, "--hl-dec", fmt.Sprintf("%d", *r.HLDec))
		case r.HLInc != nil:
			tArgs = append(tArgs, "--hl-inc", fmt.Sprintf("%d", *r.HLInc))
		}
		parts = append(parts, tArgs...)
	case "SECMARK":
		parts = append(parts, "-j", "SECMARK", "--selctx", r.SelCtx)
	case "CONNSECMARK":
		cArgs := []string{"-j", "CONNSECMARK"}
		switch {
		case r.ConnSecMarkSave:
			cArgs = append(cArgs, "--save")
		case r.ConnSecMarkRestore:
			cArgs = append(cArgs, "--restore")
		}
		parts = append(parts, cArgs...)
	case "SYNPROXY":
		sArgs := []string{"-j", "SYNPROXY"}
		if r.SynproxyMSS != 0 {
			sArgs = append(sArgs, "--mss", fmt.Sprintf("%d", r.SynproxyMSS))
		}
		if r.SynproxyWScale != 0 {
			sArgs = append(sArgs, "--wscale", fmt.Sprintf("%d", r.SynproxyWScale))
		}
		if r.SynproxyTimestamp {
			sArgs = append(sArgs, "--timestamp")
		}
		if r.SynproxySAckPerm {
			sArgs = append(sArgs, "--sack-perm")
		}
		parts = append(parts, sArgs...)
	case "TEE":
		parts = append(parts, "-j", "TEE", "--gateway", r.Gateway)
	case "TRACE":
		parts = append(parts, "-j", "TRACE")
	case "AUDIT":
		parts = append(parts, "-j", "AUDIT", "--type", r.AuditType)
	case "CHECKSUM":
		parts = append(parts, "-j", "CHECKSUM")
		if r.ChecksumFill {
			parts = append(parts, "--checksum-fill")
		}
	case "NETMAP":
		parts = append(parts, "-j", "NETMAP", "--to", r.NetmapTo)
	case "CLUSTERIP":
		cArgs := []string{"-j", "CLUSTERIP"}
		if r.ClusterIPNew {
			cArgs = append(cArgs, "--new")
		}
		if r.ClusterIPHashmode != "" {
			cArgs = append(cArgs, "--hashmode", r.ClusterIPHashmode)
		}
		if r.ClusterIPClusterMAC != "" {
			cArgs = append(cArgs, "--clustermac", r.ClusterIPClusterMAC)
		}
		if r.ClusterIPTotalNodes != 0 {
			cArgs = append(cArgs, "--total-nodes", fmt.Sprintf("%d", r.ClusterIPTotalNodes))
		}
		if r.ClusterIPLocalNode != 0 {
			cArgs = append(cArgs, "--local-node", fmt.Sprintf("%d", r.ClusterIPLocalNode))
		}
		if r.ClusterIPHashInit != 0 {
			cArgs = append(cArgs, "--hash-init", fmt.Sprintf("%d", r.ClusterIPHashInit))
		}
		parts = append(parts, cArgs...)
	case "IDLETIMER":
		iArgs := []string{"-j", "IDLETIMER", "--timeout", fmt.Sprintf("%d", r.IdletimerTimeout), "--label", r.IdletimerLabel}
		if r.IdletimerAlarm {
			iArgs = append(iArgs, "--alarm")
		}
		parts = append(parts, iArgs...)
	case "RATEEST":
		rArgs := []string{"-j", "RATEEST", "--rateest-name", r.RateestName}
		if r.RateestInterval != 0 {
			rArgs = append(rArgs, "--rateest-interval", fmt.Sprintf("%d", r.RateestInterval))
		}
		if r.RateestEwmalog != 0 {
			rArgs = append(rArgs, "--rateest-ewmalog", fmt.Sprintf("%d", r.RateestEwmalog))
		}
		parts = append(parts, rArgs...)
	case "LED":
		lArgs := []string{"-j", "LED", "--led-trigger-id", r.LEDTriggerID}
		if r.LEDDelaySet {
			lArgs = append(lArgs, "--led-delay", fmt.Sprintf("%d", r.LEDDelay))
		}
		if r.LEDAlwaysBlink {
			lArgs = append(lArgs, "--led-always-blink")
		}
		parts = append(parts, lArgs...)
	default:
		parts = append(parts, "-j", r.Jump)
	}

	return strings.Join(parts, " ")
}
