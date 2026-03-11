package codegen

import (
	"fmt"
	"strings"

	"yipt/internal/ir"
)

// tableOrder defines which tables to emit and in what order.
var tableOrder = []string{"filter", "nat", "mangle"}

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
			if r.SrcNeg {
				parts = append(parts, "-m", "set", "!", "--match-set", r.Src, "src")
			} else {
				parts = append(parts, "-m", "set", "--match-set", r.Src, "src")
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
			if r.DstNeg {
				parts = append(parts, "-m", "set", "!", "--match-set", r.Dst, "dst")
			} else {
				parts = append(parts, "-m", "set", "--match-set", r.Dst, "dst")
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
	default:
		parts = append(parts, "-j", r.Jump)
	}

	return strings.Join(parts, " ")
}
