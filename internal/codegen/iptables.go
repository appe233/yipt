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
	var sb strings.Builder

	for _, tableName := range tableOrder {
		t, ok := prog.Tables[tableName]
		if !ok {
			continue
		}

		sb.WriteString("*")
		sb.WriteString(tableName)
		sb.WriteString("\n")

		// Policy lines for built-in chains.
		for _, chain := range t.Chains {
			if chain.BuiltIn {
				policy := chain.Policy
				if policy == "" {
					policy = "ACCEPT"
				}
				sb.WriteString(fmt.Sprintf(":%s %s [0:0]\n", chain.Name, policy))
			}
		}

		// -N declarations for user-defined chains.
		for _, chain := range t.Chains {
			if !chain.BuiltIn {
				sb.WriteString(fmt.Sprintf("-N %s\n", chain.Name))
			}
		}

		// Rules.
		for _, chain := range t.Chains {
			for _, rule := range chain.IRRules {
				sb.WriteString(renderRule(rule))
				sb.WriteString("\n")
			}
		}

		sb.WriteString("COMMIT\n")
	}

	return sb.String()
}

func renderRule(r *ir.IRRule) string {
	var parts []string

	// IP version prefix.
	switch r.IPVersion {
	case 4:
		parts = append(parts, "-4")
	case 6:
		parts = append(parts, "-6")
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
				parts = append(parts, "!", "--sports", r.SPort)
			} else {
				parts = append(parts, "--sports", r.SPort)
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
				parts = append(parts, "!", "--dports", r.DPort)
			} else {
				parts = append(parts, "--dports", r.DPort)
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
