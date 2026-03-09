package codegen

import (
	"strings"

	"yipt/internal/ir"
)

// RenderIpsetScript renders shell commands to create and populate ipsets.
func RenderIpsetScript(prog *ir.Program) string {
	var sb strings.Builder

	all := append(prog.IPv4Ipsets, prog.IPv6Ipsets...)
	for _, ipset := range all {
		sb.WriteString("ipset create -exist ")
		sb.WriteString(ipset.Name)
		sb.WriteString(" hash:net family ")
		sb.WriteString(ipset.Family)
		sb.WriteString("\n")
		for _, elem := range ipset.Elements {
			sb.WriteString("ipset add ")
			sb.WriteString(ipset.Name)
			sb.WriteString(" ")
			sb.WriteString(elem)
			sb.WriteString("\n")
		}
	}

	return sb.String()
}
