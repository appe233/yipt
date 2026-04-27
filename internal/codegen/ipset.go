package codegen

import (
	"fmt"
	"strings"

	"github.com/appe233/yipt/internal/ast"
	"github.com/appe233/yipt/internal/ir"
)

// RenderIpsetScript renders shell commands to create and populate ipsets.
// Each set is emitted with its declared set-type, family, and creation options.
func RenderIpsetScript(prog *ir.Program) string {
	var sb strings.Builder

	all := append(prog.IPv4Ipsets, prog.IPv6Ipsets...)
	for _, set := range all {
		setType := set.SetType
		if setType == "" {
			setType = "hash:net"
		}
		sb.WriteString("ipset create -exist ")
		sb.WriteString(set.Name)
		sb.WriteString(" ")
		sb.WriteString(setType)
		// Bitmap types take `range` (rendered below) instead of `family`.
		if !strings.HasPrefix(setType, "bitmap:") {
			sb.WriteString(" family ")
			sb.WriteString(set.Family)
		}
		if set.Options != nil {
			sb.WriteString(renderIpsetOptions(set.Options, setType))
		}
		sb.WriteString("\n")
		for _, elem := range set.Elements {
			sb.WriteString("ipset add ")
			sb.WriteString(set.Name)
			sb.WriteString(" ")
			sb.WriteString(elem)
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

// renderIpsetOptions renders creation attributes for a set in the order ipset expects.
// Attributes that do not apply to setType are skipped (sema rejects incompatible
// combinations earlier, so this is belt-and-suspenders).
func renderIpsetOptions(opts *ast.SetOptions, setType string) string {
	var sb strings.Builder
	if opts.Range != "" && strings.HasPrefix(setType, "bitmap:") {
		sb.WriteString(" range ")
		sb.WriteString(opts.Range)
	}
	if opts.NetMask != 0 {
		fmt.Fprintf(&sb, " netmask %d", opts.NetMask)
	}
	if opts.MarkMask != "" {
		sb.WriteString(" markmask ")
		sb.WriteString(opts.MarkMask)
	}
	if opts.HashSize != 0 {
		fmt.Fprintf(&sb, " hashsize %d", opts.HashSize)
	}
	if opts.MaxElem != 0 {
		fmt.Fprintf(&sb, " maxelem %d", opts.MaxElem)
	}
	if opts.Timeout != nil {
		fmt.Fprintf(&sb, " timeout %d", *opts.Timeout)
	}
	if opts.Counters {
		sb.WriteString(" counters")
	}
	if opts.Comment {
		sb.WriteString(" comment")
	}
	if opts.SkbInfo {
		sb.WriteString(" skbinfo")
	}
	return sb.String()
}
