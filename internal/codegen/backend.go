package codegen

import "yipt/internal/ir"

// Backend renders a compiled Program into output text.
type Backend interface {
	Render(prog *ir.Program) string
}

// IptablesBackend renders iptables-restore compatible output.
type IptablesBackend struct{}

// Render implements Backend.
func (IptablesBackend) Render(prog *ir.Program) string {
	return RenderIptablesRestore(prog)
}
