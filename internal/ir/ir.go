package ir

import (
	"fmt"
	"strings"

	"yipt/internal/ast"
	"yipt/internal/sema"
)

// Program holds all the compiled data ready for code generation.
type Program struct {
	IPv4Ipsets []Ipset
	IPv6Ipsets []Ipset
	// Tables maps table name ("filter", "mangle") to a Table.
	Tables map[string]*Table
}

// Ipset is a compiled ipset set.
type Ipset struct {
	Name     string
	Family   string // "inet" or "inet6"
	Elements []string
}

// Table holds chains for one iptables table.
type Table struct {
	Name   string
	Chains []*Chain // ordered: built-ins first, then user-defined
}

// Chain holds the policy and compiled rules for one chain.
type Chain struct {
	Name      string
	Policy    string // "ACCEPT", "DROP", or "" for user-defined chains
	BuiltIn   bool
	IRRules   []*IRRule
}

// IRRule is a fully expanded, atomic iptables rule.
type IRRule struct {
	IPVersion int // 4, 6, or 0 (both/unspecified)
	Chain     string
	Comment   string

	// Interface matches
	In     string; InNeg  bool
	Out    string; OutNeg bool

	// Address matches
	Src    string; SrcNeg bool; SrcIsSet bool   // SrcIsSet → use -m set
	Dst    string; DstNeg bool; DstIsSet bool

	// Protocol
	Proto string

	// Port matches
	SPort    string; SPortNeg bool; SPortMulti bool
	DPort    string; DPortNeg bool; DPortMulti bool

	// Flags
	Syn bool

	// ICMP
	ICMPType   string // for --icmp-type
	ICMPv6Type string // for --icmpv6-type

	// Match modules (pre-rendered fragments like "-m conntrack --ctstate ...")
	MatchFragments []string

	// Target
	Jump       string
	RejectWith string
	LogPrefix  string
	SetMark    string
	TProxyMark string
	OnIP       string
	OnPort     int
}

var filterBuiltins = []string{"INPUT", "FORWARD", "OUTPUT"}
var mangleBuiltins = []string{"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"}

func isBuiltin(table, name string) bool {
	var list []string
	switch table {
	case "filter":
		list = filterBuiltins
	case "mangle":
		list = mangleBuiltins
	}
	for _, b := range list {
		if b == name {
			return true
		}
	}
	return false
}

// Build converts a Resolved document into a Program.
func Build(res *sema.Resolved) (*Program, error) {
	prog := &Program{
		Tables: make(map[string]*Table),
	}

	// Build ipset structures.
	for name, rr := range res.Resources {
		if rr.Type != "ipset" {
			continue
		}
		if rr.IsMixed {
			prog.IPv4Ipsets = append(prog.IPv4Ipsets, Ipset{
				Name:     name + "_v4",
				Family:   "inet",
				Elements: rr.IPv4Elements,
			})
			prog.IPv6Ipsets = append(prog.IPv6Ipsets, Ipset{
				Name:     name + "_v6",
				Family:   "inet6",
				Elements: rr.IPv6Elements,
			})
		} else if len(rr.IPv4Elements) > 0 {
			prog.IPv4Ipsets = append(prog.IPv4Ipsets, Ipset{
				Name:     name,
				Family:   "inet",
				Elements: rr.IPv4Elements,
			})
		} else {
			prog.IPv6Ipsets = append(prog.IPv6Ipsets, Ipset{
				Name:     name,
				Family:   "inet6",
				Elements: rr.IPv6Elements,
			})
		}
	}

	// Determine which tables have chains.
	type tableChain struct {
		table string
		name  string
	}
	chainsByTable := map[string][]tableChain{}
	for chainName, chain := range res.Doc.Chains {
		// A chain goes into the filter table if it has filter rules, or if it has a policy
		// and is a filter built-in (policy only makes sense for filter table).
		if len(chain.Filter) > 0 || (chain.Policy != "" && isBuiltin("filter", chainName)) {
			chainsByTable["filter"] = append(chainsByTable["filter"], tableChain{"filter", chainName})
		}
		// A chain goes into the mangle table only if it has mangle rules.
		// (Policy declarations are filter-table-specific; mangle built-ins default to ACCEPT.)
		if len(chain.Mangle) > 0 {
			chainsByTable["mangle"] = append(chainsByTable["mangle"], tableChain{"mangle", chainName})
		}
	}

	// For each table, order built-ins first then user-defined, then compile rules.
	for table, tcs := range chainsByTable {
		t := &Table{Name: table}
		// Collect unique chain names.
		seen := map[string]bool{}
		var orderedNames []string
		// Built-ins first.
		var builtinOrder []string
		switch table {
		case "filter":
			builtinOrder = filterBuiltins
		case "mangle":
			builtinOrder = mangleBuiltins
		}
		for _, bn := range builtinOrder {
			for _, tc := range tcs {
				if tc.name == bn && !seen[bn] {
					seen[bn] = true
					orderedNames = append(orderedNames, bn)
				}
			}
		}
		// User-defined chains.
		for _, tc := range tcs {
			if !seen[tc.name] {
				seen[tc.name] = true
				orderedNames = append(orderedNames, tc.name)
			}
		}

		for _, chainName := range orderedNames {
			chain := res.Doc.Chains[chainName]
			var rules []ast.Rule
			switch table {
			case "filter":
				rules = chain.Filter
			case "mangle":
				rules = chain.Mangle
			}

			policy := ""
			// Policy only applies to the filter table; mangle built-ins default to ACCEPT.
			if chain.Policy != "" && isBuiltin(table, chainName) && table == "filter" {
				policy = strings.ToUpper(chain.Policy)
			}

			c := &Chain{
				Name:    chainName,
				Policy:  policy,
				BuiltIn: isBuiltin(table, chainName),
			}

			for _, rule := range rules {
				expanded, err := expandRule(chainName, rule, res.Resources)
				if err != nil {
					return nil, fmt.Errorf("chain %s/%s: %w", chainName, table, err)
				}
				c.IRRules = append(c.IRRules, expanded...)
			}
			t.Chains = append(t.Chains, c)
		}

		prog.Tables[table] = t
	}

	return prog, nil
}

// expandRule expands a single AST rule into one or more IRRules,
// handling protocol lists, icmp typesets, and mixed ipsets.
func expandRule(chainName string, rule ast.Rule, resources map[string]*sema.ResolvedResource) ([]*IRRule, error) {
	// Start with a single base rule.
	bases := []*IRRule{{Chain: chainName}}

	// Expand protocol list.
	switch p := rule.Proto.(type) {
	case string:
		for _, b := range bases {
			b.Proto = p
		}
	case []interface{}:
		var expanded []*IRRule
		for _, proto := range p {
			ps, ok := proto.(string)
			if !ok {
				return nil, fmt.Errorf("protocol must be string, got %T", proto)
			}
			for _, b := range bases {
				nb := cloneRule(b)
				nb.Proto = ps
				expanded = append(expanded, nb)
			}
		}
		bases = expanded
	}

	// Set interface fields.
	for _, b := range bases {
		if rule.In != "" {
			b.In = rule.In
		}
		if rule.InNeg != "" {
			b.In = rule.InNeg
			b.InNeg = true
		}
		if rule.Out != "" {
			b.Out = rule.Out
		}
		if rule.OutNeg != "" {
			b.Out = rule.OutNeg
			b.OutNeg = true
		}
		b.Syn = rule.Syn
	}

	// Expand source address / ipset (possibly mixed).
	bases, err := expandAddrField(bases, rule.Src, false, true, resources)
	if err != nil {
		return nil, err
	}
	bases, err = expandAddrField(bases, rule.SrcNeg, true, true, resources)
	if err != nil {
		return nil, err
	}
	bases, err = expandAddrField(bases, rule.Dst, false, false, resources)
	if err != nil {
		return nil, err
	}
	bases, err = expandAddrField(bases, rule.DstNeg, true, false, resources)
	if err != nil {
		return nil, err
	}

	// Apply IP version from addresses/protocol.
	for _, b := range bases {
		// Protocol-based version.
		if b.Proto != "" {
			pv := sema.ClassifyProto(b.Proto)
			b.IPVersion = mergeVersion(b.IPVersion, int(pv))
		}
		// Address-based version (already set during expandAddrField for non-set addresses).
	}

	// Expand icmp-type (typeset or direct).
	bases, err = expandICMPField(bases, rule.ICMPType, false, resources)
	if err != nil {
		return nil, err
	}

	// Expand icmpv6-type (typeset or direct).
	bases, err = expandICMPField(bases, rule.ICMPv6Type, true, resources)
	if err != nil {
		return nil, err
	}

	// Compile ports once (they don't vary per expansion).
	sp, _, spMulti, err := compilePort(rule.SPort, false, resources)
	if err != nil {
		return nil, err
	}
	spNegVal, _, spNegMulti, err := compilePort(rule.SPortNeg, false, resources)
	if err != nil {
		return nil, err
	}
	dp, _, dpMulti, err := compilePort(rule.DPort, false, resources)
	if err != nil {
		return nil, err
	}
	dpNegVal, _, dpNegMulti, err := compilePort(rule.DPortNeg, false, resources)
	if err != nil {
		return nil, err
	}

	// Apply port fields.
	for _, b := range bases {
		if sp != "" {
			b.SPort = sp
			b.SPortNeg = false
			b.SPortMulti = spMulti
		}
		if spNegVal != "" {
			b.SPort = spNegVal
			b.SPortNeg = true
			b.SPortMulti = spNegMulti
		}
		if dp != "" {
			b.DPort = dp
			b.DPortNeg = false
			b.DPortMulti = dpMulti
		}
		if dpNegVal != "" {
			b.DPort = dpNegVal
			b.DPortNeg = true
			b.DPortMulti = dpNegMulti
		}

		// Target fields.
		b.Jump = strings.ToUpper(rule.Jump)
		switch rule.Jump {
		case "accept":
			b.Jump = "ACCEPT"
		case "drop":
			b.Jump = "DROP"
		case "return":
			b.Jump = "RETURN"
		case "reject":
			b.Jump = "REJECT"
			b.RejectWith = rule.RejectWith
		case "log":
			b.Jump = "LOG"
			b.LogPrefix = rule.LogPrefix
		case "mark":
			b.Jump = "MARK"
			b.SetMark = fmt.Sprintf("%v", rule.SetMark)
		case "tproxy":
			b.Jump = "TPROXY"
			b.OnIP = rule.OnIP
			b.OnPort = rule.OnPort
			b.TProxyMark = fmt.Sprintf("%v", rule.TProxyMark)
			// Detect IP version from on-ip.
			if rule.OnIP != "" {
				v := sema.ClassifyAddr(rule.OnIP)
				b.IPVersion = mergeVersion(b.IPVersion, int(v))
			}
		case "":
			b.Jump = ""
		default:
			// User-defined chain — keep as-is.
			b.Jump = rule.Jump
		}
	}

	// Build match fragments.
	for _, b := range bases {
		frags, ipv, err := buildMatchFragments(rule.Match)
		if err != nil {
			return nil, err
		}
		b.MatchFragments = frags
		if ipv != 0 {
			b.IPVersion = mergeVersion(b.IPVersion, ipv)
		}
		b.Comment = rule.Comment
	}

	return bases, nil
}

func mergeVersion(a, b int) int {
	if a == 0 {
		return b
	}
	if b == 0 {
		return a
	}
	if a == b {
		return a
	}
	// Contradictory — caller should handle; return 0 to keep both sides
	return 0
}

// expandAddrField handles a source/dest address field that may be a plain CIDR,
// an ipset reference ($name), or empty.
// isSrc controls whether we're expanding Src or Dst.
// mixed ipsets produce two rules (v4 and v6).
func expandAddrField(bases []*IRRule, addr string, neg bool, isSrc bool, resources map[string]*sema.ResolvedResource) ([]*IRRule, error) {
	if addr == "" {
		return bases, nil
	}

	if strings.HasPrefix(addr, "$") {
		name := addr[1:]
		rr, ok := resources[name]
		if !ok {
			return nil, fmt.Errorf("unknown resource $%s", name)
		}
		// ipset reference
		if rr.IsMixed {
			// Expand to two sets of rules: v4 using NAME_v4, v6 using NAME_v6
			var expanded []*IRRule
			for _, b := range bases {
				// IPv4 variant
				v4 := cloneRule(b)
				v4.IPVersion = mergeVersion(v4.IPVersion, 4)
				if isSrc {
					v4.Src = name + "_v4"
					v4.SrcNeg = neg
					v4.SrcIsSet = true
				} else {
					v4.Dst = name + "_v4"
					v4.DstNeg = neg
					v4.DstIsSet = true
				}
				expanded = append(expanded, v4)

				// IPv6 variant
				v6 := cloneRule(b)
				v6.IPVersion = mergeVersion(v6.IPVersion, 6)
				if isSrc {
					v6.Src = name + "_v6"
					v6.SrcNeg = neg
					v6.SrcIsSet = true
				} else {
					v6.Dst = name + "_v6"
					v6.DstNeg = neg
					v6.DstIsSet = true
				}
				expanded = append(expanded, v6)
			}
			return expanded, nil
		}
		// Pure v4 or v6 set
		setName := name
		var ipv int
		if len(rr.IPv4Elements) > 0 {
			ipv = 4
		} else {
			ipv = 6
		}
		for _, b := range bases {
			b.IPVersion = mergeVersion(b.IPVersion, ipv)
			if isSrc {
				b.Src = setName
				b.SrcNeg = neg
				b.SrcIsSet = true
			} else {
				b.Dst = setName
				b.DstNeg = neg
				b.DstIsSet = true
			}
		}
		return bases, nil
	}

	// Plain address — classify for IP version.
	v := sema.ClassifyAddr(addr)
	for _, b := range bases {
		if v != sema.IPvUnknown {
			b.IPVersion = mergeVersion(b.IPVersion, int(v))
		}
		if isSrc {
			b.Src = addr
			b.SrcNeg = neg
		} else {
			b.Dst = addr
			b.DstNeg = neg
		}
	}
	return bases, nil
}

// expandICMPField expands ICMP/ICMPv6 type references.
// If the value is a resource reference ($name), expands to one rule per element.
func expandICMPField(bases []*IRRule, val interface{}, isV6 bool, resources map[string]*sema.ResolvedResource) ([]*IRRule, error) {
	if val == nil {
		return bases, nil
	}

	switch v := val.(type) {
	case string:
		if strings.HasPrefix(v, "$") {
			name := v[1:]
			rr, ok := resources[name]
			if !ok {
				return nil, fmt.Errorf("unknown resource $%s", name)
			}
			var expanded []*IRRule
			for _, b := range bases {
				for _, elem := range rr.Elements {
					nb := cloneRule(b)
					typeStr := fmt.Sprintf("%v", elem)
					if isV6 {
						nb.ICMPv6Type = typeStr
						nb.IPVersion = mergeVersion(nb.IPVersion, 6)
					} else {
						nb.ICMPType = typeStr
						nb.IPVersion = mergeVersion(nb.IPVersion, 4)
					}
					expanded = append(expanded, nb)
				}
			}
			return expanded, nil
		}
		// Named string like "echo-reply"
		for _, b := range bases {
			if isV6 {
				b.ICMPv6Type = v
				b.IPVersion = mergeVersion(b.IPVersion, 6)
			} else {
				b.ICMPType = v
				b.IPVersion = mergeVersion(b.IPVersion, 4)
			}
		}
	case int:
		for _, b := range bases {
			if isV6 {
				b.ICMPv6Type = fmt.Sprintf("%d", v)
				b.IPVersion = mergeVersion(b.IPVersion, 6)
			} else {
				b.ICMPType = fmt.Sprintf("%d", v)
				b.IPVersion = mergeVersion(b.IPVersion, 4)
			}
		}
	}

	return bases, nil
}

// compilePort converts a port value to a rendered string + multi flag.
// portsets and lists become multiport strings.
// single ports / single ranges stay as direct --dport/--sport.
func compilePort(val interface{}, neg bool, resources map[string]*sema.ResolvedResource) (portStr string, isNeg bool, isMulti bool, err error) {
	if val == nil {
		return "", false, false, nil
	}

	switch v := val.(type) {
	case int:
		return fmt.Sprintf("%d", v), neg, false, nil
	case string:
		if strings.HasPrefix(v, "$") {
			name := v[1:]
			rr, ok := resources[name]
			if !ok {
				return "", false, false, fmt.Errorf("unknown resource $%s", name)
			}
			// portset → multiport
			var parts []string
			for _, elem := range rr.Elements {
				parts = append(parts, fmt.Sprintf("%v", elem))
			}
			return strings.Join(parts, ","), neg, true, nil
		}
		// Raw string port or range like "137:139"
		return v, neg, false, nil
	case []interface{}:
		if len(v) == 0 {
			return "", false, false, nil
		}
		// Single element check: single value or single range → no multiport
		if len(v) == 1 {
			return compilePort(v[0], neg, resources)
		}
		// Multiple elements → multiport
		var parts []string
		for _, elem := range v {
			switch e := elem.(type) {
			case int:
				parts = append(parts, fmt.Sprintf("%d", e))
			case string:
				parts = append(parts, e)
			default:
				parts = append(parts, fmt.Sprintf("%v", e))
			}
		}
		return strings.Join(parts, ","), neg, true, nil
	}

	return fmt.Sprintf("%v", val), neg, false, nil
}

// buildMatchFragments renders match module flags into string fragments.
// Returns (fragments, forced-ipversion, error).
func buildMatchFragments(mb *ast.MatchBlock) ([]string, int, error) {
	if mb == nil {
		return nil, 0, nil
	}

	var frags []string
	ipv := 0

	if mb.Conntrack != nil {
		states := strings.Join(mb.Conntrack.CTState, ",")
		frags = append(frags, fmt.Sprintf("-m conntrack --ctstate %s", states))
	}

	if mb.Recent != nil {
		r := mb.Recent
		var parts []string
		parts = append(parts, "-m recent")
		if r.Name != "" {
			parts = append(parts, "--name", r.Name)
		}
		if r.Set {
			parts = append(parts, "--set")
		}
		if r.Update {
			parts = append(parts, "--update")
		}
		if r.Seconds > 0 {
			parts = append(parts, "--seconds", fmt.Sprintf("%d", r.Seconds))
		}
		if r.HitCount > 0 {
			parts = append(parts, "--hitcount", fmt.Sprintf("%d", r.HitCount))
		}
		if r.RSource {
			parts = append(parts, "--rsource")
		}
		if r.RTTL {
			parts = append(parts, "--rttl")
		}
		frags = append(frags, strings.Join(parts, " "))
	}

	if mb.Limit != nil {
		l := mb.Limit
		frag := fmt.Sprintf("-m limit --limit %s", l.Limit)
		if l.LimitBurst > 0 {
			frag += fmt.Sprintf(" --limit-burst %d", l.LimitBurst)
		}
		frags = append(frags, frag)
	}

	if mb.Mark != nil {
		frags = append(frags, fmt.Sprintf("-m mark --mark %v", mb.Mark.Mark))
	}

	if mb.Socket != nil {
		frags = append(frags, "-m socket")
	}

	if mb.AddrType != nil {
		frags = append(frags, fmt.Sprintf("-m addrtype --dst-type %s", mb.AddrType.DstType))
		ipv = 4 // addrtype is IPv4-only
	}

	return frags, ipv, nil
}

func cloneRule(r *IRRule) *IRRule {
	n := *r
	// Deep copy match fragments slice.
	if len(r.MatchFragments) > 0 {
		n.MatchFragments = make([]string, len(r.MatchFragments))
		copy(n.MatchFragments, r.MatchFragments)
	}
	return &n
}
