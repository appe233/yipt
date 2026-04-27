package ir

import (
	"fmt"
	"strings"

	"github.com/appe233/yipt/internal/ast"
	"github.com/appe233/yipt/internal/sema"
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
	SetType  string // e.g. "hash:net", "hash:ip,port"
	Options  *ast.SetOptions
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
	// Direction flag lists for multi-dim ipset references ("src", "dst", "src,dst", ...).
	// Empty string means "use the default direction for the field (src for s:, dst for d:)".
	SrcSetDir string
	DstSetDir string

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
	// NAT targets
	ToSource string
	ToDest   string
	ToPorts  string
	// CT target (raw table)
	Zone     int
	Helper   string
	CTEvents []string
	CTMask   string
	NfMask   string

	// TCP flag / option / fragment matches
	TCPFlagsMask string // pre-joined, e.g. "SYN,ACK,FIN,RST"
	TCPFlagsComp string // pre-joined, e.g. "SYN" or "NONE"
	TCPOption    int
	Fragment     bool

	// TCPMSS target
	SetMSS         int
	ClampMSSToPMTU bool

	// CONNMARK target
	SaveMark    bool
	RestoreMark bool

	// NFLOG target
	NflogGroup     int
	NflogPrefix    string
	NflogRange     int
	NflogThreshold int

	// NFQUEUE target
	QueueNum       int
	QueueNumSet    bool
	QueueBalance   string
	QueueBypass    bool
	QueueCPUFanout bool

	// SET target
	AddSet     string
	DelSet     string
	SetFlags   []string
	SetExist   bool
	SetTimeout int

	// Phase 9 — packet-modification targets. Per-target fields are mutually
	// relevant only when Jump matches; sema guarantees they're set correctly.
	SetClass     string // CLASSIFY --set-class
	SetDSCP      string // DSCP --set-dscp (decimal or hex)
	SetDSCPClass string // DSCP --set-dscp-class
	SetTOS       string // TOS --set-tos
	AndTOS       string // TOS --and-tos
	OrTOS        string // TOS --or-tos
	XorTOS       string // TOS --xor-tos
	ECNTCPRemove bool   // ECN --ecn-tcp-remove
	// TTL / HL (target)
	TTLSet *int
	TTLDec *int
	TTLInc *int
	HLSet  *int
	HLDec  *int
	HLInc  *int
	// SECMARK / CONNSECMARK
	SelCtx             string
	ConnSecMarkSave    bool
	ConnSecMarkRestore bool
	// SYNPROXY
	SynproxyMSS       int
	SynproxyWScale    int
	SynproxyTimestamp bool
	SynproxySAckPerm  bool
	// TEE / AUDIT / CHECKSUM / NETMAP
	Gateway      string
	AuditType    string
	ChecksumFill bool
	NetmapTo     string
	// CLUSTERIP
	ClusterIPNew        bool
	ClusterIPHashmode   string
	ClusterIPClusterMAC string
	ClusterIPTotalNodes int
	ClusterIPLocalNode  int
	ClusterIPHashInit   int
	// IDLETIMER
	IdletimerTimeout int
	IdletimerLabel   string
	IdletimerAlarm   bool
	// RATEEST
	RateestName     string
	RateestInterval int
	RateestEwmalog  int
	// LED
	LEDTriggerID   string
	LEDDelay       int
	LEDDelaySet    bool
	LEDAlwaysBlink bool
}

var filterBuiltins = []string{"INPUT", "FORWARD", "OUTPUT"}
var mangleBuiltins = []string{"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"}
var natBuiltins = []string{"PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"}
var rawBuiltins = []string{"PREROUTING", "OUTPUT"}
var securityBuiltins = []string{"INPUT", "FORWARD", "OUTPUT"}

func isBuiltin(table, name string) bool {
	var list []string
	switch table {
	case "filter":
		list = filterBuiltins
	case "mangle":
		list = mangleBuiltins
	case "nat":
		list = natBuiltins
	case "raw":
		list = rawBuiltins
	case "security":
		list = securityBuiltins
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
			// Mixed family is only possible for address-bearing types; the sema
			// pass guarantees that.
			prog.IPv4Ipsets = append(prog.IPv4Ipsets, Ipset{
				Name:     name + "_v4",
				Family:   "inet",
				SetType:  rr.SetType,
				Options:  rr.SetOptions,
				Elements: rr.IPv4Elements,
			})
			prog.IPv6Ipsets = append(prog.IPv6Ipsets, Ipset{
				Name:     name + "_v6",
				Family:   "inet6",
				SetType:  rr.SetType,
				Options:  rr.SetOptions,
				Elements: rr.IPv6Elements,
			})
		} else if rr.Family == "inet6" || len(rr.IPv6Elements) > 0 {
			prog.IPv6Ipsets = append(prog.IPv6Ipsets, Ipset{
				Name:     name,
				Family:   "inet6",
				SetType:  rr.SetType,
				Options:  rr.SetOptions,
				Elements: rr.IPv6Elements,
			})
		} else {
			prog.IPv4Ipsets = append(prog.IPv4Ipsets, Ipset{
				Name:     name,
				Family:   "inet",
				SetType:  rr.SetType,
				Options:  rr.SetOptions,
				Elements: rr.IPv4Elements,
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
		// A chain goes into the nat table if it has nat rules, or if it has a policy
		// and is a nat built-in.
		if len(chain.Nat) > 0 || (chain.Policy != "" && isBuiltin("nat", chainName)) {
			chainsByTable["nat"] = append(chainsByTable["nat"], tableChain{"nat", chainName})
		}
		// A chain goes into the raw table only if it has raw rules.
		// (Policy declarations are filter-table-specific; raw built-ins default to ACCEPT.)
		if len(chain.Raw) > 0 {
			chainsByTable["raw"] = append(chainsByTable["raw"], tableChain{"raw", chainName})
		}
		// A chain goes into the security table only if it has security rules.
		if len(chain.Security) > 0 {
			chainsByTable["security"] = append(chainsByTable["security"], tableChain{"security", chainName})
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
		case "nat":
			builtinOrder = natBuiltins
		case "raw":
			builtinOrder = rawBuiltins
		case "security":
			builtinOrder = securityBuiltins
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
			case "nat":
				rules = chain.Nat
			case "raw":
				rules = chain.Raw
			case "security":
				rules = chain.Security
			}

			policy := ""
			// Policy applies to filter and nat built-in chains; mangle built-ins default to ACCEPT.
			if chain.Policy != "" && isBuiltin(table, chainName) && (table == "filter" || table == "nat") {
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
		b.Fragment = rule.Fragment
		b.TCPOption = rule.TCPOption
		if rule.TCPFlags != nil {
			b.TCPFlagsMask = strings.ToUpper(strings.Join(rule.TCPFlags.Mask, ","))
			b.TCPFlagsComp = strings.ToUpper(strings.Join(rule.TCPFlags.Comp, ","))
		}
		// Fragment (-f) is IPv4-only.
		if rule.Fragment {
			b.IPVersion = mergeVersion(b.IPVersion, 4)
		}
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
		case "masquerade":
			b.Jump = "MASQUERADE"
			b.ToPorts = rule.ToPorts
		case "snat":
			b.Jump = "SNAT"
			b.ToSource = rule.ToSource
			b.ToPorts = rule.ToPorts
		case "dnat":
			b.Jump = "DNAT"
			b.ToDest = rule.ToDest
			b.ToPorts = rule.ToPorts
		case "redirect":
			b.Jump = "REDIRECT"
			b.ToPorts = rule.ToPorts
		case "ct":
			if rule.Notrack {
				b.Jump = "NOTRACK"
			} else {
				b.Jump = "CT"
				b.Zone = rule.Zone
				b.Helper = rule.Helper
				b.CTEvents = rule.CTEvents
				if rule.CTMask != nil {
					b.CTMask = fmt.Sprintf("%v", rule.CTMask)
				}
				if rule.NfMask != nil {
					b.NfMask = fmt.Sprintf("%v", rule.NfMask)
				}
			}
		case "tcpmss":
			b.Jump = "TCPMSS"
			b.SetMSS = rule.SetMSS
			b.ClampMSSToPMTU = rule.ClampMSSToPMTU
		case "connmark":
			b.Jump = "CONNMARK"
			if rule.SetMark != nil {
				b.SetMark = fmt.Sprintf("%v", rule.SetMark)
			}
			b.SaveMark = rule.SaveMark
			b.RestoreMark = rule.RestoreMark
			if rule.CTMask != nil {
				b.CTMask = fmt.Sprintf("%v", rule.CTMask)
			}
			if rule.NfMask != nil {
				b.NfMask = fmt.Sprintf("%v", rule.NfMask)
			}
		case "nflog":
			b.Jump = "NFLOG"
			b.NflogGroup = rule.NflogGroup
			b.NflogPrefix = rule.NflogPrefix
			b.NflogRange = rule.NflogRange
			b.NflogThreshold = rule.NflogThreshold
		case "nfqueue":
			b.Jump = "NFQUEUE"
			b.QueueNum = rule.QueueNum
			b.QueueNumSet = rule.QueueNumSet
			b.QueueBalance = rule.QueueBalance
			b.QueueBypass = rule.QueueBypass
			b.QueueCPUFanout = rule.QueueCPUFanout
		case "set":
			b.Jump = "SET"
			b.AddSet = rule.AddSet
			b.DelSet = rule.DelSet
			b.SetFlags = rule.SetFlags
			b.SetExist = rule.SetExist
			b.SetTimeout = rule.SetTimeout
			// Force IP version to match the referenced set's family.
			name := rule.AddSet
			if name == "" {
				name = rule.DelSet
			}
			if rr, ok := resources[name]; ok {
				if len(rr.IPv4Elements) > 0 {
					b.IPVersion = mergeVersion(b.IPVersion, 4)
				} else if len(rr.IPv6Elements) > 0 {
					b.IPVersion = mergeVersion(b.IPVersion, 6)
				}
			}
		case "classify":
			b.Jump = "CLASSIFY"
			b.SetClass = rule.SetClass
		case "dscp":
			b.Jump = "DSCP"
			if rule.SetDSCP != nil {
				b.SetDSCP = fmt.Sprintf("%v", rule.SetDSCP)
			}
			b.SetDSCPClass = rule.SetDSCPClass
		case "tos":
			b.Jump = "TOS"
			if rule.SetTOS != nil {
				b.SetTOS = fmt.Sprintf("%v", rule.SetTOS)
			}
			if rule.AndTOS != nil {
				b.AndTOS = fmt.Sprintf("%v", rule.AndTOS)
			}
			if rule.OrTOS != nil {
				b.OrTOS = fmt.Sprintf("%v", rule.OrTOS)
			}
			if rule.XorTOS != nil {
				b.XorTOS = fmt.Sprintf("%v", rule.XorTOS)
			}
		case "ecn":
			b.Jump = "ECN"
			b.ECNTCPRemove = rule.ECNTCPRemove
		case "ttl":
			b.Jump = "TTL"
			b.TTLSet = rule.TTLSet
			b.TTLDec = rule.TTLDec
			b.TTLInc = rule.TTLInc
			b.IPVersion = mergeVersion(b.IPVersion, 4)
		case "hl":
			b.Jump = "HL"
			b.HLSet = rule.HLSet
			b.HLDec = rule.HLDec
			b.HLInc = rule.HLInc
			b.IPVersion = mergeVersion(b.IPVersion, 6)
		case "secmark":
			b.Jump = "SECMARK"
			b.SelCtx = rule.SelCtx
		case "connsecmark":
			b.Jump = "CONNSECMARK"
			b.ConnSecMarkSave = rule.ConnSecMarkSave
			b.ConnSecMarkRestore = rule.ConnSecMarkRestore
		case "synproxy":
			b.Jump = "SYNPROXY"
			b.SynproxyMSS = rule.SynproxyMSS
			b.SynproxyWScale = rule.SynproxyWScale
			b.SynproxyTimestamp = rule.SynproxyTimestamp
			b.SynproxySAckPerm = rule.SynproxySAckPerm
		case "tee":
			b.Jump = "TEE"
			b.Gateway = rule.Gateway
			if rule.Gateway != "" {
				v := sema.ClassifyAddr(rule.Gateway)
				b.IPVersion = mergeVersion(b.IPVersion, int(v))
			}
		case "trace":
			b.Jump = "TRACE"
		case "audit":
			b.Jump = "AUDIT"
			b.AuditType = strings.ToLower(rule.AuditType)
		case "checksum":
			b.Jump = "CHECKSUM"
			b.ChecksumFill = rule.ChecksumFill
		case "netmap":
			b.Jump = "NETMAP"
			b.NetmapTo = rule.NetmapTo
			if rule.NetmapTo != "" {
				v := sema.ClassifyAddr(rule.NetmapTo)
				b.IPVersion = mergeVersion(b.IPVersion, int(v))
			}
		case "clusterip":
			b.Jump = "CLUSTERIP"
			b.ClusterIPNew = rule.ClusterIPNew
			b.ClusterIPHashmode = strings.ToLower(rule.ClusterIPHashmode)
			b.ClusterIPClusterMAC = rule.ClusterIPClusterMAC
			b.ClusterIPTotalNodes = rule.ClusterIPTotalNodes
			b.ClusterIPLocalNode = rule.ClusterIPLocalNode
			b.ClusterIPHashInit = rule.ClusterIPHashInit
		case "idletimer":
			b.Jump = "IDLETIMER"
			b.IdletimerTimeout = rule.IdletimerTimeout
			b.IdletimerLabel = rule.IdletimerLabel
			b.IdletimerAlarm = rule.IdletimerAlarm
		case "rateest":
			b.Jump = "RATEEST"
			b.RateestName = rule.RateestName
			b.RateestInterval = rule.RateestInterval
			b.RateestEwmalog = rule.RateestEwmalog
		case "led":
			b.Jump = "LED"
			b.LEDTriggerID = rule.LEDTriggerID
			b.LEDDelay = rule.LEDDelay
			b.LEDDelaySet = rule.LEDDelaySet
			b.LEDAlwaysBlink = rule.LEDAlwaysBlink
		case "":
			b.Jump = ""
		default:
			// User-defined chain — keep as-is.
			b.Jump = rule.Jump
		}
	}

	// Build match fragments. Each entry in rule.Match contributes one or more fragments;
	// version forcing from any entry merges into the rule's IP version.
	var allFrags []string
	combinedIPV := 0
	for _, mb := range rule.Match {
		frags, ipv, err := buildMatchFragments(mb)
		if err != nil {
			return nil, err
		}
		allFrags = append(allFrags, frags...)
		if ipv != 0 {
			combinedIPV = mergeVersion(combinedIPV, ipv)
		}
	}
	for _, b := range bases {
		b.MatchFragments = append(b.MatchFragments, allFrags...)
		if combinedIPV != 0 {
			b.IPVersion = mergeVersion(b.IPVersion, combinedIPV)
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
// an ipset reference ($name or $name[dir,dir]), or empty.
// isSrc controls whether we're expanding Src or Dst.
// mixed ipsets produce two rules (v4 and v6).
func expandAddrField(bases []*IRRule, addr string, neg bool, isSrc bool, resources map[string]*sema.ResolvedResource) ([]*IRRule, error) {
	if addr == "" {
		return bases, nil
	}

	if strings.HasPrefix(addr, "$") {
		name, dirs, _, err := sema.ParseSetRef(addr)
		if err != nil {
			return nil, err
		}
		setDir := strings.Join(dirs, ",")
		rr, ok := resources[name]
		if !ok {
			return nil, fmt.Errorf("unknown resource $%s", name)
		}
		// ipset reference.
		// For non-address-bearing sets (hash:mac, bitmap:port, list:set), family
		// defaults to the declared family; IsMixed is never true.
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
					v4.SrcSetDir = setDir
				} else {
					v4.Dst = name + "_v4"
					v4.DstNeg = neg
					v4.DstIsSet = true
					v4.DstSetDir = setDir
				}
				expanded = append(expanded, v4)

				// IPv6 variant
				v6 := cloneRule(b)
				v6.IPVersion = mergeVersion(v6.IPVersion, 6)
				if isSrc {
					v6.Src = name + "_v6"
					v6.SrcNeg = neg
					v6.SrcIsSet = true
					v6.SrcSetDir = setDir
				} else {
					v6.Dst = name + "_v6"
					v6.DstNeg = neg
					v6.DstIsSet = true
					v6.DstSetDir = setDir
				}
				expanded = append(expanded, v6)
			}
			return expanded, nil
		}
		// Single-family set: determine family from the resolved resource.
		setName := name
		ipv := 0
		switch rr.Family {
		case "inet":
			ipv = 4
		case "inet6":
			ipv = 6
		}
		for _, b := range bases {
			if ipv != 0 {
				b.IPVersion = mergeVersion(b.IPVersion, ipv)
			}
			if isSrc {
				b.Src = setName
				b.SrcNeg = neg
				b.SrcIsSet = true
				b.SrcSetDir = setDir
			} else {
				b.Dst = setName
				b.DstNeg = neg
				b.DstIsSet = true
				b.DstSetDir = setDir
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
		c := mb.Conntrack
		parts := []string{"-m conntrack"}
		if len(c.CTState) > 0 {
			parts = append(parts, "--ctstate", strings.Join(c.CTState, ","))
		}
		if c.CTProto != "" {
			parts = append(parts, "--ctproto", c.CTProto)
		}
		if c.CTOrigSrc != "" {
			parts = append(parts, "--ctorigsrc", c.CTOrigSrc)
			ipv = mergeVersion(ipv, int(sema.ClassifyAddr(c.CTOrigSrc)))
		}
		if c.CTOrigDst != "" {
			parts = append(parts, "--ctorigdst", c.CTOrigDst)
			ipv = mergeVersion(ipv, int(sema.ClassifyAddr(c.CTOrigDst)))
		}
		if c.CTOrigSrcPort != "" {
			parts = append(parts, "--ctorigsrcport", c.CTOrigSrcPort)
		}
		if c.CTOrigDstPort != "" {
			parts = append(parts, "--ctorigdstport", c.CTOrigDstPort)
		}
		if c.CTReplSrc != "" {
			parts = append(parts, "--ctreplsrc", c.CTReplSrc)
			ipv = mergeVersion(ipv, int(sema.ClassifyAddr(c.CTReplSrc)))
		}
		if c.CTReplDst != "" {
			parts = append(parts, "--ctrepldst", c.CTReplDst)
			ipv = mergeVersion(ipv, int(sema.ClassifyAddr(c.CTReplDst)))
		}
		if len(c.CTStatus) > 0 {
			parts = append(parts, "--ctstatus", strings.Join(c.CTStatus, ","))
		}
		if c.CTExpire != "" {
			parts = append(parts, "--ctexpire", c.CTExpire)
		}
		if c.CTDir != "" {
			parts = append(parts, "--ctdir", strings.ToUpper(c.CTDir))
		}
		frags = append(frags, strings.Join(parts, " "))
	}

	if mb.Recent != nil {
		r := mb.Recent
		parts := []string{"-m recent"}
		if r.Name != "" {
			parts = append(parts, "--name", r.Name)
		}
		if r.Set {
			parts = append(parts, "--set")
		}
		if r.Update {
			parts = append(parts, "--update")
		}
		if r.RCheck {
			parts = append(parts, "--rcheck")
		}
		if r.Remove {
			parts = append(parts, "--remove")
		}
		if r.Seconds > 0 {
			parts = append(parts, "--seconds", fmt.Sprintf("%d", r.Seconds))
		}
		if r.Reap {
			parts = append(parts, "--reap")
		}
		if r.HitCount > 0 {
			parts = append(parts, "--hitcount", fmt.Sprintf("%d", r.HitCount))
		}
		if r.RSource {
			parts = append(parts, "--rsource")
		}
		if r.RDest {
			parts = append(parts, "--rdest")
		}
		if r.RTTL {
			parts = append(parts, "--rttl")
		}
		if r.Mask != "" {
			parts = append(parts, "--mask", r.Mask)
			ipv = mergeVersion(ipv, int(sema.ClassifyAddr(r.Mask)))
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

	if mb.Connmark != nil {
		frags = append(frags, fmt.Sprintf("-m connmark --mark %v", mb.Connmark.Mark))
	}

	if mb.Connlimit != nil {
		c := mb.Connlimit
		parts := []string{"-m connlimit"}
		if c.Above != nil {
			parts = append(parts, "--connlimit-above", fmt.Sprintf("%d", *c.Above))
		}
		if c.Upto != nil {
			parts = append(parts, "--connlimit-upto", fmt.Sprintf("%d", *c.Upto))
		}
		if c.Mask != nil {
			parts = append(parts, "--connlimit-mask", fmt.Sprintf("%d", *c.Mask))
		}
		if c.SAddr {
			parts = append(parts, "--connlimit-saddr")
		}
		if c.DAddr {
			parts = append(parts, "--connlimit-daddr")
		}
		frags = append(frags, strings.Join(parts, " "))
	}

	if mb.Hashlimit != nil {
		h := mb.Hashlimit
		parts := []string{"-m hashlimit"}
		if h.Upto != "" {
			parts = append(parts, "--hashlimit-upto", h.Upto)
		}
		if h.Above != "" {
			parts = append(parts, "--hashlimit-above", h.Above)
		}
		if h.Burst > 0 {
			parts = append(parts, "--hashlimit-burst", fmt.Sprintf("%d", h.Burst))
		}
		if len(h.Mode) > 0 {
			parts = append(parts, "--hashlimit-mode", strings.Join(h.Mode, ","))
		}
		if h.SrcMask != nil {
			parts = append(parts, "--hashlimit-srcmask", fmt.Sprintf("%d", *h.SrcMask))
		}
		if h.DstMask != nil {
			parts = append(parts, "--hashlimit-dstmask", fmt.Sprintf("%d", *h.DstMask))
		}
		parts = append(parts, "--hashlimit-name", h.Name)
		if h.HTableSize > 0 {
			parts = append(parts, "--hashlimit-htable-size", fmt.Sprintf("%d", h.HTableSize))
		}
		if h.HTableMax > 0 {
			parts = append(parts, "--hashlimit-htable-max", fmt.Sprintf("%d", h.HTableMax))
		}
		if h.HTableExpire > 0 {
			parts = append(parts, "--hashlimit-htable-expire", fmt.Sprintf("%d", h.HTableExpire))
		}
		if h.HTableGCInterval > 0 {
			parts = append(parts, "--hashlimit-htable-gcinterval", fmt.Sprintf("%d", h.HTableGCInterval))
		}
		frags = append(frags, strings.Join(parts, " "))
	}

	if mb.Socket != nil {
		s := mb.Socket
		parts := []string{"-m socket"}
		if s.Transparent {
			parts = append(parts, "--transparent")
		}
		if s.NoWildcard {
			parts = append(parts, "--nowildcard")
		}
		if s.RestoreSKMark {
			parts = append(parts, "--restore-skmark")
		}
		frags = append(frags, strings.Join(parts, " "))
	}

	if mb.AddrType != nil {
		a := mb.AddrType
		parts := []string{"-m addrtype"}
		if a.SrcType != "" {
			parts = append(parts, "--src-type", strings.ToUpper(a.SrcType))
		}
		if a.DstType != "" {
			parts = append(parts, "--dst-type", strings.ToUpper(a.DstType))
		}
		if a.LimitIfaceIn != "" {
			parts = append(parts, "--limit-iface-in", a.LimitIfaceIn)
		}
		if a.LimitIfaceOut != "" {
			parts = append(parts, "--limit-iface-out", a.LimitIfaceOut)
		}
		frags = append(frags, strings.Join(parts, " "))
		ipv = mergeVersion(ipv, 4) // addrtype is IPv4-only
	}

	if mb.MAC != nil {
		if mb.MAC.Neg {
			frags = append(frags, fmt.Sprintf("-m mac ! --mac-source %s", mb.MAC.MACSource))
		} else {
			frags = append(frags, fmt.Sprintf("-m mac --mac-source %s", mb.MAC.MACSource))
		}
		ipv = mergeVersion(ipv, 4) // mac matching is IPv4-only in iptables
	}

	if mb.Time != nil {
		tm := mb.Time
		parts := []string{"-m time"}
		if tm.TimeStart != "" {
			parts = append(parts, "--timestart", tm.TimeStart)
		}
		if tm.TimeStop != "" {
			parts = append(parts, "--timestop", tm.TimeStop)
		}
		if tm.Days != "" {
			parts = append(parts, "--weekdays", tm.Days)
		}
		if tm.DateStart != "" {
			parts = append(parts, "--datestart", tm.DateStart)
		}
		if tm.DateStop != "" {
			parts = append(parts, "--datestop", tm.DateStop)
		}
		if tm.MonthDays != "" {
			parts = append(parts, "--monthdays", tm.MonthDays)
		}
		if tm.UTC {
			parts = append(parts, "--utc")
		}
		if tm.KernelTZ {
			parts = append(parts, "--kerneltz")
		}
		if tm.Contiguous {
			parts = append(parts, "--contiguous")
		}
		frags = append(frags, strings.Join(parts, " "))
	}

	if mb.State != nil {
		states := strings.Join(mb.State.State, ",")
		frags = append(frags, fmt.Sprintf("-m state --state %s", states))
	}

	if mb.Owner != nil {
		o := mb.Owner
		parts := []string{"-m owner"}
		if o.UIDOwner != nil {
			parts = append(parts, "--uid-owner", fmt.Sprintf("%d", *o.UIDOwner))
		}
		if o.GIDOwner != nil {
			parts = append(parts, "--gid-owner", fmt.Sprintf("%d", *o.GIDOwner))
		}
		if o.PIDOwner != nil {
			parts = append(parts, "--pid-owner", fmt.Sprintf("%d", *o.PIDOwner))
		}
		if o.SIDOwner != nil {
			parts = append(parts, "--sid-owner", fmt.Sprintf("%d", *o.SIDOwner))
		}
		if o.CmdOwner != "" {
			parts = append(parts, "--cmd-owner", o.CmdOwner)
		}
		if o.SocketExists {
			parts = append(parts, "--socket-exists")
		}
		frags = append(frags, strings.Join(parts, " "))
	}

	if mb.IPRange != nil {
		ir := mb.IPRange
		parts := []string{"-m iprange"}
		if ir.SrcRange != "" {
			parts = append(parts, "--src-range", ir.SrcRange)
			ipv = mergeVersion(ipv, int(sema.ClassifyAddr(strings.SplitN(ir.SrcRange, "-", 2)[0])))
		}
		if ir.DstRange != "" {
			parts = append(parts, "--dst-range", ir.DstRange)
			ipv = mergeVersion(ipv, int(sema.ClassifyAddr(strings.SplitN(ir.DstRange, "-", 2)[0])))
		}
		frags = append(frags, strings.Join(parts, " "))
	}

	if mb.Length != nil {
		frags = append(frags, fmt.Sprintf("-m length --length %s", mb.Length.Length))
	}

	if mb.TTL != nil {
		t := mb.TTL
		switch {
		case t.Eq != nil:
			frags = append(frags, fmt.Sprintf("-m ttl --ttl-eq %d", *t.Eq))
		case t.Lt != nil:
			frags = append(frags, fmt.Sprintf("-m ttl --ttl-lt %d", *t.Lt))
		case t.Gt != nil:
			frags = append(frags, fmt.Sprintf("-m ttl --ttl-gt %d", *t.Gt))
		}
		ipv = mergeVersion(ipv, 4) // ttl is IPv4-only
	}

	if mb.HL != nil {
		h := mb.HL
		switch {
		case h.Eq != nil:
			frags = append(frags, fmt.Sprintf("-m hl --hl-eq %d", *h.Eq))
		case h.Lt != nil:
			frags = append(frags, fmt.Sprintf("-m hl --hl-lt %d", *h.Lt))
		case h.Gt != nil:
			frags = append(frags, fmt.Sprintf("-m hl --hl-gt %d", *h.Gt))
		}
		ipv = mergeVersion(ipv, 6) // hl is IPv6-only
	}

	if mb.PktType != nil {
		frags = append(frags, fmt.Sprintf("-m pkttype --pkt-type %s", strings.ToLower(mb.PktType.PktType)))
	}

	if mb.PhysDev != nil {
		pd := mb.PhysDev
		parts := []string{"-m physdev"}
		if pd.PhysDevIn != "" {
			parts = append(parts, "--physdev-in", pd.PhysDevIn)
		}
		if pd.PhysDevOut != "" {
			parts = append(parts, "--physdev-out", pd.PhysDevOut)
		}
		if pd.PhysDevIsIn {
			parts = append(parts, "--physdev-is-in")
		}
		if pd.PhysDevIsOut {
			parts = append(parts, "--physdev-is-out")
		}
		if pd.PhysDevIsBridged {
			parts = append(parts, "--physdev-is-bridged")
		}
		frags = append(frags, strings.Join(parts, " "))
	}

	// Phase 10 — match side of Phase 9 targets.
	if mb.DSCP != nil {
		parts := []string{"-m dscp"}
		if mb.DSCP.Neg {
			parts = append(parts, "!")
		}
		if mb.DSCP.DSCP != nil {
			parts = append(parts, "--dscp", fmt.Sprintf("%v", mb.DSCP.DSCP))
		} else {
			parts = append(parts, "--dscp-class", strings.ToUpper(mb.DSCP.DSCPClass))
		}
		frags = append(frags, strings.Join(parts, " "))
	}

	if mb.TOS != nil {
		parts := []string{"-m tos"}
		if mb.TOS.Neg {
			parts = append(parts, "!")
		}
		parts = append(parts, "--tos", fmt.Sprintf("%v", mb.TOS.TOS))
		frags = append(frags, strings.Join(parts, " "))
	}

	if mb.ECN != nil {
		parts := []string{"-m ecn"}
		if mb.ECN.TCPCWR {
			parts = append(parts, "--ecn-tcp-cwr")
		}
		if mb.ECN.TCPECE {
			parts = append(parts, "--ecn-tcp-ece")
		}
		if mb.ECN.IPECT != nil {
			parts = append(parts, "--ecn-ip-ect", fmt.Sprintf("%d", *mb.ECN.IPECT))
		}
		frags = append(frags, strings.Join(parts, " "))
	}

	// Phase 10 — metadata matches.
	if mb.Helper != nil {
		frags = append(frags, fmt.Sprintf("-m helper --helper %s", mb.Helper.Name))
	}

	if mb.Realm != nil {
		parts := []string{"-m realm"}
		if mb.Realm.Neg {
			parts = append(parts, "!")
		}
		parts = append(parts, "--realm", fmt.Sprintf("%v", mb.Realm.Realm))
		frags = append(frags, strings.Join(parts, " "))
	}

	if mb.Cluster != nil {
		c := mb.Cluster
		parts := []string{"-m cluster"}
		parts = append(parts, "--cluster-total-nodes", fmt.Sprintf("%d", c.TotalNodes))
		if c.LocalNode != 0 {
			parts = append(parts, "--cluster-local-node", fmt.Sprintf("%d", c.LocalNode))
		} else if len(c.LocalNodes) > 0 {
			nodes := make([]string, len(c.LocalNodes))
			for i, n := range c.LocalNodes {
				nodes[i] = fmt.Sprintf("%d", n)
			}
			parts = append(parts, "--cluster-local-nodemask", strings.Join(nodes, ","))
		}
		if c.HashSeed != 0 {
			parts = append(parts, "--cluster-hash-seed", fmt.Sprintf("%d", c.HashSeed))
		}
		frags = append(frags, strings.Join(parts, " "))
	}

	if mb.CPU != nil {
		frags = append(frags, fmt.Sprintf("-m cpu --cpu %d", mb.CPU.CPU))
	}

	if mb.DevGroup != nil {
		parts := []string{"-m devgroup"}
		if mb.DevGroup.SrcGroup != nil {
			parts = append(parts, "--src-group", fmt.Sprintf("%v", mb.DevGroup.SrcGroup))
		}
		if mb.DevGroup.DstGroup != nil {
			parts = append(parts, "--dst-group", fmt.Sprintf("%v", mb.DevGroup.DstGroup))
		}
		frags = append(frags, strings.Join(parts, " "))
	}

	if mb.RpFilter != nil {
		parts := []string{"-m rpfilter"}
		if mb.RpFilter.Loose {
			parts = append(parts, "--loose")
		}
		if mb.RpFilter.ValidMark {
			parts = append(parts, "--validmark")
		}
		if mb.RpFilter.AcceptLocal {
			parts = append(parts, "--accept-local")
		}
		if mb.RpFilter.Invert {
			parts = append(parts, "--invert")
		}
		frags = append(frags, strings.Join(parts, " "))
	}

	if mb.Quota != nil {
		frags = append(frags, fmt.Sprintf("-m quota --quota %d", mb.Quota.Quota))
	}

	if mb.ConnBytes != nil {
		cb := mb.ConnBytes
		parts := []string{"-m connbytes"}
		if cb.Neg {
			parts = append(parts, "!")
		}
		parts = append(parts,
			"--connbytes", cb.Connbytes,
			"--connbytes-dir", strings.ToLower(cb.ConnbytesDir),
			"--connbytes-mode", strings.ToLower(cb.Mode),
		)
		frags = append(frags, strings.Join(parts, " "))
	}

	if mb.ConnLabel != nil {
		parts := []string{"-m connlabel"}
		if mb.ConnLabel.Neg {
			parts = append(parts, "!")
		}
		parts = append(parts, "--label", fmt.Sprintf("%v", mb.ConnLabel.Label))
		if mb.ConnLabel.Set {
			parts = append(parts, "--set")
		}
		frags = append(frags, strings.Join(parts, " "))
	}

	if mb.Nfacct != nil {
		frags = append(frags, fmt.Sprintf("-m nfacct --nfacct-name %s", mb.Nfacct.Name))
	}

	// Phase 10 — structured matches.
	if mb.String != nil {
		s := mb.String
		parts := []string{"-m string"}
		parts = append(parts, "--algo", strings.ToLower(s.Algo))
		if s.From > 0 {
			parts = append(parts, "--from", fmt.Sprintf("%d", s.From))
		}
		if s.To > 0 {
			parts = append(parts, "--to", fmt.Sprintf("%d", s.To))
		}
		if s.ICase {
			parts = append(parts, "--icase")
		}
		if s.Neg {
			parts = append(parts, "!")
		}
		if s.String != "" {
			parts = append(parts, "--string", `"`+s.String+`"`)
		} else {
			parts = append(parts, "--hex-string", `"`+s.HexString+`"`)
		}
		frags = append(frags, strings.Join(parts, " "))
	}

	if mb.BPF != nil {
		if mb.BPF.Bytecode != "" {
			frags = append(frags, fmt.Sprintf("-m bpf --bytecode %q", mb.BPF.Bytecode))
		} else {
			frags = append(frags, fmt.Sprintf("-m bpf --object-pinned %s", mb.BPF.ObjectPinned))
		}
	}

	if mb.U32 != nil {
		parts := []string{"-m u32"}
		if mb.U32.Neg {
			parts = append(parts, "!")
		}
		parts = append(parts, "--u32", `"`+mb.U32.U32+`"`)
		frags = append(frags, strings.Join(parts, " "))
	}

	if mb.Statistic != nil {
		st := mb.Statistic
		parts := []string{"-m statistic"}
		parts = append(parts, "--mode", strings.ToLower(st.Mode))
		if strings.ToLower(st.Mode) == "random" {
			parts = append(parts, "--probability", fmt.Sprintf("%g", st.Probability))
		} else {
			parts = append(parts, "--every", fmt.Sprintf("%d", st.Every))
			if st.Packet != nil {
				parts = append(parts, "--packet", fmt.Sprintf("%d", *st.Packet))
			}
		}
		if st.Neg {
			parts = append(parts, "!")
		}
		frags = append(frags, strings.Join(parts, " "))
	}

	if mb.Policy != nil {
		p := mb.Policy
		parts := []string{"-m policy"}
		parts = append(parts, "--dir", strings.ToLower(p.Dir))
		parts = append(parts, "--pol", strings.ToLower(p.Policy))
		if p.Strict {
			parts = append(parts, "--strict")
		}
		for i, e := range p.Elements {
			if i > 0 {
				parts = append(parts, "--next")
			}
			if e.ReqID != 0 {
				parts = append(parts, "--reqid", fmt.Sprintf("%d", e.ReqID))
			}
			if e.SPI != "" {
				parts = append(parts, "--spi", e.SPI)
			}
			if e.Proto != "" {
				parts = append(parts, "--proto", strings.ToLower(e.Proto))
			}
			if e.Mode != "" {
				parts = append(parts, "--mode", strings.ToLower(e.Mode))
			}
			if e.TunnelSrc != "" {
				parts = append(parts, "--tunnel-src", e.TunnelSrc)
			}
			if e.TunnelDst != "" {
				parts = append(parts, "--tunnel-dst", e.TunnelDst)
			}
		}
		frags = append(frags, strings.Join(parts, " "))
	}

	// Phase 10 — IPv6 extension header matches (IPv6-only).
	if mb.IPv6Header != nil {
		h := mb.IPv6Header
		parts := []string{"-m ipv6header"}
		if h.Neg {
			parts = append(parts, "!")
		}
		headers := make([]string, len(h.Header))
		for i, name := range h.Header {
			headers[i] = strings.ToLower(name)
		}
		parts = append(parts, "--header", strings.Join(headers, ","))
		if h.Soft {
			parts = append(parts, "--soft")
		}
		frags = append(frags, strings.Join(parts, " "))
		ipv = mergeVersion(ipv, 6)
	}

	if mb.Frag != nil {
		f := mb.Frag
		parts := []string{"-m frag"}
		if f.ID != "" {
			parts = append(parts, "--fragid", f.ID)
		}
		if f.FragRes {
			parts = append(parts, "--fragres")
		}
		if f.First {
			parts = append(parts, "--fragfirst")
		}
		if f.More {
			parts = append(parts, "--fragmore")
		}
		if f.Last {
			parts = append(parts, "--fraglast")
		}
		frags = append(frags, strings.Join(parts, " "))
		ipv = mergeVersion(ipv, 6)
	}

	if mb.HBH != nil {
		h := mb.HBH
		parts := []string{"-m hbh"}
		if h.Neg {
			parts = append(parts, "!")
		}
		if h.Length > 0 {
			parts = append(parts, "--hbh-len", fmt.Sprintf("%d", h.Length))
		}
		if h.Opts != "" {
			parts = append(parts, "--hbh-opts", h.Opts)
		}
		frags = append(frags, strings.Join(parts, " "))
		ipv = mergeVersion(ipv, 6)
	}

	if mb.DstOpts != nil {
		d := mb.DstOpts
		parts := []string{"-m dst"}
		if d.Neg {
			parts = append(parts, "!")
		}
		if d.Length > 0 {
			parts = append(parts, "--dst-len", fmt.Sprintf("%d", d.Length))
		}
		if d.Opts != "" {
			parts = append(parts, "--dst-opts", d.Opts)
		}
		frags = append(frags, strings.Join(parts, " "))
		ipv = mergeVersion(ipv, 6)
	}

	if mb.Rt != nil {
		r := mb.Rt
		parts := []string{"-m rt"}
		if r.Type != nil {
			parts = append(parts, "--rt-type", fmt.Sprintf("%d", *r.Type))
		}
		if r.Segsleft != "" {
			parts = append(parts, "--rt-segsleft", r.Segsleft)
		}
		if r.Length > 0 {
			parts = append(parts, "--rt-len", fmt.Sprintf("%d", r.Length))
		}
		if r.Reserve {
			parts = append(parts, "--rt-0-res")
		}
		if r.Addrs != "" {
			parts = append(parts, "--rt-0-addrs", r.Addrs)
		}
		if r.NotStrict {
			parts = append(parts, "--rt-0-not-strict")
		}
		frags = append(frags, strings.Join(parts, " "))
		ipv = mergeVersion(ipv, 6)
	}

	if mb.MH != nil {
		parts := []string{"-m mh"}
		if mb.MH.Neg {
			parts = append(parts, "!")
		}
		parts = append(parts, "--mh-type", mb.MH.Type)
		frags = append(frags, strings.Join(parts, " "))
		ipv = mergeVersion(ipv, 6)
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
