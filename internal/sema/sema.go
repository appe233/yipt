package sema

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/appe233/yipt/internal/ast"
)

var validIfaceRe = regexp.MustCompile(`^[a-zA-Z0-9\-\.+]+$`)

// validJumpTargets is the set of built-in iptables jump targets.
var validJumpTargets = map[string]bool{
	"accept":     true,
	"drop":       true,
	"reject":     true,
	"return":     true,
	"log":        true,
	"mark":       true,
	"tproxy":     true,
	"masquerade": true,
	"snat":       true,
	"dnat":       true,
	"redirect":   true,
	"ct":         true,
	"tcpmss":     true,
	"connmark":   true,
	"nflog":      true,
	"nfqueue":    true,
	"set":        true,
	// Phase 9 — packet-modification targets.
	"classify":    true,
	"dscp":        true,
	"tos":         true,
	"ecn":         true,
	"ttl":         true,
	"hl":          true,
	"secmark":     true,
	"connsecmark": true,
	"synproxy":    true,
	"tee":         true,
	"trace":       true,
	"audit":       true,
	"checksum":    true,
	"netmap":      true,
	"clusterip":   true,
	"idletimer":   true,
	"rateest":     true,
	"led":         true,
}

// validTCPFlags is the set of flag names accepted in tcp-flags mask/comp.
var validTCPFlags = map[string]bool{
	"SYN": true, "ACK": true, "FIN": true, "RST": true,
	"URG": true, "PSH": true, "ALL": true, "NONE": true,
}

// validCTEvents is the set of valid event types for CT --ctevents.
var validCTEvents = map[string]bool{
	"new": true, "related": true, "destroy": true, "reply": true,
	"assured": true, "protoinfo": true, "helper": true, "mark": true,
	"natseqinfo": true, "secmark": true,
}

var validHelperRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// validRejectWith is the set of valid reject-with values.
var validRejectWith = map[string]bool{
	"icmp-net-unreachable":       true,
	"icmp-host-unreachable":      true,
	"icmp-port-unreachable":      true,
	"icmp-proto-unreachable":     true,
	"icmp-net-prohibited":        true,
	"icmp-host-prohibited":       true,
	"icmp-admin-prohibited":      true,
	"tcp-reset":                  true,
	"icmp6-no-route":             true,
	"no-route":                   true,
	"icmp6-adm-prohibited":       true,
	"adm-prohibited":             true,
	"icmp6-addr-unreachable":     true,
	"addr-unreach":               true,
	"icmp6-port-unreachable":     true,
}

// validProtocols is the set of valid protocol values for iptables.
var validProtocols = map[string]bool{
	"tcp": true, "udp": true, "icmp": true, "ipv6-icmp": true,
	"sctp": true, "dccp": true, "udplite": true,
	"gre": true, "esp": true, "ah": true, "all": true,
}

var validMarkRe = regexp.MustCompile(`^(0x[0-9a-fA-F]+(/0x[0-9a-fA-F]+)?|\d+)$`)
var portRangeRe = regexp.MustCompile(`^\d+:\d+$`)
var validMACRe = regexp.MustCompile(`^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$`)
var validTimeRe = regexp.MustCompile(`^\d{2}:\d{2}$`)

// validDateTimeRe matches the ISO 8601 subset iptables' time module expects:
// "YYYY-MM-DDThh:mm:ss" — the T separator and seconds are both required.
var validDateTimeRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$`)
var validRateRe = regexp.MustCompile(`^\d+/(second|sec|s|minute|min|m|hour|h|day|d)$`)

var validHashlimitModes = map[string]bool{
	"srcip":   true,
	"dstip":   true,
	"srcport": true,
	"dstport": true,
}

var validAddrTypes = map[string]bool{
	"UNSPEC": true, "UNICAST": true, "LOCAL": true, "BROADCAST": true,
	"ANYCAST": true, "MULTICAST": true, "BLACKHOLE": true, "UNREACHABLE": true,
	"PROHIBIT": true,
}

var validPktTypes = map[string]bool{
	"unicast": true, "broadcast": true, "multicast": true,
}

// ownerMatchChains lists the chains where the owner match is valid.
// iptables only maintains a socket context in locally-originating chains.
var ownerMatchChains = map[string]bool{
	"OUTPUT": true, "POSTROUTING": true,
}

var lengthRangeRe = regexp.MustCompile(`^\d+:\d+$`)

// validCTStates enumerates the conntrack --ctstate values iptables accepts.
// Kernels vary, but these are the long-stable set.
var validCTStates = map[string]bool{
	"INVALID": true, "NEW": true, "ESTABLISHED": true, "RELATED": true,
	"UNTRACKED": true, "SNAT": true, "DNAT": true,
}

// validCTStatusFlags enumerates the conntrack --ctstatus values.
var validCTStatusFlags = map[string]bool{
	"NONE": true, "EXPECTED": true, "SEEN_REPLY": true,
	"ASSURED": true, "CONFIRMED": true,
}

// validCTDirs enumerates --ctdir values.
var validCTDirs = map[string]bool{
	"ORIGINAL": true, "REPLY": true,
}

var validWeekdays = map[string]bool{
	"Mon": true, "Tue": true, "Wed": true, "Thu": true,
	"Fri": true, "Sat": true, "Sun": true,
}

// validDSCPClasses enumerates the symbolic DSCP class names iptables accepts
// for --set-dscp-class. Numeric values are handled separately via --set-dscp.
var validDSCPClasses = map[string]bool{
	"BE": true, "CS0": true, "CS1": true, "CS2": true, "CS3": true,
	"CS4": true, "CS5": true, "CS6": true, "CS7": true,
	"AF11": true, "AF12": true, "AF13": true,
	"AF21": true, "AF22": true, "AF23": true,
	"AF31": true, "AF32": true, "AF33": true,
	"AF41": true, "AF42": true, "AF43": true,
	"EF":      true,
	"VOICE-ADMIT": true,
}

// validAuditTypes enumerates --audit-type values for the AUDIT target.
var validAuditTypes = map[string]bool{
	"accept": true, "drop": true, "reject": true,
}

// validClusterIPHashmodes enumerates --hashmode values for CLUSTERIP.
var validClusterIPHashmodes = map[string]bool{
	"sourceip": true,
	"sourceip-sourceport": true,
	"sourceip-sourceport-destport": true,
}

// validClassifyClassRe matches --set-class "MAJOR:MINOR" values (hex or decimal).
var validClassifyClassRe = regexp.MustCompile(`^[0-9a-fA-F]+:[0-9a-fA-F]+$`)

// setTypeInfo describes an ipset storage type.
// hasAddress marks types that carry IP addresses (and therefore participate in
// IPv4/IPv6 family splitting). dimensions is the comma-separated tuple arity used
// to validate the default --match-set direction list.
type setTypeInfo struct {
	dimensions int
	hasAddress bool
}

// setTypes enumerates the ipset storage types that yipt recognizes.
// Types that are not listed here are rejected at validation time.
var setTypes = map[string]setTypeInfo{
	"hash:net":          {dimensions: 1, hasAddress: true},
	"hash:ip":           {dimensions: 1, hasAddress: true},
	"hash:ip,port":      {dimensions: 2, hasAddress: true},
	"hash:net,port":     {dimensions: 2, hasAddress: true},
	"hash:ip,port,ip":   {dimensions: 3, hasAddress: true},
	"hash:ip,port,net":  {dimensions: 3, hasAddress: true},
	"hash:net,port,net": {dimensions: 3, hasAddress: true},
	"hash:mac":          {dimensions: 1, hasAddress: false},
	"hash:net,iface":    {dimensions: 2, hasAddress: true},
	"hash:ip,mark":      {dimensions: 2, hasAddress: true},
	"bitmap:ip":         {dimensions: 1, hasAddress: true},
	"bitmap:ip,mac":     {dimensions: 2, hasAddress: true},
	"bitmap:port":       {dimensions: 1, hasAddress: false},
	"list:set":          {dimensions: 1, hasAddress: false},
}

// defaultSetType is used when a resource declares type: ipset without set-type.
const defaultSetType = "hash:net"

// ipsetElemPortRe matches the "port" or "proto:port" portion of a hash:*,port element.
// Examples: "80", "tcp:80", "udp:1024".
var ipsetElemPortRe = regexp.MustCompile(`^(?:(tcp|udp|sctp|udplite|dccp|icmp|icmpv6):)?(\d+|\d+-\d+)$`)

// natTargetChainConstraints maps jump targets with placement restrictions to their
// allowed (tables, chain) combinations. Most targets live in exactly one table,
// but SECMARK/CONNSECMARK are valid in both the mangle and security tables.
var natTargetChainConstraints = map[string]struct {
	tables map[string]bool
	chains map[string]bool
}{
	"SNAT":       {tables: setOf("nat"), chains: map[string]bool{"POSTROUTING": true, "INPUT": true}},
	"DNAT":       {tables: setOf("nat"), chains: map[string]bool{"PREROUTING": true, "INPUT": true, "OUTPUT": true}},
	"MASQUERADE": {tables: setOf("nat"), chains: map[string]bool{"POSTROUTING": true}},
	"REDIRECT":   {tables: setOf("nat"), chains: map[string]bool{"PREROUTING": true, "OUTPUT": true}},
	"TPROXY":     {tables: setOf("mangle"), chains: map[string]bool{"PREROUTING": true}},
	"CT":         {tables: setOf("raw"), chains: map[string]bool{"PREROUTING": true, "OUTPUT": true}},
	"TCPMSS":     {tables: setOf("mangle"), chains: map[string]bool{"PREROUTING": true, "INPUT": true, "FORWARD": true, "OUTPUT": true, "POSTROUTING": true}},
	// Phase 9 — targets with strict table/chain placement.
	"CLASSIFY":    {tables: setOf("mangle"), chains: map[string]bool{"PREROUTING": true, "INPUT": true, "FORWARD": true, "OUTPUT": true, "POSTROUTING": true}},
	"DSCP":        {tables: setOf("mangle"), chains: map[string]bool{"PREROUTING": true, "INPUT": true, "FORWARD": true, "OUTPUT": true, "POSTROUTING": true}},
	"TOS":         {tables: setOf("mangle"), chains: map[string]bool{"PREROUTING": true, "INPUT": true, "FORWARD": true, "OUTPUT": true, "POSTROUTING": true}},
	"ECN":         {tables: setOf("mangle"), chains: map[string]bool{"PREROUTING": true}},
	"TTL":         {tables: setOf("mangle"), chains: map[string]bool{"PREROUTING": true, "INPUT": true, "FORWARD": true, "OUTPUT": true, "POSTROUTING": true}},
	"HL":          {tables: setOf("mangle"), chains: map[string]bool{"PREROUTING": true, "INPUT": true, "FORWARD": true, "OUTPUT": true, "POSTROUTING": true}},
	"CHECKSUM":    {tables: setOf("mangle"), chains: map[string]bool{"PREROUTING": true, "INPUT": true, "FORWARD": true, "OUTPUT": true, "POSTROUTING": true}},
	"NETMAP":      {tables: setOf("nat"), chains: map[string]bool{"PREROUTING": true, "POSTROUTING": true, "OUTPUT": true}},
	"CLUSTERIP":   {tables: setOf("mangle"), chains: map[string]bool{"PREROUTING": true}},
	"TRACE":       {tables: setOf("raw"), chains: map[string]bool{"PREROUTING": true, "OUTPUT": true}},
	"RATEEST":     {tables: setOf("mangle"), chains: map[string]bool{"PREROUTING": true, "INPUT": true, "FORWARD": true, "OUTPUT": true, "POSTROUTING": true}},
	"AUDIT":       {tables: setOf("filter"), chains: map[string]bool{"INPUT": true, "FORWARD": true, "OUTPUT": true}},
	"SECMARK":     {tables: setOf("mangle", "security"), chains: map[string]bool{"PREROUTING": true, "INPUT": true, "FORWARD": true, "OUTPUT": true, "POSTROUTING": true}},
	"CONNSECMARK": {tables: setOf("mangle", "security"), chains: map[string]bool{"PREROUTING": true, "INPUT": true, "FORWARD": true, "OUTPUT": true, "POSTROUTING": true}},
}

// setOf builds a string-keyed set in one expression.
func setOf(values ...string) map[string]bool {
	m := make(map[string]bool, len(values))
	for _, v := range values {
		m[v] = true
	}
	return m
}

// Resolved holds the analyzed document with classified resources.
type Resolved struct {
	Doc       *ast.Document
	Resources map[string]*ResolvedResource
	Warnings  []string
}

// ResolvedResource is a resource with classification applied.
type ResolvedResource struct {
	Name         string
	Type         string
	Elements     []interface{}
	IPv4Elements []string // for ipset resources (address-bearing)
	IPv6Elements []string // for ipset resources (address-bearing)
	IsMixed      bool     // true if ipset has both v4 and v6 elements
	// ipset-specific classification.
	SetType    string          // storage type, defaulted to "hash:net" for ipset
	SetOptions *ast.SetOptions // creation attributes (may be nil)
	Dimensions int             // number of comma-separated tuple fields (1 for hash:net, 2 for hash:ip,port, ...)
	HasAddress bool            // true if elements carry an IP address (hash:net, hash:ip, hash:*,port, bitmap:ip, ...)
	Family     string          // "inet" or "inet6" — for non-address-bearing sets and overrides
}

// Analyze validates the document and returns a Resolved representation.
func Analyze(doc *ast.Document) (*Resolved, error) {
	res := &Resolved{
		Doc:       doc,
		Resources: make(map[string]*ResolvedResource),
	}

	// Step 1: build resource table.
	for name, r := range doc.Resources {
		rr := &ResolvedResource{
			Name:     name,
			Type:     r.Type,
			Elements: r.Elements,
		}
		if r.Type == "ipset" {
			if err := resolveIpset(name, r, rr); err != nil {
				return nil, err
			}
		} else if r.SetType != "" || r.SetOptions != nil {
			return nil, fmt.Errorf("resource %q: set-type and set-options are only valid on type: ipset", name)
		}
		res.Resources[name] = rr
	}

	// Step 2: validate all chain rules.
	chainNames := make(map[string]bool, len(doc.Chains))
	for name := range doc.Chains {
		chainNames[name] = true
	}
	for chainName, chain := range doc.Chains {
		// Warn if policy is set on a non-built-in chain.
		if chain.Policy != "" && !isBuiltinChain(chainName) {
			res.Warnings = append(res.Warnings, fmt.Sprintf("warning: policy %q on chain %q has no effect (only built-in chains support policies)", chain.Policy, chainName))
		}
		if err := validateRules(chainName, "filter", chain.Filter, res.Resources, chainNames); err != nil {
			return nil, err
		}
		if err := validateRules(chainName, "mangle", chain.Mangle, res.Resources, chainNames); err != nil {
			return nil, err
		}
		if err := validateRules(chainName, "nat", chain.Nat, res.Resources, chainNames); err != nil {
			return nil, err
		}
		if err := validateRules(chainName, "raw", chain.Raw, res.Resources, chainNames); err != nil {
			return nil, err
		}
		if err := validateRules(chainName, "security", chain.Security, res.Resources, chainNames); err != nil {
			return nil, err
		}
	}

	// Step 3: warn about unused resources.
	used := collectUsedRefs(doc)
	for _, name := range sortedKeys(doc.Resources) {
		if !used[name] {
			res.Warnings = append(res.Warnings, fmt.Sprintf("warning: resource \"$%s\" is defined but never used", name))
		}
	}

	return res, nil
}

// resolveIpset fills in SetType, SetOptions, Dimensions, HasAddress, Family and
// per-family element lists for an ipset resource.
func resolveIpset(name string, r ast.Resource, rr *ResolvedResource) error {
	setType := strings.ToLower(strings.TrimSpace(r.SetType))
	if setType == "" {
		setType = defaultSetType
	}
	info, ok := setTypes[setType]
	if !ok {
		return fmt.Errorf("ipset %q: unknown set-type %q", name, setType)
	}
	rr.SetType = setType
	rr.SetOptions = r.SetOptions
	rr.Dimensions = info.dimensions
	rr.HasAddress = info.hasAddress

	if err := validateSetOptions(name, setType, r.SetOptions); err != nil {
		return err
	}

	family := ""
	if r.SetOptions != nil {
		family = strings.ToLower(strings.TrimSpace(r.SetOptions.Family))
		if family != "" && family != "inet" && family != "inet6" {
			return fmt.Errorf("ipset %q: family %q must be \"inet\" or \"inet6\"", name, family)
		}
	}

	// Resolve family for non-address-bearing types (default inet).
	if !info.hasAddress {
		if family == "" {
			family = "inet"
		}
		rr.Family = family
	}

	for _, elem := range r.Elements {
		s, ok := elem.(string)
		if !ok {
			// Some element types (bitmap:port, list:set) commonly use ints or bare names.
			s = fmt.Sprintf("%v", elem)
		}
		ver, err := classifyIpsetElement(setType, s)
		if err != nil {
			return fmt.Errorf("ipset %q: %w", name, err)
		}
		if info.hasAddress {
			switch ver {
			case IPv4Only:
				rr.IPv4Elements = append(rr.IPv4Elements, s)
			case IPv6Only:
				rr.IPv6Elements = append(rr.IPv6Elements, s)
			default:
				return fmt.Errorf("ipset %q: cannot classify element %q for set-type %q", name, s, setType)
			}
		} else {
			// Non-address-bearing types have a single family bucket; IR handles
			// these by consulting rr.Family and treating elements as opaque.
			if rr.Family == "inet6" {
				rr.IPv6Elements = append(rr.IPv6Elements, s)
			} else {
				rr.IPv4Elements = append(rr.IPv4Elements, s)
			}
		}
	}

	// Address-bearing: resolve family from element classification, reconciling
	// with any explicit override.
	if info.hasAddress {
		if len(rr.IPv4Elements) > 0 && len(rr.IPv6Elements) > 0 {
			rr.IsMixed = true
		} else if len(rr.IPv4Elements) > 0 {
			rr.Family = "inet"
		} else if len(rr.IPv6Elements) > 0 {
			rr.Family = "inet6"
		}
		if family != "" {
			if rr.IsMixed {
				return fmt.Errorf("ipset %q: explicit family %q conflicts with mixed IPv4/IPv6 elements", name, family)
			}
			if rr.Family != "" && rr.Family != family {
				return fmt.Errorf("ipset %q: explicit family %q conflicts with element family %q", name, family, rr.Family)
			}
			rr.Family = family
		}
	}
	return nil
}

// validateSetOptions rejects creation attributes that are incompatible with the
// declared set-type (e.g. range on hash:*, netmask on list:set).
func validateSetOptions(name, setType string, opts *ast.SetOptions) error {
	if opts == nil {
		return nil
	}
	if opts.Timeout != nil && *opts.Timeout < 0 {
		return fmt.Errorf("ipset %q: timeout %d must be non-negative", name, *opts.Timeout)
	}
	if opts.HashSize < 0 {
		return fmt.Errorf("ipset %q: hashsize %d must be non-negative", name, opts.HashSize)
	}
	if opts.MaxElem < 0 {
		return fmt.Errorf("ipset %q: maxelem %d must be non-negative", name, opts.MaxElem)
	}
	if opts.NetMask != 0 {
		switch setType {
		case "hash:ip", "hash:ip,port", "hash:ip,port,ip", "hash:ip,port,net", "hash:ip,mark":
			// ok
		default:
			return fmt.Errorf("ipset %q: netmask is only valid for hash:ip family types, not %s", name, setType)
		}
		if opts.NetMask < 1 || opts.NetMask > 128 {
			return fmt.Errorf("ipset %q: netmask %d is outside valid range 1-128", name, opts.NetMask)
		}
	}
	if opts.MarkMask != "" {
		if setType != "hash:ip,mark" {
			return fmt.Errorf("ipset %q: markmask is only valid for hash:ip,mark, not %s", name, setType)
		}
		if !validMarkRe.MatchString(opts.MarkMask) {
			return fmt.Errorf("ipset %q: markmask %q is not a valid mark value", name, opts.MarkMask)
		}
	}
	if opts.Range != "" {
		if !strings.HasPrefix(setType, "bitmap:") {
			return fmt.Errorf("ipset %q: range is only valid for bitmap:* types, not %s", name, setType)
		}
	}
	if opts.HashSize != 0 && !strings.HasPrefix(setType, "hash:") {
		return fmt.Errorf("ipset %q: hashsize is only valid for hash:* types, not %s", name, setType)
	}
	return nil
}

// classifyIpsetElement parses one element of an ipset and returns its IP version
// (for address-bearing types). It also rejects elements whose shape does not
// match the declared set-type.
func classifyIpsetElement(setType, elem string) (IPVersion, error) {
	elem = strings.TrimSpace(elem)
	switch setType {
	case "hash:net":
		v := ClassifyAddr(elem)
		if v == IPvUnknown {
			return IPvUnknown, fmt.Errorf("hash:net element %q is not a valid IP or CIDR", elem)
		}
		return v, nil
	case "hash:ip":
		// hash:ip stores single IPs (not CIDRs). iptables ipset accepts ranges on
		// add but stores individual IPs; we accept an IP or a simple range "A-B".
		return classifyIPOrRange(setType, elem)
	case "hash:ip,port":
		return classifyTupleHead(setType, elem, 2, true)
	case "hash:net,port":
		return classifyTupleHead(setType, elem, 2, false)
	case "hash:ip,port,ip":
		return classifyTupleHead(setType, elem, 3, true)
	case "hash:ip,port,net":
		return classifyTupleHead(setType, elem, 3, true)
	case "hash:net,port,net":
		return classifyTupleHead(setType, elem, 3, false)
	case "hash:net,iface":
		return classifyTupleHead(setType, elem, 2, false)
	case "hash:ip,mark":
		return classifyTupleHead(setType, elem, 2, true)
	case "hash:mac":
		if !validMACRe.MatchString(elem) {
			return IPvUnknown, fmt.Errorf("hash:mac element %q is not a valid MAC address", elem)
		}
		return IPvUnknown, nil
	case "bitmap:ip":
		return classifyIPOrRange(setType, elem)
	case "bitmap:ip,mac":
		return classifyTupleHead(setType, elem, 2, true)
	case "bitmap:port":
		// ipset bitmap:port accepts port or "LO-HI" (using dash, not colon).
		if err := validateBitmapPortElement(elem); err != nil {
			return IPvUnknown, err
		}
		return IPvUnknown, nil
	case "list:set":
		if elem == "" {
			return IPvUnknown, fmt.Errorf("list:set element is empty")
		}
		return IPvUnknown, nil
	}
	return IPvUnknown, fmt.Errorf("unsupported set-type %q", setType)
}

// validateBitmapPortElement validates a bitmap:port element: a single port or
// a hyphenated range "LO-HI", each in 0-65535 with LO <= HI.
func validateBitmapPortElement(elem string) error {
	if strings.Contains(elem, "-") {
		parts := strings.SplitN(elem, "-", 2)
		lo, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
		hi, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err1 != nil || err2 != nil {
			return fmt.Errorf("bitmap:port element %q is not a valid port range", elem)
		}
		if lo < 0 || hi > 65535 {
			return fmt.Errorf("bitmap:port element %q has values outside 0-65535", elem)
		}
		if lo > hi {
			return fmt.Errorf("bitmap:port element %q has low > high", elem)
		}
		return nil
	}
	n, err := strconv.Atoi(elem)
	if err != nil {
		return fmt.Errorf("bitmap:port element %q is not a valid port", elem)
	}
	if n < 0 || n > 65535 {
		return fmt.Errorf("bitmap:port element %q is outside valid range 0-65535", elem)
	}
	return nil
}

// classifyIPOrRange handles bitmap:ip / hash:ip elements which may be a single IP
// (or CIDR for hash:ip) or a hyphenated range "A-B".
func classifyIPOrRange(setType, elem string) (IPVersion, error) {
	if strings.Contains(elem, "-") {
		parts := strings.SplitN(elem, "-", 2)
		aV := ClassifyAddr(strings.TrimSpace(parts[0]))
		bV := ClassifyAddr(strings.TrimSpace(parts[1]))
		if aV == IPvUnknown || bV == IPvUnknown {
			return IPvUnknown, fmt.Errorf("%s element %q contains invalid IP", setType, elem)
		}
		if aV != bV {
			return IPvUnknown, fmt.Errorf("%s element %q mixes IPv4 and IPv6", setType, elem)
		}
		return aV, nil
	}
	v := ClassifyAddr(elem)
	if v == IPvUnknown {
		return IPvUnknown, fmt.Errorf("%s element %q is not a valid IP or CIDR", setType, elem)
	}
	return v, nil
}

// classifyTupleHead validates the comma-separated tuple shape for multi-dim
// ipset elements. The first field is the IP/CIDR whose family is returned.
// wantFirstIP=true expects the first field to be a plain IP (hash:ip,*);
// wantFirstIP=false accepts a CIDR (hash:net,*).
func classifyTupleHead(setType, elem string, dims int, wantFirstIP bool) (IPVersion, error) {
	parts := strings.Split(elem, ",")
	if len(parts) != dims {
		return IPvUnknown, fmt.Errorf("%s element %q: expected %d comma-separated fields, got %d", setType, elem, dims, len(parts))
	}
	first := strings.TrimSpace(parts[0])
	v := ClassifyAddr(first)
	if v == IPvUnknown {
		return IPvUnknown, fmt.Errorf("%s element %q: first field %q is not a valid IP or CIDR", setType, elem, first)
	}
	if wantFirstIP && strings.Contains(first, "/") {
		return IPvUnknown, fmt.Errorf("%s element %q: first field must be a plain IP, not a CIDR", setType, elem)
	}
	// Second field: port for *,port* types, iface for net,iface, mark for ip,mark, MAC for ip,mac.
	second := strings.TrimSpace(parts[1])
	switch setType {
	case "hash:ip,port", "hash:net,port", "hash:ip,port,ip", "hash:ip,port,net", "hash:net,port,net":
		if !ipsetElemPortRe.MatchString(second) {
			return IPvUnknown, fmt.Errorf("%s element %q: port field %q must be PORT, PROTO:PORT, or LO-HI", setType, elem, second)
		}
	case "hash:net,iface":
		if err := validateInterfaceName("ipset", "iface", second); err != nil {
			return IPvUnknown, fmt.Errorf("%s element %q: invalid interface %q", setType, elem, second)
		}
	case "hash:ip,mark":
		if !validMarkRe.MatchString(second) {
			return IPvUnknown, fmt.Errorf("%s element %q: mark field %q is not a valid mark", setType, elem, second)
		}
	case "bitmap:ip,mac":
		if !validMACRe.MatchString(second) {
			return IPvUnknown, fmt.Errorf("%s element %q: MAC field %q is not a valid MAC", setType, elem, second)
		}
	}
	// Third field (for 3-dim types): IP or CIDR, must agree on family.
	if dims == 3 {
		third := strings.TrimSpace(parts[2])
		tv := ClassifyAddr(third)
		if tv == IPvUnknown {
			return IPvUnknown, fmt.Errorf("%s element %q: third field %q is not a valid IP or CIDR", setType, elem, third)
		}
		if tv != v {
			return IPvUnknown, fmt.Errorf("%s element %q: IP family mismatch between field 1 and field 3", setType, elem)
		}
		switch setType {
		case "hash:ip,port,ip":
			if strings.Contains(third, "/") {
				return IPvUnknown, fmt.Errorf("%s element %q: third field must be a plain IP, not a CIDR", setType, elem)
			}
		}
	}
	return v, nil
}

// ParseSetRef parses a reference of the form "$name" or "$name[dir,dir]".
// Returns ok=false when val is not a set ref at all.
// Returns an error when the ref is malformed.
func ParseSetRef(val string) (name string, dirs []string, ok bool, err error) {
	return parseSetRef(val)
}

// parseSetRef is the internal implementation.
func parseSetRef(val string) (name string, dirs []string, ok bool, err error) {
	if !strings.HasPrefix(val, "$") {
		return "", nil, false, nil
	}
	rest := val[1:]
	lb := strings.Index(rest, "[")
	if lb == -1 {
		return rest, nil, true, nil
	}
	if !strings.HasSuffix(rest, "]") {
		return "", nil, true, fmt.Errorf("malformed set reference %q: expected closing ]", val)
	}
	name = rest[:lb]
	dirStr := rest[lb+1 : len(rest)-1]
	if dirStr == "" {
		return "", nil, true, fmt.Errorf("malformed set reference %q: empty direction list", val)
	}
	for _, d := range strings.Split(dirStr, ",") {
		dirs = append(dirs, strings.ToLower(strings.TrimSpace(d)))
	}
	return name, dirs, true, nil
}

func validateRules(chainName, table string, rules []ast.Rule, resources map[string]*ResolvedResource, chainNames map[string]bool) error {
	for i, rule := range rules {
		ctx := fmt.Sprintf("chain %s/%s rule %d", chainName, table, i+1)
		if err := validateAddrRef(ctx, "s", rule.Src, resources); err != nil {
			return err
		}
		if err := validateAddrRef(ctx, "s!", rule.SrcNeg, resources); err != nil {
			return err
		}
		if err := validateAddrRef(ctx, "d", rule.Dst, resources); err != nil {
			return err
		}
		if err := validateAddrRef(ctx, "d!", rule.DstNeg, resources); err != nil {
			return err
		}
		if err := validatePortRef(ctx, "dp", rule.DPort, resources); err != nil {
			return err
		}
		if err := validatePortRef(ctx, "sp", rule.SPort, resources); err != nil {
			return err
		}
		if err := validatePortRef(ctx, "dp!", rule.DPortNeg, resources); err != nil {
			return err
		}
		if err := validatePortRef(ctx, "sp!", rule.SPortNeg, resources); err != nil {
			return err
		}
		if err := validateICMPRef(ctx, "icmp-type", rule.ICMPType, "icmp_typeset", resources); err != nil {
			return err
		}
		if err := validateICMPRef(ctx, "icmpv6-type", rule.ICMPv6Type, "icmpv6_typeset", resources); err != nil {
			return err
		}
		if len(rule.LogPrefix) > 29 {
			return fmt.Errorf("%s: log-prefix %q exceeds 29-character limit", ctx, rule.LogPrefix)
		}
		if len(rule.Comment) > 256 {
			return fmt.Errorf("%s: comment exceeds 256-character limit", ctx)
		}
		// Validate string fields for unsafe characters.
		if err := validateStringField(ctx, "log-prefix", rule.LogPrefix); err != nil {
			return err
		}
		if err := validateStringField(ctx, "comment", rule.Comment); err != nil {
			return err
		}
		// Validate interface names.
		if err := validateInterfaceName(ctx, "i", rule.In); err != nil {
			return err
		}
		if err := validateInterfaceName(ctx, "i!", rule.InNeg); err != nil {
			return err
		}
		if err := validateInterfaceName(ctx, "o", rule.Out); err != nil {
			return err
		}
		if err := validateInterfaceName(ctx, "o!", rule.OutNeg); err != nil {
			return err
		}
		// Validate address values.
		if err := validateAddrValue(ctx, "s", rule.Src); err != nil {
			return err
		}
		if err := validateAddrValue(ctx, "s!", rule.SrcNeg); err != nil {
			return err
		}
		if err := validateAddrValue(ctx, "d", rule.Dst); err != nil {
			return err
		}
		if err := validateAddrValue(ctx, "d!", rule.DstNeg); err != nil {
			return err
		}
		// Validate port values.
		if err := validatePortValue(ctx, "sp", rule.SPort); err != nil {
			return err
		}
		if err := validatePortValue(ctx, "sp!", rule.SPortNeg); err != nil {
			return err
		}
		if err := validatePortValue(ctx, "dp", rule.DPort); err != nil {
			return err
		}
		if err := validatePortValue(ctx, "dp!", rule.DPortNeg); err != nil {
			return err
		}
		// Validate jump target.
		if err := validateJumpTarget(ctx, table, chainName, rule, chainNames); err != nil {
			return err
		}
		// Validate protocol values.
		if err := validateProtocol(ctx, rule.Proto); err != nil {
			return err
		}
		// Validate reject-with.
		if err := validateRejectWith(ctx, rule); err != nil {
			return err
		}
		// Validate NAT address fields.
		if err := validateNATAddr(ctx, "to-source", rule.ToSource); err != nil {
			return err
		}
		if err := validateNATAddr(ctx, "to-destination", rule.ToDest); err != nil {
			return err
		}
		// Validate to-ports.
		if err := validateToPorts(ctx, rule.ToPorts); err != nil {
			return err
		}
		// Validate mark values.
		if err := validateMarkValue(ctx, "set-mark", rule.SetMark); err != nil {
			return err
		}
		if err := validateMarkValue(ctx, "tproxy-mark", rule.TProxyMark); err != nil {
			return err
		}
		// Validate port range strings.
		if err := validatePortRangeString(ctx, "sp", rule.SPort); err != nil {
			return err
		}
		if err := validatePortRangeString(ctx, "sp!", rule.SPortNeg); err != nil {
			return err
		}
		if err := validatePortRangeString(ctx, "dp", rule.DPort); err != nil {
			return err
		}
		if err := validatePortRangeString(ctx, "dp!", rule.DPortNeg); err != nil {
			return err
		}
		// Validate match module fields.
		for i, mb := range rule.Match {
			mctx := ctx
			if len(rule.Match) > 1 {
				mctx = fmt.Sprintf("%s match[%d]", ctx, i)
			}
			if err := validateMatchBlock(mctx, chainName, mb); err != nil {
				return err
			}
		}
		// Validate CT target fields.
		if err := validateCTTarget(ctx, rule); err != nil {
			return err
		}
		// Validate CONNMARK target fields.
		if err := validateConnmarkTarget(ctx, rule); err != nil {
			return err
		}
		// Validate NFLOG / NFQUEUE / SET targets.
		if err := validateNflogTarget(ctx, rule); err != nil {
			return err
		}
		if err := validateNfqueueTarget(ctx, rule); err != nil {
			return err
		}
		if err := validateSETTarget(ctx, rule, resources); err != nil {
			return err
		}
		// Validate TCPMSS target + tcp-flags / tcp-option / fragment.
		if err := validateTCPMSS(ctx, rule); err != nil {
			return err
		}
		if err := validateTCPFlags(ctx, rule); err != nil {
			return err
		}
		if err := validateTCPOption(ctx, rule); err != nil {
			return err
		}
		if err := validateFragment(ctx, rule); err != nil {
			return err
		}
		// Phase 9 — packet-modification targets.
		if err := validatePhase9Targets(ctx, rule); err != nil {
			return err
		}
		if err := validateConflicts(ctx, rule); err != nil {
			return err
		}
	}
	return nil
}

// requireTCPProto returns an error if the rule has an explicit non-TCP protocol.
// Empty protocol is permissive (iptables will reject at runtime).
func requireTCPProto(ctx, field string, proto interface{}) error {
	protos := collectProtos(proto)
	if len(protos) == 0 {
		return nil
	}
	for _, p := range protos {
		if strings.ToLower(p) == "tcp" {
			return nil
		}
	}
	return fmt.Errorf("%s: %s requires p: tcp", ctx, field)
}

// validateTCPMSS validates the TCPMSS target options (set-mss, clamp-mss-to-pmtu).
func validateTCPMSS(ctx string, rule ast.Rule) error {
	hasSetMSS := rule.SetMSS != 0
	hasClamp := rule.ClampMSSToPMTU
	isTCPMSS := strings.ToLower(rule.Jump) == "tcpmss"

	if (hasSetMSS || hasClamp) && !isTCPMSS {
		return fmt.Errorf("%s: set-mss/clamp-mss-to-pmtu are only valid with j: tcpmss", ctx)
	}
	if !isTCPMSS {
		return nil
	}
	if hasSetMSS && hasClamp {
		return fmt.Errorf("%s: set-mss and clamp-mss-to-pmtu are mutually exclusive", ctx)
	}
	if !hasSetMSS && !hasClamp {
		return fmt.Errorf("%s: j: tcpmss requires set-mss or clamp-mss-to-pmtu", ctx)
	}
	if hasSetMSS && (rule.SetMSS < 1 || rule.SetMSS > 65535) {
		return fmt.Errorf("%s: set-mss %d is outside valid range 1-65535", ctx, rule.SetMSS)
	}
	return requireTCPProto(ctx, "j: tcpmss", rule.Proto)
}

// validateTCPFlags validates the tcp-flags rule field.
func validateTCPFlags(ctx string, rule ast.Rule) error {
	if rule.TCPFlags == nil {
		return nil
	}
	if len(rule.TCPFlags.Mask) == 0 {
		return fmt.Errorf("%s: tcp-flags mask cannot be empty", ctx)
	}
	if len(rule.TCPFlags.Comp) == 0 {
		return fmt.Errorf("%s: tcp-flags comp cannot be empty (use [NONE] for no flags)", ctx)
	}
	for _, f := range rule.TCPFlags.Mask {
		if !validTCPFlags[strings.ToUpper(f)] {
			return fmt.Errorf("%s: unknown tcp flag %q in tcp-flags mask", ctx, f)
		}
	}
	for _, f := range rule.TCPFlags.Comp {
		if !validTCPFlags[strings.ToUpper(f)] {
			return fmt.Errorf("%s: unknown tcp flag %q in tcp-flags comp", ctx, f)
		}
	}
	return requireTCPProto(ctx, "tcp-flags", rule.Proto)
}

// validateTCPOption validates the tcp-option rule field.
func validateTCPOption(ctx string, rule ast.Rule) error {
	if rule.TCPOption == 0 {
		return nil
	}
	if rule.TCPOption < 1 || rule.TCPOption > 255 {
		return fmt.Errorf("%s: tcp-option %d is outside valid range 1-255", ctx, rule.TCPOption)
	}
	return requireTCPProto(ctx, "tcp-option", rule.Proto)
}

// validateFragment validates the fragment rule field (IPv4 only).
// iptables rejects -f when combined with ipv6-icmp or IPv6 addresses.
func validateFragment(ctx string, rule ast.Rule) error {
	if !rule.Fragment {
		return nil
	}
	for _, p := range collectProtos(rule.Proto) {
		if strings.ToLower(p) == "ipv6-icmp" {
			return fmt.Errorf("%s: fragment (-f) is not valid with p: ipv6-icmp (IPv4 only)", ctx)
		}
	}
	if addrFieldVersion(rule.Src, rule.SrcNeg) == 6 || addrFieldVersion(rule.Dst, rule.DstNeg) == 6 {
		return fmt.Errorf("%s: fragment (-f) is not valid with IPv6 addresses (IPv4 only)", ctx)
	}
	return nil
}

// validateCTTarget validates the CT target options (zone, helper, ctevents, ctmask, nfmask, notrack).
// CT-specific fields are only meaningful with j: ct.
// ctmask/nfmask are shared with j: connmark (validated there for placement).
func validateCTTarget(ctx string, rule ast.Rule) error {
	j := strings.ToLower(rule.Jump)
	hasCTOnlyField := rule.Notrack || rule.Zone != 0 || rule.Helper != "" || len(rule.CTEvents) > 0
	hasMaskField := rule.CTMask != nil || rule.NfMask != nil

	if hasCTOnlyField && j != "ct" {
		return fmt.Errorf("%s: notrack/zone/helper/ctevents are only valid with j: ct", ctx)
	}
	if hasMaskField && j != "ct" && j != "connmark" {
		return fmt.Errorf("%s: ctmask/nfmask are only valid with j: ct or j: connmark", ctx)
	}
	if j == "ct" && !hasCTOnlyField && !hasMaskField {
		return fmt.Errorf("%s: j: ct requires at least one of notrack, zone, helper, ctevents, ctmask, nfmask", ctx)
	}
	if rule.Zone < 0 || rule.Zone > 65535 {
		return fmt.Errorf("%s: zone %d is outside valid range 0-65535", ctx, rule.Zone)
	}
	if rule.Helper != "" && !validHelperRe.MatchString(rule.Helper) {
		return fmt.Errorf("%s: helper %q contains invalid characters (expected alphanumeric, underscore, or dash)", ctx, rule.Helper)
	}
	for _, ev := range rule.CTEvents {
		if !validCTEvents[strings.ToLower(ev)] {
			return fmt.Errorf("%s: unknown ctevent %q", ctx, ev)
		}
	}
	if err := validateMarkValue(ctx, "ctmask", rule.CTMask); err != nil {
		return err
	}
	if err := validateMarkValue(ctx, "nfmask", rule.NfMask); err != nil {
		return err
	}
	// Notrack with other options: conservative error.
	if rule.Notrack && (rule.Zone != 0 || rule.Helper != "" ||
		len(rule.CTEvents) > 0 || rule.CTMask != nil || rule.NfMask != nil) {
		return fmt.Errorf("%s: notrack cannot combine with zone/helper/ctevents/ctmask/nfmask", ctx)
	}
	return nil
}

// validateConnmarkTarget validates the CONNMARK target options.
// save-mark and restore-mark are only valid with j: connmark.
// Exactly one of set-mark / save-mark / restore-mark must be set.
// nfmask/ctmask can only combine with save-mark or restore-mark, not set-mark.
func validateConnmarkTarget(ctx string, rule ast.Rule) error {
	isConnmark := strings.ToLower(rule.Jump) == "connmark"
	hasSave := rule.SaveMark
	hasRestore := rule.RestoreMark

	if (hasSave || hasRestore) && !isConnmark {
		return fmt.Errorf("%s: save-mark/restore-mark are only valid with j: connmark", ctx)
	}
	if !isConnmark {
		return nil
	}
	hasSet := rule.SetMark != nil
	opts := 0
	if hasSet {
		opts++
	}
	if hasSave {
		opts++
	}
	if hasRestore {
		opts++
	}
	if opts == 0 {
		return fmt.Errorf("%s: j: connmark requires one of set-mark, save-mark, restore-mark", ctx)
	}
	if opts > 1 {
		return fmt.Errorf("%s: set-mark, save-mark, restore-mark are mutually exclusive in j: connmark", ctx)
	}
	if hasSet && (rule.CTMask != nil || rule.NfMask != nil) {
		return fmt.Errorf("%s: nfmask/ctmask cannot combine with set-mark in j: connmark", ctx)
	}
	return nil
}

// validSETFlags is the set of valid direction flags for the SET target.
var validSETFlags = map[string]bool{
	"src": true, "dst": true,
}

// validateNflogTarget validates the NFLOG target options.
// nflog-* fields are only meaningful with j: nflog.
func validateNflogTarget(ctx string, rule ast.Rule) error {
	hasField := rule.NflogGroup != 0 || rule.NflogPrefix != "" ||
		rule.NflogRange != 0 || rule.NflogThreshold != 0
	isNflog := strings.ToLower(rule.Jump) == "nflog"

	if hasField && !isNflog {
		return fmt.Errorf("%s: nflog-group/nflog-prefix/nflog-range/nflog-threshold are only valid with j: nflog", ctx)
	}
	if !isNflog {
		return nil
	}
	if rule.NflogGroup < 0 || rule.NflogGroup > 65535 {
		return fmt.Errorf("%s: nflog-group %d is outside valid range 0-65535", ctx, rule.NflogGroup)
	}
	if rule.NflogRange < 0 {
		return fmt.Errorf("%s: nflog-range %d must be non-negative", ctx, rule.NflogRange)
	}
	if rule.NflogThreshold < 0 {
		return fmt.Errorf("%s: nflog-threshold %d must be non-negative", ctx, rule.NflogThreshold)
	}
	if len(rule.NflogPrefix) > 64 {
		return fmt.Errorf("%s: nflog-prefix %q exceeds 64-character limit", ctx, rule.NflogPrefix)
	}
	return validateStringField(ctx, "nflog-prefix", rule.NflogPrefix)
}

// validateNfqueueTarget validates the NFQUEUE target options.
// Exactly one of queue-num or queue-balance must be set when j: nfqueue.
// queue-balance is of the form "N:M" with 0 <= N <= M <= 65535.
func validateNfqueueTarget(ctx string, rule ast.Rule) error {
	hasQueueField := rule.QueueNumSet || rule.QueueBalance != "" ||
		rule.QueueBypass || rule.QueueCPUFanout
	isNfqueue := strings.ToLower(rule.Jump) == "nfqueue"

	if hasQueueField && !isNfqueue {
		return fmt.Errorf("%s: queue-num/queue-balance/queue-bypass/queue-cpu-fanout are only valid with j: nfqueue", ctx)
	}
	if !isNfqueue {
		return nil
	}
	if rule.QueueNumSet && rule.QueueBalance != "" {
		return fmt.Errorf("%s: queue-num and queue-balance are mutually exclusive", ctx)
	}
	if rule.QueueNumSet && (rule.QueueNum < 0 || rule.QueueNum > 65535) {
		return fmt.Errorf("%s: queue-num %d is outside valid range 0-65535", ctx, rule.QueueNum)
	}
	if rule.QueueBalance != "" {
		parts := strings.SplitN(rule.QueueBalance, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("%s: queue-balance %q must be of the form N:M", ctx, rule.QueueBalance)
		}
		lo, err1 := strconv.Atoi(parts[0])
		hi, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			return fmt.Errorf("%s: queue-balance %q is not a valid range", ctx, rule.QueueBalance)
		}
		if lo < 0 || hi > 65535 {
			return fmt.Errorf("%s: queue-balance %q has values outside 0-65535", ctx, rule.QueueBalance)
		}
		if lo > hi {
			return fmt.Errorf("%s: queue-balance %q has low > high", ctx, rule.QueueBalance)
		}
	}
	return nil
}

// validateSETTarget validates the SET target options.
// Exactly one of add-set or del-set must be set when j: set.
// The named set must reference an existing ipset resource.
// Mixed ipsets are rejected (SET target can only write to one family's set).
// set-exist and set-timeout are only meaningful with add-set.
// set-flags must be in {src, dst}.
func validateSETTarget(ctx string, rule ast.Rule, resources map[string]*ResolvedResource) error {
	hasAdd := rule.AddSet != ""
	hasDel := rule.DelSet != ""
	hasSetField := hasAdd || hasDel || len(rule.SetFlags) > 0 ||
		rule.SetExist || rule.SetTimeout != 0
	isSET := strings.ToLower(rule.Jump) == "set"

	if hasSetField && !isSET {
		return fmt.Errorf("%s: add-set/del-set/set-flags/set-exist/set-timeout are only valid with j: set", ctx)
	}
	if !isSET {
		return nil
	}
	if !hasAdd && !hasDel {
		return fmt.Errorf("%s: j: set requires add-set or del-set", ctx)
	}
	if hasAdd && hasDel {
		return fmt.Errorf("%s: add-set and del-set are mutually exclusive", ctx)
	}
	if hasDel && (rule.SetExist || rule.SetTimeout != 0) {
		return fmt.Errorf("%s: set-exist and set-timeout only apply to add-set", ctx)
	}
	if rule.SetTimeout < 0 {
		return fmt.Errorf("%s: set-timeout %d must be non-negative", ctx, rule.SetTimeout)
	}
	if len(rule.SetFlags) == 0 {
		return fmt.Errorf("%s: j: set requires set-flags (e.g. [src] or [src,dst])", ctx)
	}
	for _, f := range rule.SetFlags {
		if !validSETFlags[strings.ToLower(f)] {
			return fmt.Errorf("%s: unknown set-flag %q (expected src or dst)", ctx, f)
		}
	}
	// Resolve ipset reference.
	name := rule.AddSet
	if hasDel {
		name = rule.DelSet
	}
	rr, ok := resources[name]
	if !ok {
		return fmt.Errorf("%s: unknown ipset %q referenced by j: set", ctx, name)
	}
	if rr.Type != "ipset" {
		return fmt.Errorf("%s: resource %q is %s, expected ipset", ctx, name, rr.Type)
	}
	if rr.IsMixed {
		return fmt.Errorf("%s: ipset %q is mixed IPv4/IPv6; j: set requires a single-family set", ctx, name)
	}
	return nil
}

// isBuiltinChain returns true if the chain name is a built-in chain in any table.
func isBuiltinChain(name string) bool {
	builtins := map[string]bool{
		"INPUT": true, "FORWARD": true, "OUTPUT": true,
		"PREROUTING": true, "POSTROUTING": true,
	}
	return builtins[name]
}

// validateJumpTarget validates the j: field against known targets and user-defined chains,
// and enforces NAT target/table/chain constraints.
func validateJumpTarget(ctx, table, chainName string, rule ast.Rule, chainNames map[string]bool) error {
	j := strings.ToLower(rule.Jump)
	if j == "" {
		return nil
	}
	if !validJumpTargets[j] && !chainNames[rule.Jump] {
		return fmt.Errorf("%s: unknown jump target %q (not a built-in target or user-defined chain)", ctx, rule.Jump)
	}
	// Validate NAT target placement.
	jUpper := strings.ToUpper(j)
	if constraint, ok := natTargetChainConstraints[jUpper]; ok {
		if !constraint.tables[table] {
			allowedTables := make([]string, 0, len(constraint.tables))
			for t := range constraint.tables {
				allowedTables = append(allowedTables, t)
			}
			sort.Strings(allowedTables)
			if len(allowedTables) == 1 {
				return fmt.Errorf("%s: target %s is only valid in the %s table, not %s", ctx, jUpper, allowedTables[0], table)
			}
			return fmt.Errorf("%s: target %s is only valid in the %s tables, not %s", ctx, jUpper, strings.Join(allowedTables, " or "), table)
		}
		// Only enforce chain constraints on built-in chains; user-defined chains
		// may be called from a valid built-in chain.
		if isBuiltinChain(chainName) && !constraint.chains[chainName] {
			allowed := make([]string, 0, len(constraint.chains))
			for c := range constraint.chains {
				allowed = append(allowed, c)
			}
			sort.Strings(allowed)
			return fmt.Errorf("%s: target %s is only valid in chains %s, not %s", ctx, jUpper, strings.Join(allowed, ", "), chainName)
		}
	}
	return nil
}

// validateProtocol validates protocol values against known protocols.
func validateProtocol(ctx string, proto interface{}) error {
	if proto == nil {
		return nil
	}
	switch p := proto.(type) {
	case string:
		if !validProtocols[strings.ToLower(p)] {
			return fmt.Errorf("%s: unknown protocol %q", ctx, p)
		}
	case []interface{}:
		for _, v := range p {
			if s, ok := v.(string); ok {
				if !validProtocols[strings.ToLower(s)] {
					return fmt.Errorf("%s: unknown protocol %q", ctx, s)
				}
			}
		}
	}
	return nil
}

// validateRejectWith validates the reject-with field.
func validateRejectWith(ctx string, rule ast.Rule) error {
	if rule.RejectWith == "" {
		return nil
	}
	if strings.ToLower(rule.Jump) != "reject" {
		return fmt.Errorf("%s: reject-with is only valid with j: reject", ctx)
	}
	if !validRejectWith[rule.RejectWith] {
		return fmt.Errorf("%s: unknown reject-with value %q", ctx, rule.RejectWith)
	}
	if rule.RejectWith == "tcp-reset" {
		protos := collectProtos(rule.Proto)
		if len(protos) > 0 {
			hasTCP := false
			for _, p := range protos {
				if strings.ToLower(p) == "tcp" {
					hasTCP = true
					break
				}
			}
			if !hasTCP {
				return fmt.Errorf("%s: reject-with tcp-reset requires p: tcp", ctx)
			}
		}
	}
	return nil
}

// validateNATAddr validates to-source / to-destination address fields.
// Format: IP, IP:port, IP:port-port, IP-IP, IP-IP:port-port
func validateNATAddr(ctx, field, val string) error {
	if val == "" {
		return nil
	}
	// Strip port suffix (after last colon if it looks like addr:port).
	addr := val
	if idx := strings.LastIndex(val, ":"); idx != -1 {
		candidate := val[:idx]
		// Only treat as addr:port if candidate parses as IP or has brackets for IPv6.
		if net.ParseIP(candidate) != nil || strings.Contains(candidate, "-") && net.ParseIP(strings.Split(candidate, "-")[0]) != nil {
			addr = candidate
		}
	}
	// Handle IP ranges (IP-IP).
	if strings.Contains(addr, "-") {
		parts := strings.SplitN(addr, "-", 2)
		if net.ParseIP(parts[0]) == nil {
			return fmt.Errorf("%s field %s: %q contains invalid IP address %q", ctx, field, val, parts[0])
		}
		if net.ParseIP(parts[1]) == nil {
			return fmt.Errorf("%s field %s: %q contains invalid IP address %q", ctx, field, val, parts[1])
		}
		return nil
	}
	if net.ParseIP(addr) == nil {
		return fmt.Errorf("%s field %s: %q is not a valid address", ctx, field, val)
	}
	return nil
}

// validateToPorts validates the to-ports field (single port or port range).
func validateToPorts(ctx, val string) error {
	if val == "" {
		return nil
	}
	return validatePortRangeStr(ctx, "to-ports", val)
}

// validateMarkValue validates set-mark and tproxy-mark values.
func validateMarkValue(ctx, field string, val interface{}) error {
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case int:
		return nil // integers are always valid
	case string:
		if !validMarkRe.MatchString(v) {
			return fmt.Errorf("%s field %s: %q is not a valid mark value (expected integer or hex like 0xff or 0xff/0xff)", ctx, field, v)
		}
	default:
		return fmt.Errorf("%s field %s: unexpected type %T", ctx, field, val)
	}
	return nil
}

// validatePortRangeString validates string port values that look like ranges (e.g. "1024:65535").
func validatePortRangeString(ctx, field string, val interface{}) error {
	s, ok := val.(string)
	if !ok {
		return nil
	}
	if strings.HasPrefix(s, "$") {
		return nil // resource reference, validated elsewhere
	}
	return validatePortRangeStr(ctx, field, s)
}

// validatePortRangeStr validates a port or port range string.
func validatePortRangeStr(ctx, field, s string) error {
	if portRangeRe.MatchString(s) {
		parts := strings.SplitN(s, ":", 2)
		low, err1 := strconv.Atoi(parts[0])
		high, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			return fmt.Errorf("%s field %s: %q is not a valid port range", ctx, field, s)
		}
		if low < 0 || low > 65535 || high < 0 || high > 65535 {
			return fmt.Errorf("%s field %s: port range %q has values outside 0-65535", ctx, field, s)
		}
		if low > high {
			return fmt.Errorf("%s field %s: port range %q has low > high", ctx, field, s)
		}
		return nil
	}
	// Single port as string.
	port, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("%s field %s: %q is not a valid port number or range", ctx, field, s)
	}
	if port < 0 || port > 65535 {
		return fmt.Errorf("%s field %s: port %d is outside valid range 0-65535", ctx, field, port)
	}
	return nil
}

// validateMatchBlock validates match module sub-fields.
func validateMatchBlock(ctx, chainName string, mb *ast.MatchBlock) error {
	if mb == nil {
		return nil
	}
	if mb.MAC != nil && mb.MAC.MACSource != "" {
		if !validMACRe.MatchString(mb.MAC.MACSource) {
			return fmt.Errorf("%s: mac-source %q is not a valid MAC address", ctx, mb.MAC.MACSource)
		}
	}
	if mb.Time != nil {
		if err := validateTimeMatch(ctx, mb.Time); err != nil {
			return err
		}
	}
	if mb.AddrType != nil {
		if err := validateAddrTypeMatch(ctx, mb.AddrType); err != nil {
			return err
		}
	}
	if mb.Connmark != nil {
		if mb.Connmark.Mark == nil {
			return fmt.Errorf("%s: connmark match requires mark", ctx)
		}
		if err := validateMarkValue(ctx, "connmark.mark", mb.Connmark.Mark); err != nil {
			return err
		}
	}
	if mb.Connlimit != nil {
		if err := validateConnlimitMatch(ctx, mb.Connlimit); err != nil {
			return err
		}
	}
	if mb.Hashlimit != nil {
		if err := validateHashlimitMatch(ctx, mb.Hashlimit); err != nil {
			return err
		}
	}
	if mb.Owner != nil {
		if err := validateOwnerMatch(ctx, chainName, mb.Owner); err != nil {
			return err
		}
	}
	if mb.IPRange != nil {
		if err := validateIPRangeMatch(ctx, mb.IPRange); err != nil {
			return err
		}
	}
	if mb.Length != nil {
		if err := validateLengthMatch(ctx, mb.Length); err != nil {
			return err
		}
	}
	if mb.TTL != nil {
		if err := validateTTLMatch(ctx, mb.TTL); err != nil {
			return err
		}
	}
	if mb.HL != nil {
		if err := validateHLMatch(ctx, mb.HL); err != nil {
			return err
		}
	}
	if mb.PktType != nil {
		if err := validatePktTypeMatch(ctx, mb.PktType); err != nil {
			return err
		}
	}
	if mb.PhysDev != nil {
		if err := validatePhysDevMatch(ctx, mb.PhysDev); err != nil {
			return err
		}
	}
	if mb.Conntrack != nil {
		if err := validateConntrackMatch(ctx, mb.Conntrack); err != nil {
			return err
		}
	}
	if mb.Recent != nil {
		if err := validateRecentMatch(ctx, mb.Recent); err != nil {
			return err
		}
	}
	// Phase 10 — match-side versions of Phase 9 target fields.
	if mb.DSCP != nil {
		if err := validateDSCPMatch(ctx, mb.DSCP); err != nil {
			return err
		}
	}
	if mb.TOS != nil {
		if err := validateTOSMatch(ctx, mb.TOS); err != nil {
			return err
		}
	}
	if mb.ECN != nil {
		if err := validateECNMatch(ctx, mb.ECN); err != nil {
			return err
		}
	}
	// Phase 10 — metadata matches.
	if mb.Helper != nil {
		if err := validateHelperMatch(ctx, mb.Helper); err != nil {
			return err
		}
	}
	if mb.Realm != nil {
		if err := validateRealmMatch(ctx, mb.Realm); err != nil {
			return err
		}
	}
	if mb.Cluster != nil {
		if err := validateClusterMatch(ctx, mb.Cluster); err != nil {
			return err
		}
	}
	if mb.CPU != nil {
		if err := validateCPUMatch(ctx, mb.CPU); err != nil {
			return err
		}
	}
	if mb.DevGroup != nil {
		if err := validateDevGroupMatch(ctx, mb.DevGroup); err != nil {
			return err
		}
	}
	if mb.RpFilter != nil {
		if err := validateRpFilterMatch(ctx, mb.RpFilter); err != nil {
			return err
		}
	}
	if mb.Quota != nil {
		if err := validateQuotaMatch(ctx, mb.Quota); err != nil {
			return err
		}
	}
	if mb.ConnBytes != nil {
		if err := validateConnBytesMatch(ctx, mb.ConnBytes); err != nil {
			return err
		}
	}
	if mb.ConnLabel != nil {
		if err := validateConnLabelMatch(ctx, mb.ConnLabel); err != nil {
			return err
		}
	}
	if mb.Nfacct != nil {
		if err := validateNfacctMatch(ctx, mb.Nfacct); err != nil {
			return err
		}
	}
	// Phase 10 — structured matches.
	if mb.String != nil {
		if err := validateStringMatch(ctx, mb.String); err != nil {
			return err
		}
	}
	if mb.BPF != nil {
		if err := validateBPFMatch(ctx, mb.BPF); err != nil {
			return err
		}
	}
	if mb.U32 != nil {
		if err := validateU32Match(ctx, mb.U32); err != nil {
			return err
		}
	}
	if mb.Statistic != nil {
		if err := validateStatisticMatch(ctx, mb.Statistic); err != nil {
			return err
		}
	}
	if mb.Policy != nil {
		if err := validatePolicyMatch(ctx, mb.Policy); err != nil {
			return err
		}
	}
	// Phase 10 — IPv6 extension headers.
	if mb.IPv6Header != nil {
		if err := validateIPv6HeaderMatch(ctx, mb.IPv6Header); err != nil {
			return err
		}
	}
	if mb.Frag != nil {
		if err := validateFragMatch(ctx, mb.Frag); err != nil {
			return err
		}
	}
	if mb.HBH != nil {
		if err := validateHBHMatch(ctx, mb.HBH); err != nil {
			return err
		}
	}
	if mb.DstOpts != nil {
		if err := validateDstOptsMatch(ctx, mb.DstOpts); err != nil {
			return err
		}
	}
	if mb.Rt != nil {
		if err := validateRtMatch(ctx, mb.Rt); err != nil {
			return err
		}
	}
	if mb.MH != nil {
		if err := validateMHMatch(ctx, mb.MH); err != nil {
			return err
		}
	}
	return nil
}

// validateRecentMatch validates the recent match module.
// Exactly one of set/update/rcheck/remove must be selected.
// rsource and rdest are mutually exclusive.
// reap requires seconds. mask must be a valid IP or CIDR.
func validateRecentMatch(ctx string, m *ast.RecentMatch) error {
	ops := 0
	if m.Set {
		ops++
	}
	if m.Update {
		ops++
	}
	if m.RCheck {
		ops++
	}
	if m.Remove {
		ops++
	}
	if ops > 1 {
		return fmt.Errorf("%s: recent match options set/update/rcheck/remove are mutually exclusive", ctx)
	}
	if m.RSource && m.RDest {
		return fmt.Errorf("%s: recent rsource and rdest are mutually exclusive", ctx)
	}
	if m.Seconds < 0 {
		return fmt.Errorf("%s: recent seconds %d must be non-negative", ctx, m.Seconds)
	}
	if m.HitCount < 0 {
		return fmt.Errorf("%s: recent hitcount %d must be non-negative", ctx, m.HitCount)
	}
	if m.Reap && m.Seconds == 0 {
		return fmt.Errorf("%s: recent reap requires seconds to be set", ctx)
	}
	if m.Name != "" {
		if err := validateStringField(ctx, "recent.name", m.Name); err != nil {
			return err
		}
	}
	if m.Mask != "" {
		if ClassifyAddr(m.Mask) == IPvUnknown {
			return fmt.Errorf("%s: recent mask %q is not a valid IP or CIDR", ctx, m.Mask)
		}
	}
	return nil
}

// validateConntrackMatch validates the conntrack match module's extended options.
// At least one ctstate/ctproto/ctorig*/ctrepl*/ctstatus/ctexpire/ctdir must be set
// (the caller has already confirmed the struct is non-nil).
func validateConntrackMatch(ctx string, m *ast.ConntrackMatch) error {
	if len(m.CTState) == 0 && m.CTProto == "" &&
		m.CTOrigSrc == "" && m.CTOrigDst == "" &&
		m.CTOrigSrcPort == "" && m.CTOrigDstPort == "" &&
		m.CTReplSrc == "" && m.CTReplDst == "" &&
		len(m.CTStatus) == 0 && m.CTExpire == "" && m.CTDir == "" {
		return fmt.Errorf("%s: conntrack match requires at least one field", ctx)
	}
	for _, s := range m.CTState {
		if !validCTStates[strings.ToUpper(s)] {
			return fmt.Errorf("%s: unknown conntrack ctstate %q", ctx, s)
		}
	}
	if m.CTProto != "" {
		if !validProtocols[strings.ToLower(m.CTProto)] {
			return fmt.Errorf("%s: unknown conntrack ctproto %q", ctx, m.CTProto)
		}
	}
	for _, f := range []struct{ field, val string }{
		{"ctorigsrc", m.CTOrigSrc}, {"ctorigdst", m.CTOrigDst},
		{"ctreplsrc", m.CTReplSrc}, {"ctrepldst", m.CTReplDst},
	} {
		if f.val != "" {
			if ClassifyAddr(f.val) == IPvUnknown {
				return fmt.Errorf("%s: conntrack %s %q is not a valid IP address or CIDR", ctx, f.field, f.val)
			}
		}
	}
	for _, f := range []struct{ field, val string }{
		{"ctorigsrcport", m.CTOrigSrcPort}, {"ctorigdstport", m.CTOrigDstPort},
	} {
		if f.val != "" {
			if err := validatePortRangeStr(ctx, f.field, f.val); err != nil {
				return err
			}
		}
	}
	for _, s := range m.CTStatus {
		if !validCTStatusFlags[strings.ToUpper(s)] {
			return fmt.Errorf("%s: unknown conntrack ctstatus %q", ctx, s)
		}
	}
	if m.CTExpire != "" {
		if err := validateExpireRange(ctx, m.CTExpire); err != nil {
			return err
		}
	}
	if m.CTDir != "" && !validCTDirs[strings.ToUpper(m.CTDir)] {
		return fmt.Errorf("%s: unknown conntrack ctdir %q (expected ORIGINAL or REPLY)", ctx, m.CTDir)
	}
	return nil
}

// validateExpireRange parses a conntrack --ctexpire argument: a non-negative integer
// or "lo:hi" with lo <= hi.
func validateExpireRange(ctx, val string) error {
	if strings.Contains(val, ":") {
		parts := strings.SplitN(val, ":", 2)
		lo, err1 := strconv.Atoi(parts[0])
		hi, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			return fmt.Errorf("%s: conntrack ctexpire %q is not a valid range", ctx, val)
		}
		if lo < 0 || hi < 0 {
			return fmt.Errorf("%s: conntrack ctexpire %q contains negative values", ctx, val)
		}
		if lo > hi {
			return fmt.Errorf("%s: conntrack ctexpire %q has lo > hi", ctx, val)
		}
		return nil
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return fmt.Errorf("%s: conntrack ctexpire %q is not a valid number or range", ctx, val)
	}
	if n < 0 {
		return fmt.Errorf("%s: conntrack ctexpire %d must be non-negative", ctx, n)
	}
	return nil
}

// validateOwnerMatch validates the owner match module.
// Requires at least one field; UID/GID/PID/SID values must be non-negative.
// Only valid on chains that see locally-originating packets (OUTPUT, POSTROUTING,
// or user-defined chains — the latter must be reached from OUTPUT/POSTROUTING at
// runtime, so we only enforce placement for built-ins).
func validateOwnerMatch(ctx, chainName string, m *ast.OwnerMatch) error {
	if m.UIDOwner == nil && m.GIDOwner == nil && m.PIDOwner == nil &&
		m.SIDOwner == nil && m.CmdOwner == "" && !m.SocketExists {
		return fmt.Errorf("%s: owner match requires at least one of uid-owner, gid-owner, pid-owner, sid-owner, cmd-owner, socket-exists", ctx)
	}
	if isBuiltinChain(chainName) && !ownerMatchChains[chainName] {
		return fmt.Errorf("%s: owner match is only valid in OUTPUT or POSTROUTING chains (socket context is not tracked elsewhere)", ctx)
	}
	if m.UIDOwner != nil && *m.UIDOwner < 0 {
		return fmt.Errorf("%s: owner uid-owner %d must be non-negative", ctx, *m.UIDOwner)
	}
	if m.GIDOwner != nil && *m.GIDOwner < 0 {
		return fmt.Errorf("%s: owner gid-owner %d must be non-negative", ctx, *m.GIDOwner)
	}
	if m.PIDOwner != nil && *m.PIDOwner < 0 {
		return fmt.Errorf("%s: owner pid-owner %d must be non-negative", ctx, *m.PIDOwner)
	}
	if m.SIDOwner != nil && *m.SIDOwner < 0 {
		return fmt.Errorf("%s: owner sid-owner %d must be non-negative", ctx, *m.SIDOwner)
	}
	if m.CmdOwner != "" {
		if err := validateStringField(ctx, "cmd-owner", m.CmdOwner); err != nil {
			return err
		}
		if len(m.CmdOwner) > 15 {
			return fmt.Errorf("%s: owner cmd-owner %q exceeds 15-character kernel comm limit", ctx, m.CmdOwner)
		}
	}
	return nil
}

// validateIPRangeMatch validates the iprange match module.
// Each range must be "A-B" with A/B valid IPs of the same version and A <= B.
// src-range and dst-range must agree on IP version when both are set.
func validateIPRangeMatch(ctx string, m *ast.IPRangeMatch) error {
	if m.SrcRange == "" && m.DstRange == "" {
		return fmt.Errorf("%s: iprange match requires src-range or dst-range", ctx)
	}
	srcVer, err := validateIPRange(ctx, "src-range", m.SrcRange)
	if err != nil {
		return err
	}
	dstVer, err := validateIPRange(ctx, "dst-range", m.DstRange)
	if err != nil {
		return err
	}
	if srcVer != 0 && dstVer != 0 && srcVer != dstVer {
		return fmt.Errorf("%s: iprange src-range and dst-range must agree on IP version (got v%d and v%d)", ctx, srcVer, dstVer)
	}
	return nil
}

// validateIPRange parses "A-B" and returns the IP version (4 or 6) of the endpoints.
// Returns 0 if val is empty.
func validateIPRange(ctx, field, val string) (int, error) {
	if val == "" {
		return 0, nil
	}
	parts := strings.SplitN(val, "-", 2)
	if len(parts) != 2 {
		return 0, fmt.Errorf("%s field %s: %q must be of the form A-B", ctx, field, val)
	}
	lo := net.ParseIP(strings.TrimSpace(parts[0]))
	hi := net.ParseIP(strings.TrimSpace(parts[1]))
	if lo == nil {
		return 0, fmt.Errorf("%s field %s: %q contains invalid IP %q", ctx, field, val, parts[0])
	}
	if hi == nil {
		return 0, fmt.Errorf("%s field %s: %q contains invalid IP %q", ctx, field, val, parts[1])
	}
	loV := ipVersionOf(lo)
	hiV := ipVersionOf(hi)
	if loV != hiV {
		return 0, fmt.Errorf("%s field %s: %q mixes IPv4 and IPv6 endpoints", ctx, field, val)
	}
	// Compare canonical 16-byte representation for both families.
	if bytesCompareIP(lo, hi) > 0 {
		return 0, fmt.Errorf("%s field %s: %q has low > high", ctx, field, val)
	}
	return loV, nil
}

func ipVersionOf(ip net.IP) int {
	if ip.To4() != nil {
		return 4
	}
	return 6
}

// bytesCompareIP compares two net.IP values in their canonical 16-byte form.
// Returns -1, 0, or 1 the same way bytes.Compare does.
func bytesCompareIP(a, b net.IP) int {
	aa := a.To16()
	bb := b.To16()
	for i := range aa {
		if aa[i] < bb[i] {
			return -1
		}
		if aa[i] > bb[i] {
			return 1
		}
	}
	return 0
}

// validateLengthMatch validates the length match module.
// Value is "N" or "N:M" with 0 <= N <= M <= 65535.
func validateLengthMatch(ctx string, m *ast.LengthMatch) error {
	if m.Length == "" {
		return fmt.Errorf("%s: length match requires length", ctx)
	}
	if lengthRangeRe.MatchString(m.Length) {
		parts := strings.SplitN(m.Length, ":", 2)
		lo, err1 := strconv.Atoi(parts[0])
		hi, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			return fmt.Errorf("%s: length %q is not a valid range", ctx, m.Length)
		}
		if lo < 0 || hi > 65535 {
			return fmt.Errorf("%s: length range %q has values outside 0-65535", ctx, m.Length)
		}
		if lo > hi {
			return fmt.Errorf("%s: length range %q has low > high", ctx, m.Length)
		}
		return nil
	}
	n, err := strconv.Atoi(m.Length)
	if err != nil {
		return fmt.Errorf("%s: length %q is not a valid number or range", ctx, m.Length)
	}
	if n < 0 || n > 65535 {
		return fmt.Errorf("%s: length %d is outside valid range 0-65535", ctx, n)
	}
	return nil
}

// validateTTLOrHL validates a ttl/hl match: exactly one of eq/lt/gt, each in 0-255.
func validateTTLOrHL(ctx, module string, eq, lt, gt *int) error {
	opts := 0
	if eq != nil {
		opts++
	}
	if lt != nil {
		opts++
	}
	if gt != nil {
		opts++
	}
	if opts == 0 {
		return fmt.Errorf("%s: %s match requires exactly one of eq, lt, gt", ctx, module)
	}
	if opts > 1 {
		return fmt.Errorf("%s: %s eq/lt/gt are mutually exclusive", ctx, module)
	}
	for _, v := range []*int{eq, lt, gt} {
		if v == nil {
			continue
		}
		if *v < 0 || *v > 255 {
			return fmt.Errorf("%s: %s value %d is outside valid range 0-255", ctx, module, *v)
		}
	}
	return nil
}

func validateTTLMatch(ctx string, m *ast.TTLMatch) error {
	return validateTTLOrHL(ctx, "ttl", m.Eq, m.Lt, m.Gt)
}

func validateHLMatch(ctx string, m *ast.HLMatch) error {
	return validateTTLOrHL(ctx, "hl", m.Eq, m.Lt, m.Gt)
}

// validateTimeMatch validates the time match module.
// timestart/timestop are HH:MM. datestart/datestop are ISO 8601 date-times.
// monthdays is a comma-separated list of 1..31. utc and kerneltz are mutually
// exclusive.
func validateTimeMatch(ctx string, m *ast.TimeMatch) error {
	if m.TimeStart != "" && !validTimeRe.MatchString(m.TimeStart) {
		return fmt.Errorf("%s: timestart %q is not a valid time (expected HH:MM)", ctx, m.TimeStart)
	}
	if m.TimeStop != "" && !validTimeRe.MatchString(m.TimeStop) {
		return fmt.Errorf("%s: timestop %q is not a valid time (expected HH:MM)", ctx, m.TimeStop)
	}
	if m.Days != "" {
		if err := validateWeekdays(ctx, m.Days); err != nil {
			return err
		}
	}
	if m.DateStart != "" && !validDateTimeRe.MatchString(m.DateStart) {
		return fmt.Errorf("%s: datestart %q is not a valid datetime (expected YYYY-MM-DDThh:mm:ss)", ctx, m.DateStart)
	}
	if m.DateStop != "" && !validDateTimeRe.MatchString(m.DateStop) {
		return fmt.Errorf("%s: datestop %q is not a valid datetime (expected YYYY-MM-DDThh:mm:ss)", ctx, m.DateStop)
	}
	if m.MonthDays != "" {
		for _, d := range strings.Split(m.MonthDays, ",") {
			d = strings.TrimSpace(d)
			n, err := strconv.Atoi(d)
			if err != nil {
				return fmt.Errorf("%s: monthdays entry %q is not a valid number", ctx, d)
			}
			if n < 1 || n > 31 {
				return fmt.Errorf("%s: monthdays entry %d is outside valid range 1-31", ctx, n)
			}
		}
	}
	if m.UTC && m.KernelTZ {
		return fmt.Errorf("%s: time utc and kerneltz are mutually exclusive", ctx)
	}
	return nil
}

// validateAddrTypeMatch validates the addrtype match module.
// At least one of src-type/dst-type/limit-iface-in/limit-iface-out must be set.
// limit-iface-in and limit-iface-out are mutually exclusive.
func validateAddrTypeMatch(ctx string, m *ast.AddrTypeMatch) error {
	if m.SrcType == "" && m.DstType == "" && m.LimitIfaceIn == "" && m.LimitIfaceOut == "" {
		return fmt.Errorf("%s: addrtype match requires at least one of src-type, dst-type, limit-iface-in, limit-iface-out", ctx)
	}
	if m.SrcType != "" && !validAddrTypes[strings.ToUpper(m.SrcType)] {
		return fmt.Errorf("%s: unknown addrtype src-type %q", ctx, m.SrcType)
	}
	if m.DstType != "" && !validAddrTypes[strings.ToUpper(m.DstType)] {
		return fmt.Errorf("%s: unknown addrtype dst-type %q", ctx, m.DstType)
	}
	if m.LimitIfaceIn != "" && m.LimitIfaceOut != "" {
		return fmt.Errorf("%s: addrtype limit-iface-in and limit-iface-out are mutually exclusive", ctx)
	}
	if err := validateInterfaceName(ctx, "limit-iface-in", m.LimitIfaceIn); err != nil {
		return err
	}
	if err := validateInterfaceName(ctx, "limit-iface-out", m.LimitIfaceOut); err != nil {
		return err
	}
	return nil
}

// validatePktTypeMatch validates the pkttype match module.
func validatePktTypeMatch(ctx string, m *ast.PktTypeMatch) error {
	if m.PktType == "" {
		return fmt.Errorf("%s: pkttype match requires pkt-type", ctx)
	}
	if !validPktTypes[strings.ToLower(m.PktType)] {
		return fmt.Errorf("%s: unknown pkttype pkt-type %q (expected unicast, broadcast, or multicast)", ctx, m.PktType)
	}
	return nil
}

// validatePhysDevMatch validates the physdev match module.
// Requires at least one field; interface names follow Linux naming rules.
func validatePhysDevMatch(ctx string, m *ast.PhysDevMatch) error {
	if m.PhysDevIn == "" && m.PhysDevOut == "" &&
		!m.PhysDevIsIn && !m.PhysDevIsOut && !m.PhysDevIsBridged {
		return fmt.Errorf("%s: physdev match requires at least one of physdev-in, physdev-out, physdev-is-in, physdev-is-out, physdev-is-bridged", ctx)
	}
	if err := validateInterfaceName(ctx, "physdev-in", m.PhysDevIn); err != nil {
		return err
	}
	if err := validateInterfaceName(ctx, "physdev-out", m.PhysDevOut); err != nil {
		return err
	}
	return nil
}

// validateConnlimitMatch validates the connlimit match module.
// At least one of above/upto is required; above and upto are mutually exclusive.
// saddr and daddr are mutually exclusive. mask must be in 0-128.
func validateConnlimitMatch(ctx string, m *ast.ConnlimitMatch) error {
	if m.Above == nil && m.Upto == nil {
		return fmt.Errorf("%s: connlimit match requires above or upto", ctx)
	}
	if m.Above != nil && m.Upto != nil {
		return fmt.Errorf("%s: connlimit above and upto are mutually exclusive", ctx)
	}
	if m.Above != nil && *m.Above < 0 {
		return fmt.Errorf("%s: connlimit above %d must be non-negative", ctx, *m.Above)
	}
	if m.Upto != nil && *m.Upto < 0 {
		return fmt.Errorf("%s: connlimit upto %d must be non-negative", ctx, *m.Upto)
	}
	if m.Mask != nil {
		if *m.Mask < 0 || *m.Mask > 128 {
			return fmt.Errorf("%s: connlimit mask %d is outside valid range 0-128", ctx, *m.Mask)
		}
	}
	if m.SAddr && m.DAddr {
		return fmt.Errorf("%s: connlimit saddr and daddr are mutually exclusive", ctx)
	}
	return nil
}

// validateHashlimitMatch validates the hashlimit match module.
// name is required; exactly one of upto/above is required; rate strings must
// parse as "N/{second,minute,hour,day}"; mode entries must be in
// {srcip,dstip,srcport,dstport}; masks in 0-128; htable-* values positive.
func validateHashlimitMatch(ctx string, m *ast.HashlimitMatch) error {
	if m.Name == "" {
		return fmt.Errorf("%s: hashlimit match requires name", ctx)
	}
	if len(m.Name) > 32 {
		return fmt.Errorf("%s: hashlimit name %q exceeds 32-character limit", ctx, m.Name)
	}
	if m.Upto == "" && m.Above == "" {
		return fmt.Errorf("%s: hashlimit match requires upto or above", ctx)
	}
	if m.Upto != "" && m.Above != "" {
		return fmt.Errorf("%s: hashlimit upto and above are mutually exclusive", ctx)
	}
	if m.Upto != "" && !validRateRe.MatchString(m.Upto) {
		return fmt.Errorf("%s: hashlimit upto %q is not a valid rate (expected N/second|minute|hour|day)", ctx, m.Upto)
	}
	if m.Above != "" && !validRateRe.MatchString(m.Above) {
		return fmt.Errorf("%s: hashlimit above %q is not a valid rate (expected N/second|minute|hour|day)", ctx, m.Above)
	}
	if m.Burst < 0 {
		return fmt.Errorf("%s: hashlimit burst %d must be non-negative", ctx, m.Burst)
	}
	for _, mode := range m.Mode {
		if !validHashlimitModes[strings.ToLower(mode)] {
			return fmt.Errorf("%s: unknown hashlimit mode %q (expected srcip, dstip, srcport, or dstport)", ctx, mode)
		}
	}
	if m.SrcMask != nil && (*m.SrcMask < 0 || *m.SrcMask > 128) {
		return fmt.Errorf("%s: hashlimit srcmask %d is outside valid range 0-128", ctx, *m.SrcMask)
	}
	if m.DstMask != nil && (*m.DstMask < 0 || *m.DstMask > 128) {
		return fmt.Errorf("%s: hashlimit dstmask %d is outside valid range 0-128", ctx, *m.DstMask)
	}
	if m.HTableSize < 0 {
		return fmt.Errorf("%s: hashlimit htable-size %d must be non-negative", ctx, m.HTableSize)
	}
	if m.HTableMax < 0 {
		return fmt.Errorf("%s: hashlimit htable-max %d must be non-negative", ctx, m.HTableMax)
	}
	if m.HTableExpire < 0 {
		return fmt.Errorf("%s: hashlimit htable-expire %d must be non-negative", ctx, m.HTableExpire)
	}
	if m.HTableGCInterval < 0 {
		return fmt.Errorf("%s: hashlimit htable-gcinterval %d must be non-negative", ctx, m.HTableGCInterval)
	}
	return nil
}

// validateConflicts checks for semantically contradictory field combinations.
func validateConflicts(ctx string, rule ast.Rule) error {
	// Collect the set of explicit protocols from the p: field.
	protos := collectProtos(rule.Proto)

	hasPort := rule.SPort != nil || rule.DPort != nil || rule.SPortNeg != nil || rule.DPortNeg != nil

	// If any port field is set, protocol must include tcp or udp.
	if hasPort && len(protos) > 0 {
		hasPortProto := false
		for _, p := range protos {
			pl := strings.ToLower(p)
			if pl == "tcp" || pl == "udp" {
				hasPortProto = true
				break
			}
		}
		if !hasPortProto {
			return fmt.Errorf("%s: port match (sp/dp) requires p: tcp or udp, got %v", ctx, protos)
		}
	}

	// icmp-type requires p: icmp (when protocol is explicitly set).
	if rule.ICMPType != nil && len(protos) > 0 {
		hasICMP := false
		for _, p := range protos {
			if strings.ToLower(p) == "icmp" {
				hasICMP = true
				break
			}
		}
		if !hasICMP {
			return fmt.Errorf("%s: icmp-type requires p: icmp, got %v", ctx, protos)
		}
	}

	// icmpv6-type requires p: ipv6-icmp (when protocol is explicitly set).
	if rule.ICMPv6Type != nil && len(protos) > 0 {
		hasICMPv6 := false
		for _, p := range protos {
			if strings.ToLower(p) == "ipv6-icmp" {
				hasICMPv6 = true
				break
			}
		}
		if !hasICMPv6 {
			return fmt.Errorf("%s: icmpv6-type requires p: ipv6-icmp, got %v", ctx, protos)
		}
	}

	// icmp-type and icmpv6-type are mutually exclusive in a single rule.
	if rule.ICMPType != nil && rule.ICMPv6Type != nil {
		return fmt.Errorf("%s: icmp-type and icmpv6-type cannot both be set in one rule", ctx)
	}

	// Detect IP version contradiction between src and dst plain addresses.
	srcVer := addrFieldVersion(rule.Src, rule.SrcNeg)
	dstVer := addrFieldVersion(rule.Dst, rule.DstNeg)
	if srcVer != 0 && dstVer != 0 && srcVer != dstVer {
		return fmt.Errorf("%s: IPv4/IPv6 version conflict between s (%s) and d (%s)", ctx, addrStr(rule.Src, rule.SrcNeg), addrStr(rule.Dst, rule.DstNeg))
	}

	return nil
}

// collectProtos returns the list of protocol strings from a rule's Proto field.
// Returns nil if no protocol is set.
func collectProtos(proto interface{}) []string {
	if proto == nil {
		return nil
	}
	switch p := proto.(type) {
	case string:
		return []string{p}
	case []interface{}:
		var out []string
		for _, v := range p {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// addrFieldVersion returns the IP version (4 or 6) of a plain (non-set) address field,
// or 0 if the field is empty, a resource ref, or unclassifiable.
func addrFieldVersion(addr, addrNeg string) int {
	a := addr
	if a == "" {
		a = addrNeg
	}
	if a == "" || strings.HasPrefix(a, "$") {
		return 0
	}
	v := ClassifyAddr(a)
	if v == IPv4Only {
		return 4
	}
	if v == IPv6Only {
		return 6
	}
	return 0
}

func addrStr(addr, addrNeg string) string {
	if addr != "" {
		return addr
	}
	return addrNeg
}

func validateAddrRef(ctx, field, val string, resources map[string]*ResolvedResource) error {
	name, dirs, isRef, err := parseSetRef(val)
	if err != nil {
		return fmt.Errorf("%s field %s: %w", ctx, field, err)
	}
	if !isRef {
		return nil
	}
	r, ok := resources[name]
	if !ok {
		return fmt.Errorf("%s field %s: unknown resource $%s", ctx, field, name)
	}
	if r.Type != "ipset" {
		return fmt.Errorf("%s field %s: $%s is %s, expected ipset", ctx, field, name, r.Type)
	}
	if dirs != nil {
		if len(dirs) != r.Dimensions {
			return fmt.Errorf("%s field %s: ipset $%s is %s (%d dimensions), got %d direction flag(s)", ctx, field, name, r.SetType, r.Dimensions, len(dirs))
		}
		for _, d := range dirs {
			if !validSETFlags[d] {
				return fmt.Errorf("%s field %s: unknown direction flag %q (expected src or dst)", ctx, field, d)
			}
		}
	}
	return nil
}

func validatePortRef(ctx, field string, val interface{}, resources map[string]*ResolvedResource) error {
	s, ok := val.(string)
	if !ok {
		return nil
	}
	if !strings.HasPrefix(s, "$") {
		return nil
	}
	name := s[1:]
	r, ok := resources[name]
	if !ok {
		return fmt.Errorf("%s field %s: unknown resource $%s", ctx, field, name)
	}
	if r.Type != "portset" {
		return fmt.Errorf("%s field %s: $%s is %s, expected portset", ctx, field, name, r.Type)
	}
	return nil
}

func validateICMPRef(ctx, field string, val interface{}, expectedType string, resources map[string]*ResolvedResource) error {
	s, ok := val.(string)
	if !ok {
		return nil
	}
	if !strings.HasPrefix(s, "$") {
		return nil
	}
	name := s[1:]
	r, ok := resources[name]
	if !ok {
		return fmt.Errorf("%s field %s: unknown resource $%s", ctx, field, name)
	}
	if r.Type != expectedType {
		return fmt.Errorf("%s field %s: $%s is %s, expected %s", ctx, field, name, r.Type, expectedType)
	}
	return nil
}

// validateStringField rejects characters that would break iptables-restore syntax.
func validateStringField(ctx, field, val string) error {
	if val == "" {
		return nil
	}
	if strings.ContainsAny(val, "\"\n\r\x00") {
		return fmt.Errorf("%s field %s: contains invalid character (quotes, newlines, or null bytes are not allowed)", ctx, field)
	}
	return nil
}

// validateInterfaceName checks Linux interface name constraints (max 15 chars, alphanumeric/dash/dot/plus).
func validateInterfaceName(ctx, field, val string) error {
	if val == "" {
		return nil
	}
	if len(val) > 15 {
		return fmt.Errorf("%s field %s: interface name %q exceeds 15-character limit", ctx, field, val)
	}
	if !validIfaceRe.MatchString(val) {
		return fmt.Errorf("%s field %s: interface name %q contains invalid characters", ctx, field, val)
	}
	return nil
}

// validateAddrValue rejects non-resource address strings that are not valid IPs or CIDRs.
func validateAddrValue(ctx, field, val string) error {
	if val == "" || strings.HasPrefix(val, "$") {
		return nil
	}
	if ClassifyAddr(val) == IPvUnknown {
		return fmt.Errorf("%s field %s: %q is not a valid IP address or CIDR", ctx, field, val)
	}
	return nil
}

// validatePortValue checks that port numbers are in the valid range 0-65535.
func validatePortValue(ctx, field string, val interface{}) error {
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case int:
		if v < 0 || v > 65535 {
			return fmt.Errorf("%s field %s: port %d is outside valid range 0-65535", ctx, field, v)
		}
	case []interface{}:
		for _, elem := range v {
			if port, ok := elem.(int); ok {
				if port < 0 || port > 65535 {
					return fmt.Errorf("%s field %s: port %d is outside valid range 0-65535", ctx, field, port)
				}
			}
		}
	}
	return nil
}

// validateWeekdays validates a comma-separated list of day names.
func validateWeekdays(ctx, val string) error {
	days := strings.Split(val, ",")
	for _, d := range days {
		if !validWeekdays[strings.TrimSpace(d)] {
			return fmt.Errorf("%s: invalid weekday %q in weekdays %q", ctx, strings.TrimSpace(d), val)
		}
	}
	return nil
}

// collectUsedRefs returns a set of resource names referenced (as $name) in any rule field.
func collectUsedRefs(doc *ast.Document) map[string]bool {
	used := make(map[string]bool)
	for _, chain := range doc.Chains {
		for _, rules := range [][]ast.Rule{chain.Filter, chain.Mangle, chain.Nat, chain.Raw, chain.Security} {
			for _, rule := range rules {
				addStrRef(used, rule.Src)
				addStrRef(used, rule.SrcNeg)
				addStrRef(used, rule.Dst)
				addStrRef(used, rule.DstNeg)
				addIfaceRef(used, rule.SPort)
				addIfaceRef(used, rule.SPortNeg)
				addIfaceRef(used, rule.DPort)
				addIfaceRef(used, rule.DPortNeg)
				addIfaceRef(used, rule.ICMPType)
				addIfaceRef(used, rule.ICMPv6Type)
				// SET target references an ipset by bare name (no $ prefix).
				if rule.AddSet != "" {
					used[rule.AddSet] = true
				}
				if rule.DelSet != "" {
					used[rule.DelSet] = true
				}
			}
		}
	}
	return used
}

func addStrRef(used map[string]bool, s string) {
	name, _, ok, err := parseSetRef(s)
	if err != nil || !ok {
		return
	}
	used[name] = true
}

func addIfaceRef(used map[string]bool, v interface{}) {
	if s, ok := v.(string); ok {
		addStrRef(used, s)
	}
}

// sortedKeys returns sorted keys of a map for deterministic output.
func sortedKeys[K ~string, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}

// validatePhase9Targets dispatches per-target validation for all the Phase 9
// packet-modification targets. Each target owns its per-field rules: required
// fields, mutually-exclusive options, numeric ranges, and where applicable,
// protocol or address-family cross-checks (done here rather than in sema's
// global validateConflicts because the constraints are target-specific).
func validatePhase9Targets(ctx string, rule ast.Rule) error {
	j := strings.ToLower(rule.Jump)

	// Map each Phase 9 rule field to its owning target; if the target is not
	// active, having the field set is a user error.
	if err := validateClassifyTarget(ctx, j, rule); err != nil {
		return err
	}
	if err := validateDSCPTarget(ctx, j, rule); err != nil {
		return err
	}
	if err := validateTOSTarget(ctx, j, rule); err != nil {
		return err
	}
	if err := validateECNTarget(ctx, j, rule); err != nil {
		return err
	}
	if err := validateTTLTarget(ctx, j, rule); err != nil {
		return err
	}
	if err := validateHLTarget(ctx, j, rule); err != nil {
		return err
	}
	if err := validateSECMARKTarget(ctx, j, rule); err != nil {
		return err
	}
	if err := validateCONNSECMARKTarget(ctx, j, rule); err != nil {
		return err
	}
	if err := validateSYNPROXYTarget(ctx, j, rule); err != nil {
		return err
	}
	if err := validateTEETarget(ctx, j, rule); err != nil {
		return err
	}
	if err := validateAUDITTarget(ctx, j, rule); err != nil {
		return err
	}
	if err := validateCHECKSUMTarget(ctx, j, rule); err != nil {
		return err
	}
	if err := validateNETMAPTarget(ctx, j, rule); err != nil {
		return err
	}
	if err := validateCLUSTERIPTarget(ctx, j, rule); err != nil {
		return err
	}
	if err := validateIDLETIMERTarget(ctx, j, rule); err != nil {
		return err
	}
	if err := validateRATEESTTarget(ctx, j, rule); err != nil {
		return err
	}
	if err := validateLEDTarget(ctx, j, rule); err != nil {
		return err
	}
	return nil
}

func validateClassifyTarget(ctx, j string, rule ast.Rule) error {
	has := rule.SetClass != ""
	if has && j != "classify" {
		return fmt.Errorf("%s: set-class is only valid with j: classify", ctx)
	}
	if j != "classify" {
		return nil
	}
	if !has {
		return fmt.Errorf("%s: j: classify requires set-class", ctx)
	}
	if !validClassifyClassRe.MatchString(rule.SetClass) {
		return fmt.Errorf("%s: set-class %q must be of the form MAJOR:MINOR (hex or decimal)", ctx, rule.SetClass)
	}
	return nil
}

func validateDSCPTarget(ctx, j string, rule ast.Rule) error {
	hasVal := rule.SetDSCP != nil
	hasClass := rule.SetDSCPClass != ""
	if (hasVal || hasClass) && j != "dscp" {
		return fmt.Errorf("%s: set-dscp/set-dscp-class are only valid with j: dscp", ctx)
	}
	if j != "dscp" {
		return nil
	}
	if !hasVal && !hasClass {
		return fmt.Errorf("%s: j: dscp requires set-dscp or set-dscp-class", ctx)
	}
	if hasVal && hasClass {
		return fmt.Errorf("%s: set-dscp and set-dscp-class are mutually exclusive", ctx)
	}
	if hasVal {
		n, err := parseIntOrHex(rule.SetDSCP)
		if err != nil {
			return fmt.Errorf("%s: set-dscp %v: %v", ctx, rule.SetDSCP, err)
		}
		if n < 0 || n > 63 {
			return fmt.Errorf("%s: set-dscp %d is outside valid range 0-63", ctx, n)
		}
	}
	if hasClass && !validDSCPClasses[strings.ToUpper(rule.SetDSCPClass)] {
		return fmt.Errorf("%s: unknown set-dscp-class %q", ctx, rule.SetDSCPClass)
	}
	return nil
}

func validateTOSTarget(ctx, j string, rule ast.Rule) error {
	opts := 0
	if rule.SetTOS != nil {
		opts++
	}
	if rule.AndTOS != nil {
		opts++
	}
	if rule.OrTOS != nil {
		opts++
	}
	if rule.XorTOS != nil {
		opts++
	}
	if opts > 0 && j != "tos" {
		return fmt.Errorf("%s: set-tos/and-tos/or-tos/xor-tos are only valid with j: tos", ctx)
	}
	if j != "tos" {
		return nil
	}
	if opts == 0 {
		return fmt.Errorf("%s: j: tos requires one of set-tos, and-tos, or-tos, xor-tos", ctx)
	}
	if opts > 1 {
		return fmt.Errorf("%s: set-tos, and-tos, or-tos, xor-tos are mutually exclusive", ctx)
	}
	for name, v := range map[string]interface{}{
		"set-tos": rule.SetTOS,
		"and-tos": rule.AndTOS,
		"or-tos":  rule.OrTOS,
		"xor-tos": rule.XorTOS,
	} {
		if v == nil {
			continue
		}
		n, err := parseIntOrHex(v)
		if err != nil {
			return fmt.Errorf("%s: %s %v: %v", ctx, name, v, err)
		}
		if n < 0 || n > 255 {
			return fmt.Errorf("%s: %s %d is outside valid range 0-255", ctx, name, n)
		}
	}
	return nil
}

func validateECNTarget(ctx, j string, rule ast.Rule) error {
	if rule.ECNTCPRemove && j != "ecn" {
		return fmt.Errorf("%s: ecn-tcp-remove is only valid with j: ecn", ctx)
	}
	if j != "ecn" {
		return nil
	}
	if !rule.ECNTCPRemove {
		return fmt.Errorf("%s: j: ecn requires ecn-tcp-remove: true", ctx)
	}
	return requireTCPProto(ctx, "j: ecn", rule.Proto)
}

func validateTTLTarget(ctx, j string, rule ast.Rule) error {
	opts := 0
	if rule.TTLSet != nil {
		opts++
	}
	if rule.TTLDec != nil {
		opts++
	}
	if rule.TTLInc != nil {
		opts++
	}
	if opts > 0 && j != "ttl" {
		return fmt.Errorf("%s: ttl-set/ttl-dec/ttl-inc are only valid with j: ttl", ctx)
	}
	if j != "ttl" {
		return nil
	}
	if opts == 0 {
		return fmt.Errorf("%s: j: ttl requires one of ttl-set, ttl-dec, ttl-inc", ctx)
	}
	if opts > 1 {
		return fmt.Errorf("%s: ttl-set, ttl-dec, ttl-inc are mutually exclusive", ctx)
	}
	for name, p := range map[string]*int{
		"ttl-set": rule.TTLSet,
		"ttl-dec": rule.TTLDec,
		"ttl-inc": rule.TTLInc,
	} {
		if p == nil {
			continue
		}
		if *p < 0 || *p > 255 {
			return fmt.Errorf("%s: %s %d is outside valid range 0-255", ctx, name, *p)
		}
	}
	if addrFieldVersion(rule.Src, rule.SrcNeg) == 6 || addrFieldVersion(rule.Dst, rule.DstNeg) == 6 {
		return fmt.Errorf("%s: j: ttl is IPv4-only but rule has IPv6 address", ctx)
	}
	for _, p := range collectProtos(rule.Proto) {
		if strings.ToLower(p) == "ipv6-icmp" {
			return fmt.Errorf("%s: j: ttl is IPv4-only (incompatible with p: ipv6-icmp)", ctx)
		}
	}
	return nil
}

func validateHLTarget(ctx, j string, rule ast.Rule) error {
	opts := 0
	if rule.HLSet != nil {
		opts++
	}
	if rule.HLDec != nil {
		opts++
	}
	if rule.HLInc != nil {
		opts++
	}
	if opts > 0 && j != "hl" {
		return fmt.Errorf("%s: hl-set/hl-dec/hl-inc are only valid with j: hl", ctx)
	}
	if j != "hl" {
		return nil
	}
	if opts == 0 {
		return fmt.Errorf("%s: j: hl requires one of hl-set, hl-dec, hl-inc", ctx)
	}
	if opts > 1 {
		return fmt.Errorf("%s: hl-set, hl-dec, hl-inc are mutually exclusive", ctx)
	}
	for name, p := range map[string]*int{
		"hl-set": rule.HLSet,
		"hl-dec": rule.HLDec,
		"hl-inc": rule.HLInc,
	} {
		if p == nil {
			continue
		}
		if *p < 0 || *p > 255 {
			return fmt.Errorf("%s: %s %d is outside valid range 0-255", ctx, name, *p)
		}
	}
	if addrFieldVersion(rule.Src, rule.SrcNeg) == 4 || addrFieldVersion(rule.Dst, rule.DstNeg) == 4 {
		return fmt.Errorf("%s: j: hl is IPv6-only but rule has IPv4 address", ctx)
	}
	for _, p := range collectProtos(rule.Proto) {
		if strings.ToLower(p) == "icmp" {
			return fmt.Errorf("%s: j: hl is IPv6-only (incompatible with p: icmp)", ctx)
		}
	}
	return nil
}

func validateSECMARKTarget(ctx, j string, rule ast.Rule) error {
	if rule.SelCtx != "" && j != "secmark" {
		return fmt.Errorf("%s: selctx is only valid with j: secmark", ctx)
	}
	if j != "secmark" {
		return nil
	}
	if rule.SelCtx == "" {
		return fmt.Errorf("%s: j: secmark requires selctx", ctx)
	}
	return validateStringField(ctx, "selctx", rule.SelCtx)
}

func validateCONNSECMARKTarget(ctx, j string, rule ast.Rule) error {
	hasSave := rule.ConnSecMarkSave
	hasRestore := rule.ConnSecMarkRestore
	if (hasSave || hasRestore) && j != "connsecmark" {
		return fmt.Errorf("%s: connsecmark-save/connsecmark-restore are only valid with j: connsecmark", ctx)
	}
	if j != "connsecmark" {
		return nil
	}
	if !hasSave && !hasRestore {
		return fmt.Errorf("%s: j: connsecmark requires connsecmark-save or connsecmark-restore", ctx)
	}
	if hasSave && hasRestore {
		return fmt.Errorf("%s: connsecmark-save and connsecmark-restore are mutually exclusive", ctx)
	}
	return nil
}

func validateSYNPROXYTarget(ctx, j string, rule ast.Rule) error {
	has := rule.SynproxyMSS != 0 || rule.SynproxyWScale != 0 ||
		rule.SynproxyTimestamp || rule.SynproxySAckPerm
	if has && j != "synproxy" {
		return fmt.Errorf("%s: synproxy-* fields are only valid with j: synproxy", ctx)
	}
	if j != "synproxy" {
		return nil
	}
	if rule.SynproxyMSS < 0 || rule.SynproxyMSS > 65535 {
		return fmt.Errorf("%s: synproxy-mss %d is outside valid range 0-65535", ctx, rule.SynproxyMSS)
	}
	if rule.SynproxyWScale < 0 || rule.SynproxyWScale > 14 {
		return fmt.Errorf("%s: synproxy-wscale %d is outside valid range 0-14", ctx, rule.SynproxyWScale)
	}
	return nil
}

func validateTEETarget(ctx, j string, rule ast.Rule) error {
	if rule.Gateway != "" && j != "tee" {
		return fmt.Errorf("%s: gateway is only valid with j: tee", ctx)
	}
	if j != "tee" {
		return nil
	}
	if rule.Gateway == "" {
		return fmt.Errorf("%s: j: tee requires gateway", ctx)
	}
	if net.ParseIP(rule.Gateway) == nil {
		return fmt.Errorf("%s: gateway %q is not a valid IP address", ctx, rule.Gateway)
	}
	return nil
}

func validateAUDITTarget(ctx, j string, rule ast.Rule) error {
	if rule.AuditType != "" && j != "audit" {
		return fmt.Errorf("%s: audit-type is only valid with j: audit", ctx)
	}
	if j != "audit" {
		return nil
	}
	if rule.AuditType == "" {
		return fmt.Errorf("%s: j: audit requires audit-type", ctx)
	}
	if !validAuditTypes[strings.ToLower(rule.AuditType)] {
		return fmt.Errorf("%s: audit-type %q must be one of accept, drop, reject", ctx, rule.AuditType)
	}
	return nil
}

func validateCHECKSUMTarget(ctx, j string, rule ast.Rule) error {
	if rule.ChecksumFill && j != "checksum" {
		return fmt.Errorf("%s: checksum-fill is only valid with j: checksum", ctx)
	}
	if j != "checksum" {
		return nil
	}
	if !rule.ChecksumFill {
		return fmt.Errorf("%s: j: checksum requires checksum-fill: true", ctx)
	}
	return nil
}

func validateNETMAPTarget(ctx, j string, rule ast.Rule) error {
	if rule.NetmapTo != "" && j != "netmap" {
		return fmt.Errorf("%s: netmap-to is only valid with j: netmap", ctx)
	}
	if j != "netmap" {
		return nil
	}
	if rule.NetmapTo == "" {
		return fmt.Errorf("%s: j: netmap requires netmap-to", ctx)
	}
	if ClassifyAddr(rule.NetmapTo) == IPvUnknown {
		return fmt.Errorf("%s: netmap-to %q is not a valid IP or CIDR", ctx, rule.NetmapTo)
	}
	return nil
}

func validateCLUSTERIPTarget(ctx, j string, rule ast.Rule) error {
	has := rule.ClusterIPNew || rule.ClusterIPHashmode != "" ||
		rule.ClusterIPClusterMAC != "" || rule.ClusterIPTotalNodes != 0 ||
		rule.ClusterIPLocalNode != 0 || rule.ClusterIPHashInit != 0
	if has && j != "clusterip" {
		return fmt.Errorf("%s: clusterip-* fields are only valid with j: clusterip", ctx)
	}
	if j != "clusterip" {
		return nil
	}
	if !rule.ClusterIPNew {
		return fmt.Errorf("%s: j: clusterip requires clusterip-new: true (first-use declaration)", ctx)
	}
	if rule.ClusterIPHashmode == "" {
		return fmt.Errorf("%s: j: clusterip requires clusterip-hashmode", ctx)
	}
	if !validClusterIPHashmodes[strings.ToLower(rule.ClusterIPHashmode)] {
		return fmt.Errorf("%s: clusterip-hashmode %q must be one of sourceip, sourceip-sourceport, sourceip-sourceport-destport", ctx, rule.ClusterIPHashmode)
	}
	if rule.ClusterIPClusterMAC == "" {
		return fmt.Errorf("%s: j: clusterip requires clusterip-clustermac", ctx)
	}
	if !validMACRe.MatchString(rule.ClusterIPClusterMAC) {
		return fmt.Errorf("%s: clusterip-clustermac %q is not a valid MAC address", ctx, rule.ClusterIPClusterMAC)
	}
	if rule.ClusterIPTotalNodes < 1 {
		return fmt.Errorf("%s: clusterip-total-nodes %d must be positive", ctx, rule.ClusterIPTotalNodes)
	}
	if rule.ClusterIPLocalNode < 1 || rule.ClusterIPLocalNode > rule.ClusterIPTotalNodes {
		return fmt.Errorf("%s: clusterip-local-node %d must be in 1..total-nodes (%d)", ctx, rule.ClusterIPLocalNode, rule.ClusterIPTotalNodes)
	}
	return nil
}

func validateIDLETIMERTarget(ctx, j string, rule ast.Rule) error {
	has := rule.IdletimerTimeout != 0 || rule.IdletimerLabel != "" || rule.IdletimerAlarm
	if has && j != "idletimer" {
		return fmt.Errorf("%s: idletimer-* fields are only valid with j: idletimer", ctx)
	}
	if j != "idletimer" {
		return nil
	}
	if rule.IdletimerTimeout <= 0 {
		return fmt.Errorf("%s: j: idletimer requires idletimer-timeout > 0", ctx)
	}
	if rule.IdletimerLabel == "" {
		return fmt.Errorf("%s: j: idletimer requires idletimer-label", ctx)
	}
	if len(rule.IdletimerLabel) > 27 {
		return fmt.Errorf("%s: idletimer-label %q exceeds 27-character limit", ctx, rule.IdletimerLabel)
	}
	return validateStringField(ctx, "idletimer-label", rule.IdletimerLabel)
}

func validateRATEESTTarget(ctx, j string, rule ast.Rule) error {
	has := rule.RateestName != "" || rule.RateestInterval != 0 || rule.RateestEwmalog != 0
	if has && j != "rateest" {
		return fmt.Errorf("%s: rateest-* fields are only valid with j: rateest", ctx)
	}
	if j != "rateest" {
		return nil
	}
	if rule.RateestName == "" {
		return fmt.Errorf("%s: j: rateest requires rateest-name", ctx)
	}
	if len(rule.RateestName) > 15 {
		return fmt.Errorf("%s: rateest-name %q exceeds 15-character limit", ctx, rule.RateestName)
	}
	if err := validateStringField(ctx, "rateest-name", rule.RateestName); err != nil {
		return err
	}
	if rule.RateestInterval < 0 {
		return fmt.Errorf("%s: rateest-interval %d must be non-negative", ctx, rule.RateestInterval)
	}
	if rule.RateestEwmalog < 0 {
		return fmt.Errorf("%s: rateest-ewmalog %d must be non-negative", ctx, rule.RateestEwmalog)
	}
	return nil
}

func validateLEDTarget(ctx, j string, rule ast.Rule) error {
	has := rule.LEDTriggerID != "" || rule.LEDDelaySet || rule.LEDAlwaysBlink
	if has && j != "led" {
		return fmt.Errorf("%s: led-* fields are only valid with j: led", ctx)
	}
	if j != "led" {
		return nil
	}
	if rule.LEDTriggerID == "" {
		return fmt.Errorf("%s: j: led requires led-trigger-id", ctx)
	}
	if err := validateStringField(ctx, "led-trigger-id", rule.LEDTriggerID); err != nil {
		return err
	}
	if rule.LEDDelay < 0 {
		return fmt.Errorf("%s: led-delay %d must be non-negative", ctx, rule.LEDDelay)
	}
	return nil
}

// validDSCPClassesForMatch reuses validDSCPClasses (target side).
// validTOSNames enumerates the named TOS values iptables accepts.
var validTOSNames = map[string]bool{
	"Minimize-Delay":        true,
	"Maximize-Throughput":   true,
	"Maximize-Reliability":  true,
	"Minimize-Cost":         true,
	"Normal-Service":        true,
}

// validConnBytesDirs enumerates --connbytes-dir values.
var validConnBytesDirs = map[string]bool{
	"original": true, "reply": true, "both": true,
}

// validConnBytesModes enumerates --connbytes-mode values.
var validConnBytesModes = map[string]bool{
	"packets": true, "bytes": true, "avgpkt": true,
}

// validPolicyDirs enumerates --dir values for the policy match.
var validPolicyDirs = map[string]bool{
	"in": true, "out": true,
}

// validPolicyValues enumerates --pol values for the policy match.
var validPolicyValues = map[string]bool{
	"none": true, "ipsec": true,
}

// validPolicyProtos enumerates --proto values for a policy element.
var validPolicyProtos = map[string]bool{
	"ah": true, "esp": true, "ipcomp": true,
}

// validPolicyModes enumerates --mode values for a policy element.
var validPolicyModes = map[string]bool{
	"tunnel": true, "transport": true,
}

// validIPv6Headers enumerates the extension-header names accepted by -m ipv6header.
var validIPv6Headers = map[string]bool{
	"hop":        true,
	"hop-by-hop": true,
	"dst":        true,
	"route":      true,
	"frag":       true,
	"auth":       true,
	"esp":        true,
	"none":       true,
	"proto":      true,
}

// validStatisticModes enumerates -m statistic --mode values.
var validStatisticModes = map[string]bool{
	"random": true, "nth": true,
}

// validateDSCPMatch validates the dscp match module.
// Exactly one of dscp or dscp-class must be set.
func validateDSCPMatch(ctx string, m *ast.DSCPMatch) error {
	hasVal := m.DSCP != nil
	hasClass := m.DSCPClass != ""
	if !hasVal && !hasClass {
		return fmt.Errorf("%s: dscp match requires dscp or dscp-class", ctx)
	}
	if hasVal && hasClass {
		return fmt.Errorf("%s: dscp and dscp-class are mutually exclusive", ctx)
	}
	if hasVal {
		n, err := parseIntOrHex(m.DSCP)
		if err != nil {
			return fmt.Errorf("%s: dscp match %v: %v", ctx, m.DSCP, err)
		}
		if n < 0 || n > 63 {
			return fmt.Errorf("%s: dscp match value %d is outside valid range 0-63", ctx, n)
		}
	}
	if hasClass && !validDSCPClasses[strings.ToUpper(m.DSCPClass)] {
		return fmt.Errorf("%s: unknown dscp-class %q", ctx, m.DSCPClass)
	}
	return nil
}

// validateTOSMatch validates the tos match module.
// Value may be an integer (optionally with /mask), hex, or a named TOS class.
func validateTOSMatch(ctx string, m *ast.TOSMatch) error {
	if m.TOS == nil {
		return fmt.Errorf("%s: tos match requires tos", ctx)
	}
	s := fmt.Sprintf("%v", m.TOS)
	// Strip /mask for validation of the base value.
	base := s
	if idx := strings.Index(s, "/"); idx >= 0 {
		base = s[:idx]
		maskStr := s[idx+1:]
		mn, err := parseIntOrHex(maskStr)
		if err != nil {
			return fmt.Errorf("%s: tos mask %q: %v", ctx, maskStr, err)
		}
		if mn < 0 || mn > 255 {
			return fmt.Errorf("%s: tos mask %d is outside valid range 0-255", ctx, mn)
		}
	}
	if validTOSNames[base] {
		return nil
	}
	n, err := parseIntOrHex(base)
	if err != nil {
		return fmt.Errorf("%s: tos match %q is not a valid number, hex, or named value", ctx, base)
	}
	if n < 0 || n > 255 {
		return fmt.Errorf("%s: tos match %d is outside valid range 0-255", ctx, n)
	}
	return nil
}

// validateECNMatch validates the ecn match module.
// At least one of tcp-cwr / tcp-ece / ip-ect must be set. ip-ect is 0..3.
func validateECNMatch(ctx string, m *ast.ECNMatch) error {
	if !m.TCPCWR && !m.TCPECE && m.IPECT == nil {
		return fmt.Errorf("%s: ecn match requires at least one of tcp-cwr, tcp-ece, ip-ect", ctx)
	}
	if m.IPECT != nil && (*m.IPECT < 0 || *m.IPECT > 3) {
		return fmt.Errorf("%s: ecn ip-ect %d is outside valid range 0-3", ctx, *m.IPECT)
	}
	return nil
}

// validateHelperMatch validates the helper match module.
func validateHelperMatch(ctx string, m *ast.HelperMatch) error {
	if m.Name == "" {
		return fmt.Errorf("%s: helper match requires name", ctx)
	}
	if !validHelperRe.MatchString(m.Name) {
		return fmt.Errorf("%s: helper name %q contains invalid characters", ctx, m.Name)
	}
	return nil
}

// validateRealmMatch validates the realm match module. Value is an int, hex,
// or "VALUE/MASK".
func validateRealmMatch(ctx string, m *ast.RealmMatch) error {
	if m.Realm == nil {
		return fmt.Errorf("%s: realm match requires realm", ctx)
	}
	s := fmt.Sprintf("%v", m.Realm)
	base := s
	if idx := strings.Index(s, "/"); idx >= 0 {
		base = s[:idx]
		if _, err := parseIntOrHex(s[idx+1:]); err != nil {
			return fmt.Errorf("%s: realm mask %q: %v", ctx, s[idx+1:], err)
		}
	}
	if _, err := parseIntOrHex(base); err != nil {
		return fmt.Errorf("%s: realm value %q: %v", ctx, base, err)
	}
	return nil
}

// validateClusterMatch validates the cluster match module.
// total-nodes is required; local-node or local-nodes must be set and within range.
func validateClusterMatch(ctx string, m *ast.ClusterMatch) error {
	if m.TotalNodes < 1 {
		return fmt.Errorf("%s: cluster match requires total-nodes >= 1", ctx)
	}
	if m.LocalNode == 0 && len(m.LocalNodes) == 0 {
		return fmt.Errorf("%s: cluster match requires local-node or local-nodes", ctx)
	}
	if m.LocalNode != 0 && len(m.LocalNodes) != 0 {
		return fmt.Errorf("%s: cluster local-node and local-nodes are mutually exclusive", ctx)
	}
	if m.LocalNode != 0 && (m.LocalNode < 1 || m.LocalNode > m.TotalNodes) {
		return fmt.Errorf("%s: cluster local-node %d must be in 1..total-nodes (%d)", ctx, m.LocalNode, m.TotalNodes)
	}
	for _, n := range m.LocalNodes {
		if n < 1 || n > m.TotalNodes {
			return fmt.Errorf("%s: cluster local-nodes entry %d must be in 1..total-nodes (%d)", ctx, n, m.TotalNodes)
		}
	}
	if m.HashSeed < 0 {
		return fmt.Errorf("%s: cluster hash-seed %d must be non-negative", ctx, m.HashSeed)
	}
	return nil
}

// validateCPUMatch validates the cpu match module.
func validateCPUMatch(ctx string, m *ast.CPUMatch) error {
	if m.CPU < 0 {
		return fmt.Errorf("%s: cpu match %d must be non-negative", ctx, m.CPU)
	}
	return nil
}

// validateDevGroupMatch validates the devgroup match module.
func validateDevGroupMatch(ctx string, m *ast.DevGroupMatch) error {
	if m.SrcGroup == nil && m.DstGroup == nil {
		return fmt.Errorf("%s: devgroup match requires src-group or dst-group", ctx)
	}
	for _, f := range []struct {
		name string
		val  interface{}
	}{{"src-group", m.SrcGroup}, {"dst-group", m.DstGroup}} {
		if f.val == nil {
			continue
		}
		s := fmt.Sprintf("%v", f.val)
		base := s
		if idx := strings.Index(s, "/"); idx >= 0 {
			base = s[:idx]
			if _, err := parseIntOrHex(s[idx+1:]); err != nil {
				return fmt.Errorf("%s: devgroup %s mask %q: %v", ctx, f.name, s[idx+1:], err)
			}
		}
		if _, err := parseIntOrHex(base); err != nil {
			return fmt.Errorf("%s: devgroup %s value %q: %v", ctx, f.name, base, err)
		}
	}
	return nil
}

// validateRpFilterMatch validates the rpfilter match module.
func validateRpFilterMatch(ctx string, m *ast.RpFilterMatch) error {
	// All flags optional. Always valid.
	_ = m
	_ = ctx
	return nil
}

// validateQuotaMatch validates the quota match module.
func validateQuotaMatch(ctx string, m *ast.QuotaMatch) error {
	if m.Quota <= 0 {
		return fmt.Errorf("%s: quota match requires quota > 0", ctx)
	}
	return nil
}

// validateConnBytesMatch validates the connbytes match module.
// connbytes (N or lo:hi) required. dir and mode required with fixed vocab.
func validateConnBytesMatch(ctx string, m *ast.ConnBytesMatch) error {
	if m.Connbytes == "" {
		return fmt.Errorf("%s: connbytes match requires connbytes", ctx)
	}
	if err := validateNonNegRange(ctx, "connbytes", m.Connbytes); err != nil {
		return err
	}
	if m.ConnbytesDir == "" {
		return fmt.Errorf("%s: connbytes match requires connbytes-dir", ctx)
	}
	if !validConnBytesDirs[strings.ToLower(m.ConnbytesDir)] {
		return fmt.Errorf("%s: unknown connbytes-dir %q (expected original, reply, or both)", ctx, m.ConnbytesDir)
	}
	if m.Mode == "" {
		return fmt.Errorf("%s: connbytes match requires connbytes-mode", ctx)
	}
	if !validConnBytesModes[strings.ToLower(m.Mode)] {
		return fmt.Errorf("%s: unknown connbytes-mode %q (expected packets, bytes, or avgpkt)", ctx, m.Mode)
	}
	return nil
}

// validateNonNegRange validates a single non-negative number or "lo:hi" range.
func validateNonNegRange(ctx, field, s string) error {
	if strings.Contains(s, ":") {
		parts := strings.SplitN(s, ":", 2)
		lo, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
		hi, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err1 != nil || err2 != nil {
			return fmt.Errorf("%s: %s %q is not a valid range", ctx, field, s)
		}
		if lo < 0 || hi < 0 {
			return fmt.Errorf("%s: %s %q contains negative values", ctx, field, s)
		}
		if lo > hi {
			return fmt.Errorf("%s: %s %q has lo > hi", ctx, field, s)
		}
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("%s: %s %q is not a valid number or range", ctx, field, s)
	}
	if n < 0 {
		return fmt.Errorf("%s: %s %d must be non-negative", ctx, field, n)
	}
	return nil
}

// validateConnLabelMatch validates the connlabel match module.
func validateConnLabelMatch(ctx string, m *ast.ConnLabelMatch) error {
	if m.Label == nil {
		return fmt.Errorf("%s: connlabel match requires label", ctx)
	}
	switch v := m.Label.(type) {
	case int:
		if v < 0 || v > 127 {
			return fmt.Errorf("%s: connlabel numeric label %d is outside valid range 0-127", ctx, v)
		}
	case string:
		if v == "" {
			return fmt.Errorf("%s: connlabel label string is empty", ctx)
		}
		if err := validateStringField(ctx, "connlabel", v); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s: connlabel label must be an integer or string, got %T", ctx, m.Label)
	}
	return nil
}

// validateNfacctMatch validates the nfacct match module.
func validateNfacctMatch(ctx string, m *ast.NfacctMatch) error {
	if m.Name == "" {
		return fmt.Errorf("%s: nfacct match requires name", ctx)
	}
	if err := validateStringField(ctx, "nfacct.name", m.Name); err != nil {
		return err
	}
	if len(m.Name) > 32 {
		return fmt.Errorf("%s: nfacct name %q exceeds 32-character limit", ctx, m.Name)
	}
	return nil
}

// validateStringMatch validates the string match module.
// Exactly one of string or hex-string must be set; algo ∈ {bm,kmp}.
func validateStringMatch(ctx string, m *ast.StringMatch) error {
	if m.String == "" && m.HexString == "" {
		return fmt.Errorf("%s: string match requires string or hex-string", ctx)
	}
	if m.String != "" && m.HexString != "" {
		return fmt.Errorf("%s: string and hex-string are mutually exclusive", ctx)
	}
	if m.Algo == "" {
		return fmt.Errorf("%s: string match requires algo (bm or kmp)", ctx)
	}
	if strings.ToLower(m.Algo) != "bm" && strings.ToLower(m.Algo) != "kmp" {
		return fmt.Errorf("%s: string algo %q must be bm or kmp", ctx, m.Algo)
	}
	if m.From < 0 {
		return fmt.Errorf("%s: string from %d must be non-negative", ctx, m.From)
	}
	if m.To < 0 {
		return fmt.Errorf("%s: string to %d must be non-negative", ctx, m.To)
	}
	if m.To != 0 && m.From > m.To {
		return fmt.Errorf("%s: string from %d exceeds to %d", ctx, m.From, m.To)
	}
	if m.String != "" {
		if err := validateStringField(ctx, "string.string", m.String); err != nil {
			return err
		}
	}
	if m.HexString != "" {
		// --hex-string is a free-form "|XX XX|literal|XX XX|" encoding; just
		// reject quotes/newlines that would break iptables-restore parsing.
		if err := validateStringField(ctx, "string.hex-string", m.HexString); err != nil {
			return err
		}
	}
	return nil
}

// validateBPFMatch validates the bpf match module.
// Exactly one of bytecode or object-pinned must be set.
func validateBPFMatch(ctx string, m *ast.BPFMatch) error {
	if m.Bytecode == "" && m.ObjectPinned == "" {
		return fmt.Errorf("%s: bpf match requires bytecode or object-pinned", ctx)
	}
	if m.Bytecode != "" && m.ObjectPinned != "" {
		return fmt.Errorf("%s: bpf bytecode and object-pinned are mutually exclusive", ctx)
	}
	if err := validateStringField(ctx, "bpf", m.Bytecode); err != nil {
		return err
	}
	if err := validateStringField(ctx, "bpf", m.ObjectPinned); err != nil {
		return err
	}
	return nil
}

// validateU32Match validates the u32 match module.
func validateU32Match(ctx string, m *ast.U32Match) error {
	if m.U32 == "" {
		return fmt.Errorf("%s: u32 match requires u32 expression", ctx)
	}
	return validateStringField(ctx, "u32", m.U32)
}

// validateStatisticMatch validates the statistic match module.
// mode ∈ {random,nth}; random needs probability 0..1; nth needs every >= 1.
func validateStatisticMatch(ctx string, m *ast.StatisticMatch) error {
	if m.Mode == "" {
		return fmt.Errorf("%s: statistic match requires mode", ctx)
	}
	mode := strings.ToLower(m.Mode)
	if !validStatisticModes[mode] {
		return fmt.Errorf("%s: statistic mode %q must be random or nth", ctx, m.Mode)
	}
	if mode == "random" {
		if m.Probability <= 0 || m.Probability > 1 {
			return fmt.Errorf("%s: statistic probability %g must be in (0,1]", ctx, m.Probability)
		}
		if m.Every != 0 || m.Packet != nil {
			return fmt.Errorf("%s: statistic mode random does not accept every/packet", ctx)
		}
	}
	if mode == "nth" {
		if m.Every < 1 {
			return fmt.Errorf("%s: statistic mode nth requires every >= 1", ctx)
		}
		if m.Packet != nil && (*m.Packet < 0 || *m.Packet >= m.Every) {
			return fmt.Errorf("%s: statistic packet %d must be in 0..every-1 (%d)", ctx, *m.Packet, m.Every-1)
		}
		if m.Probability != 0 {
			return fmt.Errorf("%s: statistic mode nth does not accept probability", ctx)
		}
	}
	return nil
}

// validatePolicyMatch validates the policy match module.
// dir/pol required; each element is validated independently.
func validatePolicyMatch(ctx string, m *ast.PolicyMatch) error {
	if m.Dir == "" {
		return fmt.Errorf("%s: policy match requires dir (in or out)", ctx)
	}
	if !validPolicyDirs[strings.ToLower(m.Dir)] {
		return fmt.Errorf("%s: policy dir %q must be in or out", ctx, m.Dir)
	}
	if m.Policy == "" {
		return fmt.Errorf("%s: policy match requires pol (none or ipsec)", ctx)
	}
	if !validPolicyValues[strings.ToLower(m.Policy)] {
		return fmt.Errorf("%s: policy pol %q must be none or ipsec", ctx, m.Policy)
	}
	for i, e := range m.Elements {
		ectx := fmt.Sprintf("%s element[%d]", ctx, i)
		if e.Proto != "" && !validPolicyProtos[strings.ToLower(e.Proto)] {
			return fmt.Errorf("%s: proto %q must be ah, esp, or ipcomp", ectx, e.Proto)
		}
		if e.Mode != "" && !validPolicyModes[strings.ToLower(e.Mode)] {
			return fmt.Errorf("%s: mode %q must be tunnel or transport", ectx, e.Mode)
		}
		if e.ReqID < 0 {
			return fmt.Errorf("%s: reqid %d must be non-negative", ectx, e.ReqID)
		}
		if e.SPI != "" {
			if _, err := parseIntOrHex(e.SPI); err != nil {
				return fmt.Errorf("%s: spi %q: %v", ectx, e.SPI, err)
			}
		}
		if e.TunnelSrc != "" && ClassifyAddr(e.TunnelSrc) == IPvUnknown {
			return fmt.Errorf("%s: tunnel-src %q is not a valid IP or CIDR", ectx, e.TunnelSrc)
		}
		if e.TunnelDst != "" && ClassifyAddr(e.TunnelDst) == IPvUnknown {
			return fmt.Errorf("%s: tunnel-dst %q is not a valid IP or CIDR", ectx, e.TunnelDst)
		}
	}
	return nil
}

// validateIPv6HeaderMatch validates the ipv6header match module.
func validateIPv6HeaderMatch(ctx string, m *ast.IPv6HeaderMatch) error {
	if len(m.Header) == 0 {
		return fmt.Errorf("%s: ipv6header match requires header", ctx)
	}
	for _, h := range m.Header {
		if !validIPv6Headers[strings.ToLower(h)] {
			return fmt.Errorf("%s: unknown ipv6header %q", ctx, h)
		}
	}
	return nil
}

// validateFragMatch validates the frag match module (IPv6-only).
func validateFragMatch(ctx string, m *ast.FragMatch) error {
	if m.ID != "" {
		if err := validateNonNegRange(ctx, "frag id", m.ID); err != nil {
			return err
		}
	}
	// Every flag is optional. At least one of {id, first, more, last, fragres}
	// should be set, otherwise the match is a no-op — but iptables will still
	// accept bare "-m frag", so we allow it.
	return nil
}

// validateHBHMatch validates the hbh match module (IPv6-only).
func validateHBHMatch(ctx string, m *ast.HBHMatch) error {
	if m.Length < 0 {
		return fmt.Errorf("%s: hbh length %d must be non-negative", ctx, m.Length)
	}
	if m.Opts != "" {
		if err := validateStringField(ctx, "hbh.opts", m.Opts); err != nil {
			return err
		}
	}
	return nil
}

// validateDstOptsMatch validates the dst match module (IPv6-only).
func validateDstOptsMatch(ctx string, m *ast.DstOptsMatch) error {
	if m.Length < 0 {
		return fmt.Errorf("%s: dst length %d must be non-negative", ctx, m.Length)
	}
	if m.Opts != "" {
		if err := validateStringField(ctx, "dst.opts", m.Opts); err != nil {
			return err
		}
	}
	return nil
}

// validateRtMatch validates the rt match module (IPv6-only).
func validateRtMatch(ctx string, m *ast.RtMatch) error {
	if m.Type != nil && (*m.Type < 0 || *m.Type > 255) {
		return fmt.Errorf("%s: rt type %d is outside valid range 0-255", ctx, *m.Type)
	}
	if m.Segsleft != "" {
		if err := validateNonNegRange(ctx, "rt segsleft", m.Segsleft); err != nil {
			return err
		}
	}
	if m.Length < 0 {
		return fmt.Errorf("%s: rt length %d must be non-negative", ctx, m.Length)
	}
	if m.Addrs != "" {
		for _, a := range strings.Split(m.Addrs, ",") {
			a = strings.TrimSpace(a)
			if ClassifyAddr(a) != IPv6Only {
				return fmt.Errorf("%s: rt addrs entry %q is not a valid IPv6 address", ctx, a)
			}
		}
	}
	return nil
}

// validateMHMatch validates the mh match module (IPv6-only).
func validateMHMatch(ctx string, m *ast.MHMatch) error {
	if m.Type == "" {
		return fmt.Errorf("%s: mh match requires type", ctx)
	}
	if err := validateStringField(ctx, "mh.type", m.Type); err != nil {
		return err
	}
	// --mh type accepts named types (binding-update, home-test, ...) and numeric
	// ranges. Leave detailed name validation to iptables so we don't get stale
	// when new types are added.
	return nil
}

// parseIntOrHex accepts int or string ("0xNN" or decimal) and returns the integer value.
func parseIntOrHex(v interface{}) (int, error) {
	switch t := v.(type) {
	case int:
		return t, nil
	case string:
		s := strings.TrimSpace(t)
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			n, err := strconv.ParseInt(s[2:], 16, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid hex %q", s)
			}
			return int(n), nil
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return 0, fmt.Errorf("not a number: %q", s)
		}
		return n, nil
	}
	return 0, fmt.Errorf("expected int or hex string, got %T", v)
}
