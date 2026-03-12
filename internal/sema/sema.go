package sema

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"yipt/internal/ast"
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
}

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

var validAddrTypes = map[string]bool{
	"UNSPEC": true, "UNICAST": true, "LOCAL": true, "BROADCAST": true,
	"ANYCAST": true, "MULTICAST": true, "BLACKHOLE": true, "UNREACHABLE": true,
	"PROHIBIT": true,
}

var validWeekdays = map[string]bool{
	"Mon": true, "Tue": true, "Wed": true, "Thu": true,
	"Fri": true, "Sat": true, "Sun": true,
}

// natTargetChainConstraints maps NAT jump targets to their allowed (table, chain) combinations.
var natTargetChainConstraints = map[string]struct {
	table  string
	chains map[string]bool
}{
	"SNAT":       {table: "nat", chains: map[string]bool{"POSTROUTING": true, "INPUT": true}},
	"DNAT":       {table: "nat", chains: map[string]bool{"PREROUTING": true, "INPUT": true, "OUTPUT": true}},
	"MASQUERADE": {table: "nat", chains: map[string]bool{"POSTROUTING": true}},
	"REDIRECT":   {table: "nat", chains: map[string]bool{"PREROUTING": true, "OUTPUT": true}},
	"TPROXY":     {table: "mangle", chains: map[string]bool{"PREROUTING": true}},
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
	IPv4Elements []string // for ipset resources
	IPv6Elements []string // for ipset resources
	IsMixed      bool     // true if ipset has both v4 and v6 elements
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
			for _, elem := range r.Elements {
				s, ok := elem.(string)
				if !ok {
					return nil, fmt.Errorf("ipset %q: element %v is not a string", name, elem)
				}
				v := ClassifyAddr(s)
				switch v {
				case IPv4Only:
					rr.IPv4Elements = append(rr.IPv4Elements, s)
				case IPv6Only:
					rr.IPv6Elements = append(rr.IPv6Elements, s)
				default:
					return nil, fmt.Errorf("ipset %q: cannot classify element %q", name, s)
				}
			}
			if len(rr.IPv4Elements) > 0 && len(rr.IPv6Elements) > 0 {
				rr.IsMixed = true
			}
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
		if err := validateMatchBlock(ctx, rule.Match); err != nil {
			return err
		}
		if err := validateConflicts(ctx, rule); err != nil {
			return err
		}
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
		if table != constraint.table {
			return fmt.Errorf("%s: target %s is only valid in the %s table, not %s", ctx, jUpper, constraint.table, table)
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
func validateMatchBlock(ctx string, mb *ast.MatchBlock) error {
	if mb == nil {
		return nil
	}
	if mb.MAC != nil && mb.MAC.MACSource != "" {
		if !validMACRe.MatchString(mb.MAC.MACSource) {
			return fmt.Errorf("%s: mac-source %q is not a valid MAC address", ctx, mb.MAC.MACSource)
		}
	}
	if mb.Time != nil {
		if mb.Time.TimeStart != "" && !validTimeRe.MatchString(mb.Time.TimeStart) {
			return fmt.Errorf("%s: timestart %q is not a valid time (expected HH:MM)", ctx, mb.Time.TimeStart)
		}
		if mb.Time.TimeStop != "" && !validTimeRe.MatchString(mb.Time.TimeStop) {
			return fmt.Errorf("%s: timestop %q is not a valid time (expected HH:MM)", ctx, mb.Time.TimeStop)
		}
		if mb.Time.Days != "" {
			if err := validateWeekdays(ctx, mb.Time.Days); err != nil {
				return err
			}
		}
	}
	if mb.AddrType != nil && mb.AddrType.DstType != "" {
		if !validAddrTypes[strings.ToUpper(mb.AddrType.DstType)] {
			return fmt.Errorf("%s: unknown addrtype dst-type %q", ctx, mb.AddrType.DstType)
		}
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
	if !strings.HasPrefix(val, "$") {
		return nil
	}
	name := val[1:]
	r, ok := resources[name]
	if !ok {
		return fmt.Errorf("%s field %s: unknown resource $%s", ctx, field, name)
	}
	if r.Type != "ipset" {
		return fmt.Errorf("%s field %s: $%s is %s, expected ipset", ctx, field, name, r.Type)
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
		for _, rules := range [][]ast.Rule{chain.Filter, chain.Mangle, chain.Nat} {
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
			}
		}
	}
	return used
}

func addStrRef(used map[string]bool, s string) {
	if strings.HasPrefix(s, "$") {
		used[s[1:]] = true
	}
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
