package sema

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"yipt/internal/ast"
)

var validIfaceRe = regexp.MustCompile(`^[a-zA-Z0-9\-\.+]+$`)

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
	for chainName, chain := range doc.Chains {
		if err := validateRules(chainName, "filter", chain.Filter, res.Resources); err != nil {
			return nil, err
		}
		if err := validateRules(chainName, "mangle", chain.Mangle, res.Resources); err != nil {
			return nil, err
		}
		if err := validateRules(chainName, "nat", chain.Nat, res.Resources); err != nil {
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

func validateRules(chainName, table string, rules []ast.Rule, resources map[string]*ResolvedResource) error {
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
		if err := validateConflicts(ctx, rule); err != nil {
			return err
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
