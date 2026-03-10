package sema

import (
	"fmt"
	"strings"

	"yipt/internal/ast"
)

// Resolved holds the analyzed document with classified resources.
type Resolved struct {
	Doc       *ast.Document
	Resources map[string]*ResolvedResource
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
