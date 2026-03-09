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
	}
	return nil
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
