package ast

import "gopkg.in/yaml.v3"

// Document is the top-level YAML structure.
type Document struct {
	Resources map[string]Resource `yaml:"resources"`
	Chains    map[string]Chain    `yaml:"chains"`
}

// Resource represents a named reusable set (ipset, portset, icmp_typeset, icmpv6_typeset).
type Resource struct {
	Type     string        `yaml:"type"`
	Elements []interface{} `yaml:"elements"`
}

// Chain represents an iptables chain with optional policy and rules.
type Chain struct {
	Policy string `yaml:"policy"`
	Filter []Rule `yaml:"filter"`
	Mangle []Rule `yaml:"mangle"`
	Nat    []Rule `yaml:"nat"`
}

// Rule represents a single iptables rule.
// Because YAML keys like "i!", "o!" etc. are not valid Go struct tag identifiers,
// we implement yaml.Unmarshaler and decode manually.
type Rule struct {
	In      string
	InNeg   string
	Out     string
	OutNeg  string
	Src     string
	SrcNeg  string
	Dst     string
	DstNeg  string
	Proto   interface{} // string | []interface{}
	SPort   interface{} // int | string | []interface{}
	DPort   interface{} // int | string | []interface{}
	SPortNeg interface{} // negated source port
	DPortNeg interface{} // negated dest port
	Syn     bool
	ICMPType   interface{} // int | string | "$resname"
	ICMPv6Type interface{} // int | string | "$resname"
	Jump       string
	RejectWith string
	LogPrefix  string
	Comment    string
	SetMark    interface{} // int | string
	TProxyMark interface{} // int | string
	OnIP       string
	OnPort     int
	// NAT-specific target fields
	ToSource string
	ToDest   string
	ToPorts  string
	Match      *MatchBlock
}

// UnmarshalYAML implements yaml.Unmarshaler for Rule.
// This is needed because keys like "i!", "s!" are not valid Go struct tag names.
func (r *Rule) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return nil
	}

	for i := 0; i+1 < len(value.Content); i += 2 {
		key := value.Content[i].Value
		val := value.Content[i+1]

		switch key {
		case "i":
			r.In = val.Value
		case "i!":
			r.InNeg = val.Value
		case "o":
			r.Out = val.Value
		case "o!":
			r.OutNeg = val.Value
		case "s":
			r.Src = val.Value
		case "s!":
			r.SrcNeg = val.Value
		case "d":
			r.Dst = val.Value
		case "d!":
			r.DstNeg = val.Value
		case "p":
			var v interface{}
			if err := val.Decode(&v); err != nil {
				return err
			}
			r.Proto = v
		case "sp":
			var v interface{}
			if err := val.Decode(&v); err != nil {
				return err
			}
			r.SPort = v
		case "dp":
			var v interface{}
			if err := val.Decode(&v); err != nil {
				return err
			}
			r.DPort = v
		case "sp!":
			var v interface{}
			if err := val.Decode(&v); err != nil {
				return err
			}
			r.SPortNeg = v
		case "dp!":
			var v interface{}
			if err := val.Decode(&v); err != nil {
				return err
			}
			r.DPortNeg = v
		case "syn":
			r.Syn = val.Value == "true"
		case "icmp-type":
			var v interface{}
			if err := val.Decode(&v); err != nil {
				return err
			}
			r.ICMPType = v
		case "icmpv6-type":
			var v interface{}
			if err := val.Decode(&v); err != nil {
				return err
			}
			r.ICMPv6Type = v
		case "j":
			r.Jump = val.Value
		case "reject-with":
			r.RejectWith = val.Value
		case "log-prefix":
			r.LogPrefix = val.Value
		case "comment":
			r.Comment = val.Value
		case "set-mark":
			var v interface{}
			if err := val.Decode(&v); err != nil {
				return err
			}
			r.SetMark = v
		case "tproxy-mark":
			var v interface{}
			if err := val.Decode(&v); err != nil {
				return err
			}
			r.TProxyMark = v
		case "on-ip":
			r.OnIP = val.Value
		case "on-port":
			if err := val.Decode(&r.OnPort); err != nil {
				return err
			}
		case "to-source":
			r.ToSource = val.Value
		case "to-destination":
			r.ToDest = val.Value
		case "to-ports":
			r.ToPorts = val.Value
		case "match":
			mb := &MatchBlock{}
			if err := val.Decode(mb); err != nil {
				return err
			}
			r.Match = mb
		}
	}
	return nil
}

// MatchBlock holds extended match modules.
type MatchBlock struct {
	Conntrack *ConntrackMatch `yaml:"conntrack"`
	Recent    *RecentMatch    `yaml:"recent"`
	Limit     *LimitMatch     `yaml:"limit"`
	Mark      *MarkMatch      `yaml:"mark"`
	Socket    *SocketMatch    `yaml:"socket"`
	AddrType  *AddrTypeMatch  `yaml:"addrtype"`
	MAC       *MACMatch       `yaml:"mac"`
	Time      *TimeMatch      `yaml:"time"`
	State     *StateMatch     `yaml:"state"`
}

// ConntrackMatch represents the conntrack match module.
type ConntrackMatch struct {
	CTState []string `yaml:"ctstate"`
}

// RecentMatch represents the recent match module.
type RecentMatch struct {
	Name     string `yaml:"name"`
	Set      bool   `yaml:"set"`
	Update   bool   `yaml:"update"`
	Seconds  int    `yaml:"seconds"`
	HitCount int    `yaml:"hitcount"`
	RSource  bool   `yaml:"rsource"`
	RTTL     bool   `yaml:"rttl"`
}

// LimitMatch represents the limit match module.
type LimitMatch struct {
	Limit      string `yaml:"limit"`
	LimitBurst int    `yaml:"limit-burst"`
}

// MarkMatch represents the mark match module.
type MarkMatch struct {
	Mark interface{} `yaml:"mark"` // int | string (e.g. "0xff")
}

// SocketMatch represents the socket match module (no options needed).
type SocketMatch struct{}

// AddrTypeMatch represents the addrtype match module.
type AddrTypeMatch struct {
	DstType string `yaml:"dst-type"`
}

// MACMatch represents the mac match module.
type MACMatch struct {
	MACSource string `yaml:"mac-source"`
}

// TimeMatch represents the time match module.
type TimeMatch struct {
	TimeStart string `yaml:"timestart"`
	TimeStop  string `yaml:"timestop"`
	Days      string `yaml:"weekdays"`
}

// StateMatch represents the legacy state match module.
type StateMatch struct {
	State []string `yaml:"state"`
}
