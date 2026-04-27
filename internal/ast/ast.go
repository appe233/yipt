package ast

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Document is the top-level YAML structure.
type Document struct {
	Resources map[string]Resource `yaml:"resources"`
	Chains    map[string]Chain    `yaml:"chains"`
}

// Resource represents a named reusable set (ipset, portset, icmp_typeset, icmpv6_typeset).
// For ipset resources, SetType declares the storage type (default "hash:net")
// and SetOptions declares optional creation attributes like timeout or maxelem.
type Resource struct {
	Type       string        `yaml:"type"`
	SetType    string        `yaml:"set-type"`
	SetOptions *SetOptions   `yaml:"set-options"`
	Elements   []interface{} `yaml:"elements"`
}

// SetOptions holds optional ipset creation attributes.
// Not every attribute applies to every set type; sema validates compatibility.
type SetOptions struct {
	Timeout  *int   `yaml:"timeout"`  // default element timeout in seconds
	Counters bool   `yaml:"counters"` // enable per-element packet/byte counters
	Comment  bool   `yaml:"comment"`  // allow per-element comments
	SkbInfo  bool   `yaml:"skbinfo"`  // enable SKBINFO extension
	HashSize int    `yaml:"hashsize"` // initial hash bucket count (power of 2)
	MaxElem  int    `yaml:"maxelem"`  // maximum number of elements
	NetMask  int    `yaml:"netmask"`  // fixed prefix length for hash:ip / hash:ip,mark
	MarkMask string `yaml:"markmask"` // fixed mark mask for hash:*,mark
	Range    string `yaml:"range"`    // range for bitmap:* types (e.g. "1.2.3.0-1.2.3.255" or "1024-65535")
	Family   string `yaml:"family"`   // override inferred family ("inet" or "inet6")
}

// Chain represents an iptables chain with optional policy and rules.
type Chain struct {
	Policy   string `yaml:"policy"`
	Filter   []Rule `yaml:"filter"`
	Mangle   []Rule `yaml:"mangle"`
	Nat      []Rule `yaml:"nat"`
	Raw      []Rule `yaml:"raw"`
	Security []Rule `yaml:"security"`
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
	// CT target fields (raw table)
	Notrack  bool
	Zone     int
	Helper   string
	CTEvents []string
	CTMask   interface{} // int | string (hex)
	NfMask   interface{} // int | string (hex)
	// TCP / fragment polish
	TCPFlags       *TCPFlagsSpec
	Fragment       bool
	TCPOption      int
	SetMSS         int  // for j: tcpmss
	ClampMSSToPMTU bool // for j: tcpmss
	// CONNMARK target fields
	SaveMark    bool
	RestoreMark bool
	// NFLOG target fields
	NflogGroup     int
	NflogPrefix    string
	NflogRange     int
	NflogThreshold int
	// NFQUEUE target fields
	QueueNum       int  // 0 means "use queue-balance or default 0"
	QueueNumSet    bool // distinguishes unset from 0
	QueueBalance   string
	QueueBypass    bool
	QueueCPUFanout bool
	// SET target fields
	AddSet     string
	DelSet     string
	SetFlags   []string
	SetExist   bool
	SetTimeout int
	// Phase 9 — packet-modification targets.
	// CLASSIFY
	SetClass string // "MAJOR:MINOR" for CBQ / HTB classification
	// DSCP
	SetDSCP      interface{} // int or hex string for --set-dscp
	SetDSCPClass string      // DSCP class name (e.g. "EF", "AF41") for --set-dscp-class
	// TOS (exactly one of set/and/or/xor)
	SetTOS interface{} // value or name for --set-tos
	AndTOS interface{} // for --and-tos
	OrTOS  interface{} // for --or-tos
	XorTOS interface{} // for --xor-tos
	// ECN
	ECNTCPRemove bool // --ecn-tcp-remove (requires p: tcp)
	// TTL (target, IPv4 only) — exactly one of set/dec/inc
	TTLSet *int
	TTLDec *int
	TTLInc *int
	// HL (target, IPv6 only) — exactly one of set/dec/inc
	HLSet *int
	HLDec *int
	HLInc *int
	// SECMARK
	SelCtx string // --selctx
	// CONNSECMARK (exactly one of save/restore)
	ConnSecMarkSave    bool
	ConnSecMarkRestore bool
	// SYNPROXY
	SynproxyMSS       int  // --mss
	SynproxyWScale    int  // --wscale
	SynproxyTimestamp bool // --timestamp
	SynproxySAckPerm  bool // --sack-perm
	// TEE
	Gateway string // --gateway IP
	// AUDIT
	AuditType string // --type {accept,drop,reject}
	// CHECKSUM
	ChecksumFill bool // --checksum-fill
	// NETMAP
	NetmapTo string // --to A.B.C.D/N
	// CLUSTERIP
	ClusterIPNew        bool   // --new
	ClusterIPHashmode   string // --hashmode {sourceip,sourceip-sourceport,sourceip-sourceport-destport}
	ClusterIPClusterMAC string // --clustermac MAC
	ClusterIPTotalNodes int    // --total-nodes
	ClusterIPLocalNode  int    // --local-node
	ClusterIPHashInit   int    // --hash-init
	// IDLETIMER
	IdletimerTimeout int    // --timeout (seconds)
	IdletimerLabel   string // --label
	IdletimerAlarm   bool   // --alarm
	// RATEEST
	RateestName     string // --rateest-name
	RateestInterval int    // --rateest-interval (ms)
	RateestEwmalog  int    // --rateest-ewmalog
	// LED
	LEDTriggerID   string // --led-trigger-id
	LEDDelay       int    // --led-delay (ms); 0 means unset
	LEDDelaySet    bool   // distinguishes --led-delay 0 from unset
	LEDAlwaysBlink bool   // --led-always-blink
	// Match is an ordered list of match module groups.
	// YAML accepts either a single mapping (backwards compat, wraps to a one-entry list)
	// or a sequence of mappings (enables repeating the same module, e.g. recent --set
	// chained with recent --update).
	Match []*MatchBlock
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
		case "notrack":
			r.Notrack = val.Value == "true"
		case "zone":
			if err := val.Decode(&r.Zone); err != nil {
				return err
			}
		case "helper":
			r.Helper = val.Value
		case "ctevents":
			if err := val.Decode(&r.CTEvents); err != nil {
				return err
			}
		case "ctmask":
			var v interface{}
			if err := val.Decode(&v); err != nil {
				return err
			}
			r.CTMask = v
		case "nfmask":
			var v interface{}
			if err := val.Decode(&v); err != nil {
				return err
			}
			r.NfMask = v
		case "tcp-flags":
			spec := &TCPFlagsSpec{}
			if err := val.Decode(spec); err != nil {
				return err
			}
			r.TCPFlags = spec
		case "fragment":
			r.Fragment = val.Value == "true"
		case "tcp-option":
			if err := val.Decode(&r.TCPOption); err != nil {
				return err
			}
		case "set-mss":
			if err := val.Decode(&r.SetMSS); err != nil {
				return err
			}
		case "clamp-mss-to-pmtu":
			r.ClampMSSToPMTU = val.Value == "true"
		case "save-mark":
			r.SaveMark = val.Value == "true"
		case "restore-mark":
			r.RestoreMark = val.Value == "true"
		case "nflog-group":
			if err := val.Decode(&r.NflogGroup); err != nil {
				return err
			}
		case "nflog-prefix":
			r.NflogPrefix = val.Value
		case "nflog-range":
			if err := val.Decode(&r.NflogRange); err != nil {
				return err
			}
		case "nflog-threshold":
			if err := val.Decode(&r.NflogThreshold); err != nil {
				return err
			}
		case "queue-num":
			if err := val.Decode(&r.QueueNum); err != nil {
				return err
			}
			r.QueueNumSet = true
		case "queue-balance":
			r.QueueBalance = val.Value
		case "queue-bypass":
			r.QueueBypass = val.Value == "true"
		case "queue-cpu-fanout":
			r.QueueCPUFanout = val.Value == "true"
		case "add-set":
			r.AddSet = val.Value
		case "del-set":
			r.DelSet = val.Value
		case "set-flags":
			if err := val.Decode(&r.SetFlags); err != nil {
				return err
			}
		case "set-exist":
			r.SetExist = val.Value == "true"
		case "set-timeout":
			if err := val.Decode(&r.SetTimeout); err != nil {
				return err
			}
		case "set-class":
			r.SetClass = val.Value
		case "set-dscp":
			var v interface{}
			if err := val.Decode(&v); err != nil {
				return err
			}
			r.SetDSCP = v
		case "set-dscp-class":
			r.SetDSCPClass = val.Value
		case "set-tos":
			var v interface{}
			if err := val.Decode(&v); err != nil {
				return err
			}
			r.SetTOS = v
		case "and-tos":
			var v interface{}
			if err := val.Decode(&v); err != nil {
				return err
			}
			r.AndTOS = v
		case "or-tos":
			var v interface{}
			if err := val.Decode(&v); err != nil {
				return err
			}
			r.OrTOS = v
		case "xor-tos":
			var v interface{}
			if err := val.Decode(&v); err != nil {
				return err
			}
			r.XorTOS = v
		case "ecn-tcp-remove":
			r.ECNTCPRemove = val.Value == "true"
		case "ttl-set":
			var n int
			if err := val.Decode(&n); err != nil {
				return err
			}
			r.TTLSet = &n
		case "ttl-dec":
			var n int
			if err := val.Decode(&n); err != nil {
				return err
			}
			r.TTLDec = &n
		case "ttl-inc":
			var n int
			if err := val.Decode(&n); err != nil {
				return err
			}
			r.TTLInc = &n
		case "hl-set":
			var n int
			if err := val.Decode(&n); err != nil {
				return err
			}
			r.HLSet = &n
		case "hl-dec":
			var n int
			if err := val.Decode(&n); err != nil {
				return err
			}
			r.HLDec = &n
		case "hl-inc":
			var n int
			if err := val.Decode(&n); err != nil {
				return err
			}
			r.HLInc = &n
		case "selctx":
			r.SelCtx = val.Value
		case "connsecmark-save":
			r.ConnSecMarkSave = val.Value == "true"
		case "connsecmark-restore":
			r.ConnSecMarkRestore = val.Value == "true"
		case "synproxy-mss":
			if err := val.Decode(&r.SynproxyMSS); err != nil {
				return err
			}
		case "synproxy-wscale":
			if err := val.Decode(&r.SynproxyWScale); err != nil {
				return err
			}
		case "synproxy-timestamp":
			r.SynproxyTimestamp = val.Value == "true"
		case "synproxy-sack-perm":
			r.SynproxySAckPerm = val.Value == "true"
		case "gateway":
			r.Gateway = val.Value
		case "audit-type":
			r.AuditType = val.Value
		case "checksum-fill":
			r.ChecksumFill = val.Value == "true"
		case "netmap-to":
			r.NetmapTo = val.Value
		case "clusterip-new":
			r.ClusterIPNew = val.Value == "true"
		case "clusterip-hashmode":
			r.ClusterIPHashmode = val.Value
		case "clusterip-clustermac":
			r.ClusterIPClusterMAC = val.Value
		case "clusterip-total-nodes":
			if err := val.Decode(&r.ClusterIPTotalNodes); err != nil {
				return err
			}
		case "clusterip-local-node":
			if err := val.Decode(&r.ClusterIPLocalNode); err != nil {
				return err
			}
		case "clusterip-hash-init":
			if err := val.Decode(&r.ClusterIPHashInit); err != nil {
				return err
			}
		case "idletimer-timeout":
			if err := val.Decode(&r.IdletimerTimeout); err != nil {
				return err
			}
		case "idletimer-label":
			r.IdletimerLabel = val.Value
		case "idletimer-alarm":
			r.IdletimerAlarm = val.Value == "true"
		case "rateest-name":
			r.RateestName = val.Value
		case "rateest-interval":
			if err := val.Decode(&r.RateestInterval); err != nil {
				return err
			}
		case "rateest-ewmalog":
			if err := val.Decode(&r.RateestEwmalog); err != nil {
				return err
			}
		case "led-trigger-id":
			r.LEDTriggerID = val.Value
		case "led-delay":
			if err := val.Decode(&r.LEDDelay); err != nil {
				return err
			}
			r.LEDDelaySet = true
		case "led-always-blink":
			r.LEDAlwaysBlink = val.Value == "true"
		case "match":
			switch val.Kind {
			case yaml.SequenceNode:
				for _, item := range val.Content {
					mb := &MatchBlock{}
					if err := item.Decode(mb); err != nil {
						return err
					}
					r.Match = append(r.Match, mb)
				}
			case yaml.MappingNode:
				mb := &MatchBlock{}
				if err := val.Decode(mb); err != nil {
					return err
				}
				r.Match = []*MatchBlock{mb}
			default:
				return fmt.Errorf("match: expected mapping or sequence, got %v", val.Kind)
			}
		default:
			return fmt.Errorf("unknown rule field %q", key)
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
	Connmark  *ConnmarkMatch  `yaml:"connmark"`
	Connlimit *ConnlimitMatch `yaml:"connlimit"`
	Hashlimit *HashlimitMatch `yaml:"hashlimit"`
	Socket    *SocketMatch    `yaml:"socket"`
	AddrType  *AddrTypeMatch  `yaml:"addrtype"`
	MAC       *MACMatch       `yaml:"mac"`
	Time      *TimeMatch      `yaml:"time"`
	State     *StateMatch     `yaml:"state"`
	Owner     *OwnerMatch     `yaml:"owner"`
	IPRange   *IPRangeMatch   `yaml:"iprange"`
	Length    *LengthMatch    `yaml:"length"`
	TTL       *TTLMatch       `yaml:"ttl"`
	HL        *HLMatch        `yaml:"hl"`
	PktType   *PktTypeMatch   `yaml:"pkttype"`
	PhysDev   *PhysDevMatch   `yaml:"physdev"`
	// Phase 10 — match side of Phase 9 packet-modification targets.
	DSCP *DSCPMatch `yaml:"dscp"`
	TOS  *TOSMatch  `yaml:"tos"`
	ECN  *ECNMatch  `yaml:"ecn"`
	// Phase 10 — metadata / per-packet matches.
	Helper    *HelperMatch    `yaml:"helper"`
	Realm     *RealmMatch     `yaml:"realm"`
	Cluster   *ClusterMatch   `yaml:"cluster"`
	CPU       *CPUMatch       `yaml:"cpu"`
	DevGroup  *DevGroupMatch  `yaml:"devgroup"`
	RpFilter  *RpFilterMatch  `yaml:"rpfilter"`
	Quota     *QuotaMatch     `yaml:"quota"`
	ConnBytes *ConnBytesMatch `yaml:"connbytes"`
	ConnLabel *ConnLabelMatch `yaml:"connlabel"`
	Nfacct    *NfacctMatch    `yaml:"nfacct"`
	// Phase 10 — inspection / structured matches.
	String    *StringMatch    `yaml:"string"`
	BPF       *BPFMatch       `yaml:"bpf"`
	U32       *U32Match       `yaml:"u32"`
	Statistic *StatisticMatch `yaml:"statistic"`
	Policy    *PolicyMatch    `yaml:"policy"`
	// Phase 10 — IPv6 extension header matches (IPv6-only).
	IPv6Header *IPv6HeaderMatch `yaml:"ipv6header"`
	Frag       *FragMatch       `yaml:"frag"`
	HBH        *HBHMatch        `yaml:"hbh"`
	DstOpts    *DstOptsMatch    `yaml:"dst"`
	Rt         *RtMatch         `yaml:"rt"`
	MH         *MHMatch         `yaml:"mh"`
}

// ConntrackMatch represents the conntrack match module.
// Beyond the basic ctstate, iptables' conntrack module exposes per-tuple matches
// (original and reply direction source/dest addresses and ports), the tracked L4
// protocol, connection status flags, the expiry countdown, and the packet's
// traversal direction.
type ConntrackMatch struct {
	CTState       []string `yaml:"ctstate"`
	CTProto       string   `yaml:"ctproto"`
	CTOrigSrc     string   `yaml:"ctorigsrc"`
	CTOrigDst     string   `yaml:"ctorigdst"`
	CTOrigSrcPort string   `yaml:"ctorigsrcport"` // port or "N:M" range
	CTOrigDstPort string   `yaml:"ctorigdstport"`
	CTReplSrc     string   `yaml:"ctreplsrc"`
	CTReplDst     string   `yaml:"ctrepldst"`
	CTStatus      []string `yaml:"ctstatus"`
	CTExpire      string   `yaml:"ctexpire"` // seconds: single N or "N:M" range
	CTDir         string   `yaml:"ctdir"`    // ORIGINAL | REPLY
}

// RecentMatch represents the recent match module.
// One of set/update/rcheck/remove selects the operation; the remaining fields tune
// the window (seconds, hitcount, reap), the keying (rsource/rdest, mask), and TTL
// checking (rttl).
type RecentMatch struct {
	Name     string `yaml:"name"`
	Set      bool   `yaml:"set"`
	Update   bool   `yaml:"update"`
	RCheck   bool   `yaml:"rcheck"`
	Remove   bool   `yaml:"remove"`
	Seconds  int    `yaml:"seconds"`
	Reap     bool   `yaml:"reap"`
	HitCount int    `yaml:"hitcount"`
	RSource  bool   `yaml:"rsource"`
	RDest    bool   `yaml:"rdest"`
	RTTL     bool   `yaml:"rttl"`
	Mask     string `yaml:"mask"` // IP or CIDR mask applied to the tracked address
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

// ConnmarkMatch represents the connmark match module.
type ConnmarkMatch struct {
	Mark interface{} `yaml:"mark"` // int | string (e.g. "0xff" or "0xff/0xff")
}

// ConnlimitMatch represents the connlimit match module.
// --connlimit-above / --connlimit-upto cap per-source (or per-dest) connection counts;
// --connlimit-mask groups hosts by prefix length (0-32 IPv4, 0-128 IPv6).
type ConnlimitMatch struct {
	Above *int `yaml:"above"`
	Upto  *int `yaml:"upto"`
	Mask  *int `yaml:"mask"`
	SAddr bool `yaml:"saddr"`
	DAddr bool `yaml:"daddr"`
}

// HashlimitMatch represents the hashlimit match module.
// Rate strings look like "5/second" or "1000/minute"; allowed units: second, sec, s,
// minute, min, m, hour, h, day, d.
type HashlimitMatch struct {
	Name             string   `yaml:"name"`
	Upto             string   `yaml:"upto"`
	Above            string   `yaml:"above"`
	Burst            int      `yaml:"burst"`
	Mode             []string `yaml:"mode"`
	SrcMask          *int     `yaml:"srcmask"`
	DstMask          *int     `yaml:"dstmask"`
	HTableSize       int      `yaml:"htable-size"`
	HTableMax        int      `yaml:"htable-max"`
	HTableExpire     int      `yaml:"htable-expire"`
	HTableGCInterval int      `yaml:"htable-gcinterval"`
}

// SocketMatch represents the socket match module.
// Bare --m socket (no flags) matches packets with a socket lookup hit.
// transparent restricts the match to sockets with IP_TRANSPARENT set (tproxy).
// nowildcard disables wildcard-address equivalence for the socket lookup.
// restore-skmark copies the socket's mark into the packet mark.
type SocketMatch struct {
	Transparent   bool `yaml:"transparent"`
	NoWildcard    bool `yaml:"nowildcard"`
	RestoreSKMark bool `yaml:"restore-skmark"`
}

// AddrTypeMatch represents the addrtype match module.
// limit-iface-in and limit-iface-out restrict the lookup to the incoming or
// outgoing interface respectively; they are mutually exclusive.
type AddrTypeMatch struct {
	SrcType       string `yaml:"src-type"`
	DstType       string `yaml:"dst-type"`
	LimitIfaceIn  string `yaml:"limit-iface-in"`
	LimitIfaceOut string `yaml:"limit-iface-out"`
}

// MACMatch represents the mac match module.
// Either mac-source or mac-source! may be set (the latter negates the match).
type MACMatch struct {
	MACSource string
	Neg       bool
}

// UnmarshalYAML accepts "mac-source" and "mac-source!" keys; the bang form
// sets Neg=true so codegen emits the "!" inversion before --mac-source.
func (m *MACMatch) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("mac: expected mapping")
	}
	for i := 0; i+1 < len(value.Content); i += 2 {
		key := value.Content[i].Value
		val := value.Content[i+1]
		switch key {
		case "mac-source":
			m.MACSource = val.Value
		case "mac-source!":
			m.MACSource = val.Value
			m.Neg = true
		default:
			return fmt.Errorf("unknown mac match field %q", key)
		}
	}
	return nil
}

// TimeMatch represents the time match module.
// datestart/datestop expect ISO-8601 timestamps (e.g. "2026-01-01T00:00:00").
// monthdays is a comma-separated list of 1..31.
// utc and kerneltz are mutually exclusive. contiguous widens range matches to
// cover the wrap at midnight (required when timestart > timestop).
type TimeMatch struct {
	TimeStart  string `yaml:"timestart"`
	TimeStop   string `yaml:"timestop"`
	Days       string `yaml:"weekdays"`
	DateStart  string `yaml:"datestart"`
	DateStop   string `yaml:"datestop"`
	MonthDays  string `yaml:"monthdays"`
	UTC        bool   `yaml:"utc"`
	KernelTZ   bool   `yaml:"kerneltz"`
	Contiguous bool   `yaml:"contiguous"`
}

// StateMatch represents the legacy state match module.
type StateMatch struct {
	State []string `yaml:"state"`
}

// TCPFlagsSpec represents the tcp-flags rule field.
// YAML shape: {mask: [SYN, ACK, FIN, RST], comp: [SYN]}
type TCPFlagsSpec struct {
	Mask []string `yaml:"mask"`
	Comp []string `yaml:"comp"`
}

// OwnerMatch represents the owner match module (OUTPUT/POSTROUTING only).
// Any non-nil pointer emits the corresponding --flag; SocketExists emits --socket-exists.
type OwnerMatch struct {
	UIDOwner      *int   `yaml:"uid-owner"`
	GIDOwner      *int   `yaml:"gid-owner"`
	PIDOwner      *int   `yaml:"pid-owner"`
	SIDOwner      *int   `yaml:"sid-owner"`
	CmdOwner      string `yaml:"cmd-owner"`
	SocketExists  bool   `yaml:"socket-exists"`
}

// IPRangeMatch represents the iprange match module.
// Ranges are inclusive and written as "A.B.C.D-E.F.G.H".
type IPRangeMatch struct {
	SrcRange string `yaml:"src-range"`
	DstRange string `yaml:"dst-range"`
}

// LengthMatch represents the length match module.
// Value is a single length or a range "N:M".
type LengthMatch struct {
	Length string `yaml:"length"`
}

// TTLMatch represents the ttl match module (IPv4 only).
// Exactly one of eq/lt/gt must be set.
type TTLMatch struct {
	Eq *int `yaml:"eq"`
	Lt *int `yaml:"lt"`
	Gt *int `yaml:"gt"`
}

// HLMatch represents the hl match module (IPv6 only).
// Exactly one of eq/lt/gt must be set.
type HLMatch struct {
	Eq *int `yaml:"eq"`
	Lt *int `yaml:"lt"`
	Gt *int `yaml:"gt"`
}

// PktTypeMatch represents the pkttype match module.
// pkt-type ∈ {unicast, broadcast, multicast}.
type PktTypeMatch struct {
	PktType string `yaml:"pkt-type"`
}

// PhysDevMatch represents the physdev match module (bridge firewalls).
type PhysDevMatch struct {
	PhysDevIn        string `yaml:"physdev-in"`
	PhysDevOut       string `yaml:"physdev-out"`
	PhysDevIsIn      bool   `yaml:"physdev-is-in"`
	PhysDevIsOut     bool   `yaml:"physdev-is-out"`
	PhysDevIsBridged bool   `yaml:"physdev-is-bridged"`
}

// DSCPMatch represents the dscp match module.
// Exactly one of dscp or dscp-class must be set.
type DSCPMatch struct {
	DSCP      interface{} `yaml:"dscp"`       // int (0-63) or hex string
	DSCPClass string      `yaml:"dscp-class"` // e.g. "EF", "AF41"
	Neg       bool        `yaml:"neg"`
}

// TOSMatch represents the tos match module.
// Value is an int (0-255), a hex string, or a name (Minimize-Delay, Maximize-Throughput,
// Maximize-Reliability, Minimize-Cost, Normal-Service). An optional mask may be combined
// as VALUE/MASK.
type TOSMatch struct {
	TOS interface{} `yaml:"tos"`
	Neg bool        `yaml:"neg"`
}

// ECNMatch represents the ecn match module.
// Any combination of the three flags may be set; each adds the corresponding
// --ecn-tcp-cwr / --ecn-tcp-ece / --ecn-ip-ect fragment. ECT is an int 0-3.
type ECNMatch struct {
	TCPCWR bool `yaml:"tcp-cwr"`
	TCPECE bool `yaml:"tcp-ece"`
	IPECT  *int `yaml:"ip-ect"`
}

// HelperMatch represents the helper match module: matches packets that belong
// to connections being tracked by a specific conntrack helper (e.g. "ftp").
type HelperMatch struct {
	Name string `yaml:"name"`
}

// RealmMatch represents the realm match module (routing realm).
// Value is an int (decimal or "0xHEX"), optionally with /mask.
type RealmMatch struct {
	Realm interface{} `yaml:"realm"`
	Neg   bool        `yaml:"neg"`
}

// ClusterMatch represents the cluster match module (clustered NAT).
type ClusterMatch struct {
	TotalNodes int   `yaml:"total-nodes"`
	LocalNode  int   `yaml:"local-node"`
	LocalNodes []int `yaml:"local-nodes"` // alt: comma-separated list
	HashSeed   int   `yaml:"hash-seed"`
}

// CPUMatch represents the cpu match module.
type CPUMatch struct {
	CPU int `yaml:"cpu"`
}

// DevGroupMatch represents the devgroup match module.
type DevGroupMatch struct {
	SrcGroup interface{} `yaml:"src-group"` // int or "GROUP/MASK"
	DstGroup interface{} `yaml:"dst-group"`
}

// RpFilterMatch represents the rpfilter match module (reverse-path filter).
// Any subset of flags may be set.
type RpFilterMatch struct {
	Loose       bool `yaml:"loose"`
	ValidMark   bool `yaml:"validmark"`
	AcceptLocal bool `yaml:"accept-local"`
	Invert      bool `yaml:"invert"`
}

// QuotaMatch represents the quota match module.
type QuotaMatch struct {
	Quota int64 `yaml:"quota"`
}

// ConnBytesMatch represents the connbytes match module.
// Direction must be "original", "reply", or "both".
// Mode must be "packets", "bytes", or "avgpkt".
type ConnBytesMatch struct {
	Connbytes    string `yaml:"connbytes"` // single N or "N:M" range
	ConnbytesDir string `yaml:"connbytes-dir"`
	Mode         string `yaml:"connbytes-mode"`
	Neg          bool   `yaml:"neg"`
}

// ConnLabelMatch represents the connlabel match module.
// Either a numeric label (0-127) or a symbolic name (resolved against connlabel.conf).
type ConnLabelMatch struct {
	Label interface{} `yaml:"label"`
	Set   bool        `yaml:"set"`
	Neg   bool        `yaml:"neg"`
}

// NfacctMatch represents the nfacct match module.
type NfacctMatch struct {
	Name string `yaml:"name"`
}

// StringMatch represents the string match module.
// Exactly one of string or hex-string must be set. algo must be "bm" or "kmp".
// from/to are byte offsets; icase requests case-insensitive matching.
type StringMatch struct {
	Algo      string `yaml:"algo"`
	From      int    `yaml:"from"`
	To        int    `yaml:"to"`
	String    string `yaml:"string"`
	HexString string `yaml:"hex-string"`
	ICase     bool   `yaml:"icase"`
	Neg       bool   `yaml:"neg"`
}

// BPFMatch represents the bpf match module.
// One of bytecode (decoded cBPF instructions) or object-pinned (pinned eBPF object path).
type BPFMatch struct {
	Bytecode     string `yaml:"bytecode"`
	ObjectPinned string `yaml:"object-pinned"`
}

// U32Match represents the u32 match module.
// The expression follows the u32 mini-language (e.g. "0>>22&0x3C@ 12>>26&0x3F=0x10").
type U32Match struct {
	U32 string `yaml:"u32"`
	Neg bool   `yaml:"neg"`
}

// StatisticMatch represents the statistic match module.
// Mode: "random" (uses probability) or "nth" (uses every, packet, optionally).
type StatisticMatch struct {
	Mode        string  `yaml:"mode"`
	Probability float64 `yaml:"probability"`
	Every       int     `yaml:"every"`
	Packet      *int    `yaml:"packet"`
	Neg         bool    `yaml:"neg"`
}

// PolicyMatch represents the policy match module (IPsec).
// Direction must be "in" or "out". Policy must be "none" or "ipsec".
// strict + one-or-more elements is the typical shape.
type PolicyMatch struct {
	Dir      string          `yaml:"dir"`
	Policy   string          `yaml:"pol"`
	Strict   bool            `yaml:"strict"`
	Elements []PolicyElement `yaml:"elements"`
}

// PolicyElement is one --reqid / --spi / --proto / ... set within a policy match.
// Multiple elements render as multiple --next-separated blocks.
type PolicyElement struct {
	ReqID    int    `yaml:"reqid"`
	SPI      string `yaml:"spi"`      // decimal or 0xHEX
	Proto    string `yaml:"proto"`    // "ah", "esp", "ipcomp"
	Mode     string `yaml:"mode"`     // "tunnel" or "transport"
	TunnelSrc string `yaml:"tunnel-src"`
	TunnelDst string `yaml:"tunnel-dst"`
}

// IPv6HeaderMatch represents the ipv6header match module (IPv6-only).
// Headers is a comma-separated list of extension header names (hop-by-hop, dst, route,
// frag, auth, esp, none, proto).
type IPv6HeaderMatch struct {
	Header []string `yaml:"header"`
	Soft   bool     `yaml:"soft"`
	Neg    bool     `yaml:"neg"`
}

// FragMatch represents the frag (Fragment) match module (IPv6-only).
type FragMatch struct {
	ID     string `yaml:"id"`     // single id or "lo:hi" range
	FragRes bool  `yaml:"fragres"`
	First  bool   `yaml:"first"`
	More   bool   `yaml:"more"`
	Last   bool   `yaml:"last"`
}

// HBHMatch represents the hbh (Hop-By-Hop Options) match module (IPv6-only).
type HBHMatch struct {
	Length int    `yaml:"length"`
	Opts   string `yaml:"opts"` // comma-separated OPTIONNUM[:LEN]
	Neg    bool   `yaml:"neg"`
}

// DstOptsMatch represents the dst (Destination Options) match module (IPv6-only).
type DstOptsMatch struct {
	Length int    `yaml:"length"`
	Opts   string `yaml:"opts"`
	Neg    bool   `yaml:"neg"`
}

// RtMatch represents the rt (Routing Header) match module (IPv6-only).
type RtMatch struct {
	Type    *int   `yaml:"type"`
	Segsleft string `yaml:"segsleft"` // single N or "lo:hi"
	Length  int    `yaml:"length"`
	Reserve bool   `yaml:"reserve"`
	Addrs   string `yaml:"addrs"` // comma-separated list of IPv6 addresses (type 0)
	NotStrict bool `yaml:"not-strict"`
}

// MHMatch represents the mh (Mobility Header) match module (IPv6-only).
type MHMatch struct {
	Type string `yaml:"type"` // single name/number or "lo:hi"
	Neg  bool   `yaml:"neg"`
}
