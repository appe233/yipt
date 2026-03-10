# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`yipt.go` is a YAML-to-iptables compiler written in Go. It translates a declarative YAML firewall configuration into `iptables`/`ip6tables` commands.

## YAML Configuration Format

The primary artifact in this repo is the YAML rule format. The reference file `rule_files/all_features.yaml` documents every supported feature.

### Top-level structure

```yaml
resources:   # Named reusable sets (referenced via $name)
chains:      # iptables chains with rules
```

### Resource types

| Type | Purpose |
|------|---------|
| `ipset` | IP/subnet sets used in `s:` / `d:` fields |
| `portset` | Port sets compiled to `--multiport` rules |
| `icmp_typeset` | IPv4 ICMP type groups |
| `icmpv6_typeset` | ICMPv6 type groups |

Resources are referenced in rules with a `$` prefix (e.g., `$trusted_networks`, `$wg_ports`).

### Chain structure

```yaml
chains:
  CHAIN_NAME:
    policy: drop|accept          # optional; sets default policy (built-in chains only)
    filter:                      # rules for the filter table
      - { ... }
    mangle:                      # rules for the mangle table
      - { ... }
    nat:                         # rules for the nat table
      - { ... }
```

Supported tables and their built-in chains:

| Table | Built-in chains |
|-------|----------------|
| `filter` | `INPUT`, `FORWARD`, `OUTPUT` |
| `mangle` | `PREROUTING`, `INPUT`, `FORWARD`, `OUTPUT`, `POSTROUTING` |
| `nat` | `PREROUTING`, `INPUT`, `OUTPUT`, `POSTROUTING` |

### Rule fields

| Field | Description |
|-------|-------------|
| `i` / `i!` | Input interface (negated with `!`) |
| `o` / `o!` | Output interface |
| `s` / `s!` | Source address/ipset |
| `d` / `d!` | Destination address/ipset |
| `p` | Protocol (`tcp`, `udp`, `icmp`, `ipv6-icmp`); can be a list `[tcp, udp]` |
| `sp` / `sp!` | Source port; single, list `[80, 443]`, range `[1024:65535]`, or `$portset` |
| `dp` / `dp!` | Destination port (same formats) |
| `syn` | Match TCP SYN flag |
| `icmp-type` | ICMP type (numeric, named string, or `$resource`) |
| `icmpv6-type` | ICMPv6 type (numeric or `$resource`) |
| `j` | Jump target (`accept`, `drop`, `return`, `reject`, `log`, `tproxy`, `mark`, `masquerade`, `snat`, `dnat`, `redirect`, or user chain) |
| `reject-with` | Rejection type (e.g., `tcp-reset`) when `j: reject` |
| `log-prefix` | Log prefix string (max 29 chars) when `j: log` |
| `comment` | Rule comment (max 29 chars) |
| `set-mark` | Mark value for `j: mark` |
| `on-ip` / `on-port` / `tproxy-mark` | tproxy target parameters |
| `to-source` | SNAT target address (with optional port) |
| `to-destination` | DNAT target address (with optional port) |
| `to-ports` | Port range for `masquerade`, `snat`, `dnat`, `redirect` |
| `match` | Extended match modules (see below) |

### `match` sub-fields

```yaml
match:
  conntrack:
    ctstate: [ESTABLISHED, RELATED, NEW, INVALID]
  recent:
    name: SSH
    set: true          # --set
    update: true       # --update
    seconds: 300
    hitcount: 10
    rsource: true
    rttl: true
  limit:
    limit: 1/second
    limit-burst: 100
  mark:
    mark: "0xff"
  socket: {}           # socket match (no options needed)
  addrtype:
    dst-type: BROADCAST|MULTICAST|ANYCAST|...
  mac:
    mac-source: "aa:bb:cc:dd:ee:ff"   # IPv4 only
  time:
    timestart: "08:00"
    timestop: "18:00"
    weekdays: "Mon,Tue,Wed,Thu,Fri"
  state:               # legacy module; prefer conntrack
    state: [ESTABLISHED, RELATED]
```

Multiple match modules can be combined in a single `match` object.
