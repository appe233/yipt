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
```

### Rule fields

| Field | Description |
|-------|-------------|
| `i` / `i!` | Input interface (negated with `!`) |
| `o` / `o!` | Output interface |
| `s` / `s!` | Source address/ipset |
| `d` / `d!` | Destination address/ipset |
| `p` | Protocol (`tcp`, `udp`, `icmp`, `ipv6-icmp`); can be a list `[tcp, udp]` |
| `sp` / `dp` | Source/destination port; single, list `[80, 443]`, or range `[1024:65535]` |
| `sp!` / `dp!` | Negated port match |
| `syn` | Match TCP SYN flag |
| `icmp-type` | ICMP type (numeric, named string, or `$resource`) |
| `icmpv6-type` | ICMPv6 type (numeric or `$resource`) |
| `j` | Jump target (`accept`, `drop`, `return`, `reject`, `log`, `tproxy`, `mark`, or user chain) |
| `reject-with` | Rejection type (e.g., `tcp-reset`) when `j: reject` |
| `log-prefix` | Log prefix string when `j: log` |
| `comment` | Rule comment |
| `set-mark` | Mark value for `j: mark` target |
| `on-ip` / `on-port` / `tproxy-mark` | tproxy target parameters |
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
```

Multiple match modules can be combined in a single `match` object.
