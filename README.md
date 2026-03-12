# yipt

`yipt` (YAML iptables) is a compiler that translates a declarative YAML firewall configuration into `iptables-restore`-compatible commands and `ipset` shell scripts.

## Why

Raw `iptables` commands are verbose, repetitive, and easy to get wrong. `yipt` lets you express firewall rules in a concise, readable YAML format with named resource references, automatic IPv4/IPv6 rule splitting, and multiport compilation — then generates the exact iptables syntax you'd write by hand.

## How it works

The compiler runs a five-stage pipeline:

```
YAML file → Parser → Semantic Analysis → IR → Code Generation → output
```

1. **Parser** — reads the YAML into an AST
2. **Semantic analysis** — validates all `$resource` references and IP version constraints; warns about unused resources
3. **IR (Intermediate Representation)** — expands protocol lists, ICMP typesets, and mixed ipsets into individual rules; infers IP versions
4. **Code generation** — renders `iptables-restore` format and `ipset` shell commands

## Installation

```sh
go install github.com/appe233/yipt/cmd/yipt@latest
```

Or build from source:

```sh
git clone https://github.com/appe233/yipt.git
cd yipt.go
go build ./cmd/yipt
```

## Usage

```
yipt [--format FORMAT] [--ipset-out FILE] input.yaml
```

- `--format`: Output format (required when ipsets are used):
  - `iptables` — IPv4 rules only, no version prefix (pipe to `iptables-restore`)
  - `ip6tables` — IPv6 rules only, no version prefix (pipe to `ip6tables-restore`)
  - `ipset` — ipset commands only (pipe to `ipset restore`)
  - `combined` — all rules with `-4`/`-6` prefixes, no ipsets (default when no ipsets exist)
- `--ipset-out FILE`: (legacy) writes ipset script to FILE (ignored when `--format ipset` is used)
- Warnings (e.g. unused resources) are printed to **stderr** and do not affect the generated output.

Rules with unspecified IP version (`IPVersion=0`) appear in both `iptables` and `ip6tables` outputs.

### Applying the output

When your configuration uses ipsets, you must specify `--format` and generate separate outputs:

```sh
# Create ipsets first
yipt --format ipset firewall.yaml | ipset restore

# Then apply IPv4 rules
yipt --format iptables firewall.yaml | iptables-restore

# Then apply IPv6 rules
yipt --format ip6tables firewall.yaml | ip6tables-restore
```

For configurations without ipsets, the default combined format works:

```sh
yipt firewall.yaml | iptables-restore
```

## Configuration format

A configuration file has two top-level sections:

```yaml
resources:   # Named reusable sets (referenced with $name)
chains:      # iptables chains with rules
```

### Resources

Resources are named sets referenced in rules with a `$` prefix.

| Type | Compiled to | Referenced in |
|------|-------------|---------------|
| `ipset` | `ipset` hash:net entries | `s:`, `d:` fields |
| `portset` | `--multiport` rules | `sp:`, `dp:` fields |
| `icmp_typeset` | One rule per type | `icmp-type:` field |
| `icmpv6_typeset` | One rule per type | `icmpv6-type:` field |

```yaml
resources:

  trusted_networks:
    type: ipset
    elements:
      - 192.168.1.0/24
      - 10.0.0.0/24

  bgp_peers:
    type: ipset
    elements:
      - 172.20.0.0/14   # IPv4
      - fd00::/8        # IPv6 — automatically split into separate ipsets

  wg_ports:
    type: portset
    elements:
      - 34512
      - 21816
      - 22547

  basic_icmp_types:
    type: icmp_typeset
    elements:
      - 0   # Echo Reply
      - 3   # Destination Unreachable
      - 11  # Time Exceeded

  neighbor_discovery_types:
    type: icmpv6_typeset
    elements:
      - 135 # Neighbor Solicitation
      - 136 # Neighbor Advertisement
```

**Mixed ipsets** (containing both IPv4 and IPv6 addresses) are automatically split at compile time into two ipsets named `NAME_v4` and `NAME_v6`, and two separate rules are emitted for each rule that references them.

If a resource is defined but not referenced in any rule, `yipt` prints a warning to stderr:

```
warning: resource "$trusted_networks" is defined but never used
```

The warning does not affect the generated output or exit code.

### Chains

```yaml
chains:
  INPUT:
    policy: drop          # sets default policy (built-in chains only)
    filter:               # rules in the filter table
      - { ... }
  PREROUTING:
    mangle:               # rules in the mangle table
      - { ... }
    nat:                  # rules in the nat table
      - { ... }
  MY_CHAIN:               # user-defined chains need no policy
    filter:
      - { ... }
```

Supported tables and their built-in chains:

| Table | Built-in chains |
|-------|----------------|
| `filter` | `INPUT`, `FORWARD`, `OUTPUT` |
| `mangle` | `PREROUTING`, `INPUT`, `FORWARD`, `OUTPUT`, `POSTROUTING` |
| `nat` | `PREROUTING`, `INPUT`, `OUTPUT`, `POSTROUTING` |

### Rule fields

#### Interfaces

| Field | Description |
|-------|-------------|
| `i` | Match input interface |
| `i!` | Negated input interface |
| `o` | Match output interface |
| `o!` | Negated output interface |

#### Addresses

| Field | Description |
|-------|-------------|
| `s` | Source address or CIDR (or `$ipset`) |
| `s!` | Negated source |
| `d` | Destination address or CIDR (or `$ipset`) |
| `d!` | Negated destination |

#### Protocol and ports

| Field | Description |
|-------|-------------|
| `p` | Protocol: `tcp`, `udp`, `icmp`, `ipv6-icmp`; or a list `[tcp, udp]` |
| `sp` | Source port: integer, range `"1024:65535"`, list `[80, 443]`, or `$portset` |
| `dp` | Destination port (same formats) |
| `sp!` | Negated source port |
| `dp!` | Negated destination port |
| `syn` | Match TCP SYN flag (`true`/`false`) |

Port lists are compiled to `--multiport`. Ranges use the `start:end` syntax. A single-element list is compiled as a plain `--dport`/`--sport`.

#### ICMP

| Field | Description |
|-------|-------------|
| `icmp-type` | IPv4 ICMP type: numeric, named string (e.g. `echo-reply`), or `$icmp_typeset` |
| `icmpv6-type` | ICMPv6 type: numeric or `$icmpv6_typeset` |

When an `$icmp_typeset` or `$icmpv6_typeset` with N elements is referenced, the single rule expands into N rules.

#### Jump targets

| `j:` value | Generated target | Notes |
|------------|------------------|-------|
| `accept` | `ACCEPT` | |
| `drop` | `DROP` | |
| `return` | `RETURN` | |
| `reject` | `REJECT` | Combine with `reject-with:` |
| `log` | `LOG` | Combine with `log-prefix:` |
| `mark` | `MARK` | Combine with `set-mark:` |
| `tproxy` | `TPROXY` | Combine with `on-ip:`, `on-port:`, `tproxy-mark:` |
| `masquerade` | `MASQUERADE` | Optionally combine with `to-ports:` |
| `snat` | `SNAT` | Combine with `to-source:`; optionally `to-ports:` |
| `dnat` | `DNAT` | Combine with `to-destination:`; optionally `to-ports:` |
| `redirect` | `REDIRECT` | Optionally combine with `to-ports:` |
| Any other string | Used as-is | Jump to user-defined chain |

```yaml
- {p: tcp, dp: 113, reject-with: tcp-reset, j: reject}
- {match: {limit: {limit: 1/second, limit-burst: 100}}, log-prefix: "iptables[DOS]: ", j: log}
- {p: [udp, tcp], on-ip: 127.0.0.1, on-port: 12345, tproxy-mark: 1, j: tproxy}
- {p: [udp, tcp], set-mark: 1, j: mark}
- {o: eth0, j: masquerade}
- {p: tcp, dp: 80, to-destination: 192.168.1.10:8080, j: dnat}
- {s: 192.168.1.0/24, to-source: 203.0.113.1, j: snat}
```

#### Match modules

The `match:` field supports multiple modules in a single rule:

```yaml
match:
  conntrack:
    ctstate: [ESTABLISHED, RELATED, NEW, INVALID]

  recent:
    name: SSH
    set: true       # --set
    update: true    # --update
    seconds: 300
    hitcount: 10
    rsource: true
    rttl: true

  limit:
    limit: 1/second
    limit-burst: 100

  mark:
    mark: "0xff"    # hex or decimal

  socket: {}        # no options needed

  addrtype:
    dst-type: BROADCAST   # MULTICAST, ANYCAST, etc.

  mac:
    mac-source: "aa:bb:cc:dd:ee:ff"

  time:
    timestart: "08:00"
    timestop: "18:00"
    weekdays: "Mon,Tue,Wed,Thu,Fri"

  state:            # legacy state module (prefer conntrack)
    state: [ESTABLISHED, RELATED]
```

Multiple modules can be combined:

```yaml
- match:
    recent: {name: SSH, update: true, seconds: 300, hitcount: 10}
    limit:  {limit: 1/second, limit-burst: 100}
  log-prefix: "iptables[SSH-brute]: "
  j: log
```

#### Comment

```yaml
- {p: udp, dp: $wg_ports, j: accept, comment: "WireGuard peers"}
```

Maximum 29 characters (iptables `--comment` limit). Compiled to `-m comment --comment "..."`.

## Example

```yaml
resources:
  trusted_networks:
    type: ipset
    elements:
      - 192.168.1.0/24
      - 10.0.0.0/24

  wg_ports:
    type: portset
    elements: [34512, 21816, 22547]

  basic_icmp_types:
    type: icmp_typeset
    elements: [0, 3, 11, 12]

chains:
  INPUT:
    policy: drop
    filter:
      - {i: lo, j: accept}
      - {match: {conntrack: {ctstate: [ESTABLISHED, RELATED]}}, j: accept}
      - {match: {conntrack: {ctstate: [INVALID]}}, j: drop}
      - {s: $trusted_networks, p: tcp, dp: 22, syn: true,
         match: {conntrack: {ctstate: [NEW]}}, j: accept}
      - {p: udp, dp: $wg_ports, j: accept, comment: "WireGuard peers"}
      - {p: icmp, icmp-type: $basic_icmp_types, j: accept}

  FORWARD:
    policy: drop
    filter: []

  OUTPUT:
    policy: accept
    filter: []
```

Running `yipt firewall.yaml` produces:

```
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -m conntrack --ctstate INVALID -j DROP
-4 -A INPUT -m set --match-set trusted_networks src -p tcp --dport 22 --syn -m conntrack --ctstate NEW -j ACCEPT
-A INPUT -p udp -m multiport --dports 34512,21816,22547 -m comment --comment "WireGuard peers" -j ACCEPT
-4 -A INPUT -p icmp --icmp-type 0 -j ACCEPT
-4 -A INPUT -p icmp --icmp-type 3 -j ACCEPT
-4 -A INPUT -p icmp --icmp-type 11 -j ACCEPT
-4 -A INPUT -p icmp --icmp-type 12 -j ACCEPT
COMMIT
```

The ipset script:

```sh
ipset create -exist trusted_networks hash:net family inet
ipset add trusted_networks 192.168.1.0/24
ipset add trusted_networks 10.0.0.0/24
```

## Reference

See [`rule_files/all_features.yaml`](rule_files/all_features.yaml) for a complete example covering every supported feature: mixed ipsets, ICMP/ICMPv6 typesets, conntrack, recent, limit, mark, socket, addrtype, tproxy, protocol lists, port ranges, negations, and more.

## Development

```sh
go test ./...
```

The test suite covers all pipeline stages — parser, semantic analysis, IR expansion, code generation — plus end-to-end integration tests against `all_features.yaml` and `nat_example.yaml`.
