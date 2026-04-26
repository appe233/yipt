# AGENTS.md

This file is the working guide for Codex and other coding agents in this repository.

## Project Overview

`yipt.go` is a YAML-to-iptables compiler written in Go. It translates a declarative firewall configuration into `iptables-restore` / `ip6tables-restore` text and `ipset restore` scripts.

The primary product surface is the YAML rule format. The canonical living example is `rule_files/all_features.yaml`.

## Working Rules

- Preserve existing YAML compatibility unless the user explicitly asks for a breaking change.
- Keep changes vertical: YAML surface, semantic validation, IR lowering, codegen, fixture, and tests should move together.
- Prefer validation in `internal/sema` over letting bad input reach codegen.
- Keep generated output deterministic; tests assert exact fragments in many places.
- Do not rewrite unrelated Claude-era work in the dirty tree. There is substantial uncommitted feature work, so inspect before editing.

## Verification

Run these before handing off code changes:

```sh
go test ./...
go build ./...
```

For rule-format or codegen changes, also smoke the full fixture:

```sh
go run ./cmd/yipt --format combined rule_files/all_features.yaml
go run ./cmd/yipt --format ipset rule_files/all_features.yaml
```

On Linux, when available, validate rendered syntax with:

```sh
go run ./cmd/yipt --format iptables rule_files/all_features.yaml | sudo iptables-restore --test
go run ./cmd/yipt --format ip6tables rule_files/all_features.yaml | sudo ip6tables-restore --test
```

## Pipeline

The compiler flow is:

```text
YAML -> parser -> AST -> sema -> IR -> codegen -> output text
```

The implementation intentionally follows this shape:

| Stage | Files | Responsibility |
|---|---|---|
| YAML surface | `internal/ast/ast.go` | Structs and `Rule.UnmarshalYAML`; unknown rule fields are rejected here. |
| Validation | `internal/sema/sema.go` | Resource resolution, table/chain constraints, option validation, IP-family conflicts, warnings. |
| IR lowering | `internal/ir/ir.go` | Rule fan-out, mixed ipset splitting, IP-version tagging, target normalization. |
| Rendering | `internal/codegen/iptables.go`, `internal/codegen/ipset.go` | `iptables-restore` text and `ipset` scripts. |
| Fixtures | `rule_files/*.yaml` | End-to-end examples. `all_features.yaml` is the main coverage fixture. |
| Tests | `internal/**/*_test.go`, `cmd/yipt/integration_test.go` | Unit and integration coverage. |

## Feature Addition Checklist

For a new rule field, target, match module, table, or ipset feature:

1. Add the YAML field or struct in `internal/ast/ast.go`.
2. Add the key to `Rule.UnmarshalYAML` if it is a rule-level field.
3. Add semantic validation in `internal/sema/sema.go`.
4. Add IR fields and lowering in `internal/ir/ir.go`.
5. Add rendering in `internal/codegen/iptables.go` or `internal/codegen/ipset.go`.
6. Add an example to `rule_files/all_features.yaml` or a focused fixture.
7. Add focused tests at the lowest useful layer plus an integration assertion for user-visible output.
8. Update `README.md` when the public YAML surface changes.

## Important Files

- `cmd/yipt/main.go` - CLI flags and pipeline orchestration.
- `internal/ast/ast.go` - YAML model and strict rule unmarshaling.
- `internal/sema/sema.go` - semantic validation and resource classification.
- `internal/sema/ipversion.go` - IP-family classification helpers.
- `internal/ir/ir.go` - rule expansion and table/chain construction.
- `internal/codegen/iptables.go` - `iptables-restore` rendering.
- `internal/codegen/ipset.go` - `ipset restore` rendering.
- `rule_files/all_features.yaml` - broad feature fixture and reference example.
- `write-a-detailed-and-buzzing-wozniak.md` - staged roadmap through full iptables coverage.

## Current Roadmap State

Phases 1 through 9 of `write-a-detailed-and-buzzing-wozniak.md` are substantially implemented in the current working tree. Phase 9 packet-modification targets are present across AST, sema, IR, codegen, fixture, and integration tests.

Known follow-up work:

- Keep `README.md` in sync with newly added YAML fields.
- Add stronger AST tests for every boolean field, because some current boolean unmarshaling uses string comparison.
- Run `iptables-restore --test` / `ip6tables-restore --test` on a Linux runner for generated syntax validation.
- Continue Phase 10 exotic matches and security-table polish from the roadmap.

## YAML Surface Summary

Top-level shape:

```yaml
resources:   # named reusable sets, referenced with $name
chains:      # iptables chains with per-table rule lists
```

Supported tables:

| Table | Built-in chains |
|---|---|
| `raw` | `PREROUTING`, `OUTPUT` |
| `filter` | `INPUT`, `FORWARD`, `OUTPUT` |
| `nat` | `PREROUTING`, `INPUT`, `OUTPUT`, `POSTROUTING` |
| `mangle` | `PREROUTING`, `INPUT`, `FORWARD`, `OUTPUT`, `POSTROUTING` |
| `security` | `INPUT`, `FORWARD`, `OUTPUT` |

Supported resource types:

| Type | Purpose |
|---|---|
| `ipset` | Address, MAC, port, tuple, bitmap, or list sets used in `s:` / `d:` and SET target fields. |
| `portset` | Port lists compiled to `multiport`. |
| `icmp_typeset` | IPv4 ICMP type expansion. |
| `icmpv6_typeset` | IPv6 ICMP type expansion. |

Supported ipset `set-type` values include `hash:net`, `hash:ip`, `hash:ip,port`, `hash:net,port`, `hash:ip,port,ip`, `hash:ip,port,net`, `hash:net,port,net`, `hash:mac`, `hash:net,iface`, `hash:ip,mark`, `bitmap:ip`, `bitmap:ip,mac`, `bitmap:port`, and `list:set`.

Common target families now covered include NAT (`snat`, `dnat`, `masquerade`, `redirect`, `netmap`), packet marks (`mark`, `connmark`), conntrack bypass/config (`ct`, `notrack`), TCP polish (`tcpmss`, `tcp-flags`, `tcp-option`, `fragment`), userspace integration (`nflog`, `nfqueue`, `set`), and Phase 9 packet-modification targets (`classify`, `dscp`, `tos`, `ecn`, `ttl`, `hl`, `secmark`, `connsecmark`, `synproxy`, `tee`, `trace`, `audit`, `checksum`, `clusterip`, `idletimer`, `rateest`, `led`).

