package main

import (
	"flag"
	"fmt"
	"os"

	"yipt/internal/codegen"
	"yipt/internal/ir"
	"yipt/internal/parser"
	"yipt/internal/sema"
)

func main() {
	ipsetOut := flag.String("ipset-out", "", "Write ipset script to FILE instead of stdout")
	format := flag.String("format", "", "Output format: iptables, ip6tables, combined, ipset")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: yipt [--format FORMAT] [--ipset-out FILE] input.yaml\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

	inputFile := flag.Arg(0)

	doc, err := parser.ParseFile(inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse error: %v\n", err)
		os.Exit(1)
	}

	resolved, err := sema.Analyze(doc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "semantic error: %v\n", err)
		os.Exit(1)
	}
	for _, w := range resolved.Warnings {
		fmt.Fprintln(os.Stderr, w)
	}

	prog, err := ir.Build(resolved)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ir build error: %v\n", err)
		os.Exit(1)
	}

	// Detect if ipsets are present.
	hasIpsets := len(prog.IPv4Ipsets) > 0 || len(prog.IPv6Ipsets) > 0

	// Smart default: if ipsets exist and no format specified, error with helpful message.
	if *format == "" {
		if hasIpsets {
			fmt.Fprintf(os.Stderr, "Error: Configuration uses ipsets. Please specify --format:\n")
			fmt.Fprintf(os.Stderr, "  --format iptables   (IPv4 rules only, pipe to iptables-restore)\n")
			fmt.Fprintf(os.Stderr, "  --format ip6tables  (IPv6 rules only, pipe to ip6tables-restore)\n")
			fmt.Fprintf(os.Stderr, "  --format ipset      (ipset commands, pipe to ipset restore)\n")
			fmt.Fprintf(os.Stderr, "  --format combined   (all rules with -4/-6 prefixes, no ipsets)\n")
			os.Exit(1)
		}
		*format = "combined"
	}

	// Handle output based on format.
	switch *format {
	case "iptables":
		fmt.Print(codegen.RenderIptablesRestoreIPv4(prog))
	case "ip6tables":
		fmt.Print(codegen.RenderIptablesRestoreIPv6(prog))
	case "combined":
		backend := codegen.IptablesBackend{}
		fmt.Print(backend.Render(prog))
	case "ipset":
		if *ipsetOut != "" {
			fmt.Fprintf(os.Stderr, "Warning: --ipset-out is ignored when --format ipset is used\n")
		}
		ipsetScript := codegen.RenderIpsetScript(prog)
		if ipsetScript == "" {
			fmt.Print("# No ipsets defined\n")
		} else {
			fmt.Print(ipsetScript)
		}
	default:
		fmt.Fprintf(os.Stderr, "Error: invalid format %q\n", *format)
		os.Exit(1)
	}

	// Handle legacy --ipset-out flag (only for non-ipset formats).
	if *ipsetOut != "" && *format != "ipset" {
		ipsetScript := codegen.RenderIpsetScript(prog)
		if err := os.WriteFile(*ipsetOut, []byte(ipsetScript), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing ipset script: %v\n", err)
			os.Exit(1)
		}
	}
}
