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
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: yipt [--ipset-out FILE] input.yaml\n")
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

	prog, err := ir.Build(resolved)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ir build error: %v\n", err)
		os.Exit(1)
	}

	iptablesOut := codegen.RenderIptablesRestore(prog)
	ipsetScript := codegen.RenderIpsetScript(prog)

	fmt.Print(iptablesOut)

	if *ipsetOut != "" {
		if err := os.WriteFile(*ipsetOut, []byte(ipsetScript), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing ipset script: %v\n", err)
			os.Exit(1)
		}
	} else {
		if ipsetScript != "" {
			fmt.Println()
			fmt.Print(ipsetScript)
		}
	}
}
