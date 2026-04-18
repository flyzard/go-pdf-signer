package main

import (
	"fmt"
	"os"

	"github.com/flyzard/pdf-signer/internal/cli"
)

const version = "0.1.0"

const usageTemplate = `pdf-signer %s — PAdES-LT digital signature tool

High-level (recommended):
  pdf-signer sign-start   --input=FILE --signer-cert=FILE --state-out=FILE [options]
  pdf-signer sign-finish  --state=FILE --signature=FILE --output=FILE
  pdf-signer sign-local   --input=FILE --output=FILE --key=FILE [options]  (CI/testing only)

Low-level primitives (legacy; kept for back-compat during migration):
  pdf-signer prepare      --input=FILE --output=FILE --signer-name=NAME [options]
  pdf-signer embed        --input=FILE --output=FILE --cms=FILE
  pdf-signer finalize     --input=FILE --output=FILE [--tsa-url=URL]

Other:
  pdf-signer verify       --input=FILE
  pdf-signer version
`

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "sign-start":
		cli.RunSignStart(os.Args[2:])
	case "sign-finish":
		cli.RunSignFinish(os.Args[2:])
	case "sign-local":
		cli.RunSignLocal(os.Args[2:])
	case "prepare":
		cli.RunPrepare(os.Args[2:])
	case "embed":
		cli.RunEmbed(os.Args[2:])
	case "finalize":
		cli.RunFinalize(os.Args[2:])
	case "verify":
		cli.RunVerify(os.Args[2:])
	case "version":
		fmt.Printf("pdf-signer %s\n", version)
	case "-h", "--help", "help":
		printUsage()
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, usageTemplate, version)
}
