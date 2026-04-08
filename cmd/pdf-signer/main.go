package main

import (
	"fmt"
	"os"

	"github.com/flyzard/pdf-signer/internal/cli"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
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
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `pdf-signer %s — PAdES-LT digital signature tool

Usage:
  pdf-signer prepare   --input=FILE --output=FILE --signer-name=NAME [options]
  pdf-signer embed     --input=FILE --output=FILE --cms=FILE [--field-name=NAME]
  pdf-signer finalize  --input=FILE --output=FILE [--tsa-url=URL]
  pdf-signer verify    --input=FILE
  pdf-signer version
`, version)
}
