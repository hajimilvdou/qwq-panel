// SPDX-License-Identifier: AGPL-3.0-only

// Command qwqctl is the operator and developer CLI: plugin keygen/pack/sign/
// verify (P2-T3) and API access. It never talks to the database directly;
// every change goes through the public API as an operation.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/qwq-panel/qwq/internal/buildinfo"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "qwqctl", buildinfo.Read())
		return 0
	case "help", "--help", "-h":
		usage(stdout)
		return 0
	case "keygen":
		return runKeygen(args[1:], stdout, stderr)
	case "pack":
		return runPack(args[1:], stdout, stderr)
	case "sign":
		return runSign(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "qwqctl: unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: qwqctl <command> [flags] [args]

commands:
  version                       print version and ABI information
  keygen -out <prefix>          generate an Ed25519 plugin signing key pair
  pack -src <dir> -out <ppkg>   build a package from a directory
  sign -key <priv> <ppkg>       replace signatures/manifest.sig in place
  verify -trust <pub> <ppkg>    verify a package against trusted keys
  help                          show this help

Run "qwqctl <command> -h" for the flags of one command.
`)
}
