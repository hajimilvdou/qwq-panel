// SPDX-License-Identifier: AGPL-3.0-only

// Command qwq is the host binary. Roles run as subcommands of the same static
// binary but always as separate processes (ARCH §3): serve-controller,
// serve-agent, privileged, doctor, recover, setup-token, backup, restore.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/qwq-panel/qwq/internal/buildinfo"
	"github.com/qwq-panel/qwq/internal/doctor"
	"github.com/qwq-panel/qwq/internal/sandbox"
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
		fmt.Fprintln(stdout, "qwq", buildinfo.Read())
		return 0
	case "help", "--help", "-h":
		usage(stdout)
		return 0
	case "serve-controller":
		return runServe(args[1:], stdout, stderr)
	case "serve-agent":
		return runServeAgent(args[1:], stdout, stderr)
	case "privileged":
		return runPrivileged(args[1:], os.Stdin, stdout, stderr)
	case "recover":
		return runRecover(args[1:], os.Stdin, stdout, stderr)
	case "access":
		return runAccess(args[1:], stdout, stderr)
	case "setup-token":
		return runSetupToken(args[1:], stdout, stderr)
	case "doctor":
		return runDoctor(args[1:], doctor.System(), stdout, stderr)
	case doctorDBCommand:
		return runDoctorDB(args[1:], stdout, stderr)
	case "support-bundle":
		return runSupportBundle(args[1:], stdout, stderr)
	case "backup":
		return runBackup(args[1:], stdout, stderr)
	case "restore":
		return runRestore(args[1:], stdout, stderr)
	case "firewall-restore":
		return runFirewallRestore(args[1:], stderr, sandbox.NewCapabilityClient(sandbox.DefaultCapabilitySocket))
	case "plugin":
		return runPlugin(args[1:], stdout, stderr)
	case "rotate-master-key":
		return runRotateMasterKey(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "qwq: unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: qwq <command>

commands:
  serve-controller  run the standalone/controller host process
  serve-agent       run the local plugin supervisor
  privileged        install/render plugin units (root only)
  recover           reset an administrator (root only, local console)
  access            show or reset live panel listen address, entry path and domain (root only)
  setup-token       print the one-time first-setup link (root only)
  version           print version and ABI information
  doctor            check the host and the installation (read-only)
  support-bundle    collect redacted diagnostics into a tarball (root only)
  backup            write a consistent backup of data, keys and configuration
  restore           restore a backup (root only, controller stopped)
  firewall-restore  restore the saved qwq firewall through its capability helper
  plugin            author, sign, verify, or bootstrap signed plugin packages
  rotate-master-key rotate the AES-256 master key and re-encrypt stored secrets (root only)
  help              show this help
`)
}
