// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/qwq-panel/qwq/internal/sandbox"
)

// privilegedEUID is os.Geteuid. Tests replace it so the refusal path is
// covered without actually dropping privileges.
var privilegedEUID = os.Geteuid

const (
	// maxSpecBytes bounds the JSON spec read from -spec.
	maxSpecBytes = 64 << 10
	// maxCredentialBytes bounds the token read from stdin.
	maxCredentialBytes = 4 << 10
)

// privilegedOutcome is the JSON object every privileged command prints to
// stdout. Errors are reported in the same shape so a caller only has one
// format to parse; the human-readable line goes to stderr for the journal.
type privilegedOutcome struct {
	OK         bool     `json:"ok"`
	Command    string   `json:"command"`
	ID         string   `json:"id,omitempty"`
	Group      string   `json:"group,omitempty"`
	Files      []string `json:"files,omitempty"`
	Dirs       []string `json:"dirs,omitempty"`
	Tmpfiles   string   `json:"tmpfiles,omitempty"`
	Credential string   `json:"credential,omitempty"`
	Error      string   `json:"error,omitempty"`
}

// runPrivileged implements `qwq privileged ...`: the only role that writes
// below /etc/systemd/system, /etc/tmpfiles.d and /run/qwq for a plugin. It
// refuses to run unless it is root on Linux, never starts a listener and never
// talks to a plugin, so a compromised agent cannot reach it (the agent only
// gets polkit start/stop/kill).
//
// Exit status: 0 success, 1 error, 2 usage.
func runPrivileged(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		privilegedUsage(stderr)
		return 2
	}
	command := args[0]
	switch command {
	case "help", "-h", "--help":
		privilegedUsage(stdout)
		return 0
	}
	if runtime.GOOS != "linux" {
		return privilegedFail(stdout, stderr, privilegedOutcome{Command: command},
			errors.New("qwq privileged is only supported on Linux"))
	}
	if privilegedEUID() != 0 {
		return privilegedFail(stdout, stderr, privilegedOutcome{Command: command},
			errors.New("qwq privileged must run as root"))
	}
	switch command {
	case "render":
		return privilegedRender(args[1:], stdin, stdout, stderr)
	case "install":
		return privilegedInstall(args[1:], stdin, stdout, stderr)
	case "remove":
		return privilegedRemove(args[1:], stdout, stderr)
	case "verify-entrypoint":
		return privilegedVerifyEntrypoint(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "qwq privileged: unknown command %q\n\n", command)
		privilegedUsage(stderr)
		return 2
	}
}

func privilegedUsage(w io.Writer) {
	fmt.Fprint(w, `usage: qwq privileged <command> [flags]

Linux only, root only. This role writes the systemd units, the per-plugin
group, the credential and the runtime directories of one plugin. It never
starts a listener and never talks to a plugin.

commands:
  render             render the unit files for one plugin into a directory
  install            install one plugin's units, group, credential and dirs
  remove             remove one plugin's units, group, credential and dirs
  verify-entrypoint  check the installed entrypoint digest (ExecStartPre)
  help               show this help

Every command prints one JSON object to stdout and exits 0 (ok), 1 (error) or
2 (usage). Tokens are read from stdin, never from argv.
`)
}

// privilegedFail prints the outcome and the human-readable error.
func privilegedFail(stdout, stderr io.Writer, out privilegedOutcome, err error) int {
	out.OK = false
	out.Error = err.Error()
	writeJSON(stdout, out)
	fmt.Fprintf(stderr, "qwq privileged %s: %v\n", out.Command, err)
	return 1
}

// privilegedSucceed prints the outcome.
func privilegedSucceed(stdout, stderr io.Writer, out privilegedOutcome) int {
	out.OK = true
	writeJSON(stdout, out)
	fmt.Fprintf(stderr, "qwq privileged %s: ok\n", out.Command)
	return 0
}

func writeJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// privilegedRender writes the rendered files for one plugin below outDir:
// systemd/ holds the unit files, tmpfiles.d/ the runtime-directory snippet.
// It is the dry run an operator or CI uses to inspect a unit before installing
// it.
func privilegedRender(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	out := privilegedOutcome{Command: "render"}
	fs := flag.NewFlagSet("render", flag.ContinueOnError)
	fs.SetOutput(stderr)
	specPath := fs.String("spec", "", "path to the unit spec JSON (\"-\" for stdin)")
	outDir := fs.String("out", "", "directory to write the rendered files into")
	if err := fs.Parse(args); err != nil {
		return privilegedParseError(err)
	}
	if *outDir == "" || *specPath == "" {
		fmt.Fprintln(stderr, "qwq privileged render: -spec and -out are required")
		return 2
	}
	spec, err := readSpec(*specPath, stdin)
	if err != nil {
		return privilegedFail(stdout, stderr, out, err)
	}
	files, err := sandbox.RenderUnit(spec)
	if err != nil {
		return privilegedFail(stdout, stderr, out, err)
	}
	tmpfiles, err := sandbox.RenderTmpfiles(spec)
	if err != nil {
		return privilegedFail(stdout, stderr, out, err)
	}
	tmpfilesName, err := sandbox.TmpfilesName(spec.ID)
	if err != nil {
		return privilegedFail(stdout, stderr, out, err)
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	unitDir := filepath.Join(*outDir, "systemd")
	for _, name := range names {
		path := filepath.Join(unitDir, filepath.FromSlash(name))
		if err := sandbox.WriteFileAtomic(path, files[name], sandbox.UnitFileMode); err != nil {
			return privilegedFail(stdout, stderr, out, err)
		}
		out.Files = append(out.Files, path)
	}
	tmpfilesPath := filepath.Join(*outDir, "tmpfiles.d", tmpfilesName)
	if err := sandbox.WriteFileAtomic(tmpfilesPath, tmpfiles, sandbox.TmpfilesFileMode); err != nil {
		return privilegedFail(stdout, stderr, out, err)
	}
	out.Tmpfiles = tmpfilesPath
	out.ID = spec.ID
	return privilegedSucceed(stdout, stderr, out)
}

// installFlags are shared by install and remove so both hit the same paths.
type installFlags struct {
	unitDir     *string
	tmpfilesDir *string
	runtimeBase *string
	agentUser   *string
}

func addInstallFlags(fs *flag.FlagSet) installFlags {
	return installFlags{
		unitDir:     fs.String("unit-dir", sandbox.DefaultUnitDir, "systemd unit directory"),
		tmpfilesDir: fs.String("tmpfiles-dir", sandbox.DefaultTmpfilesDir, "tmpfiles.d directory"),
		runtimeBase: fs.String("runtime-base", sandbox.DefaultRuntimeBase, "systemd %t for system services"),
		agentUser:   fs.String("agent-user", sandbox.DefaultAgentUser, "user that owns the plugin socket"),
	}
}

func (f installFlags) installer() sandbox.Installer {
	return sandbox.Installer{
		UnitDir:     *f.unitDir,
		TmpfilesDir: *f.tmpfilesDir,
		RuntimeBase: *f.runtimeBase,
		AgentUser:   *f.agentUser,
		Runner:      sandbox.ExecRunner{},
	}
}

// privilegedInstall performs the whole privileged half of a plugin install.
// The token is optional but read from stdin, never argv: argv is visible in
// /proc and in the journal.
func privilegedInstall(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	out := privilegedOutcome{Command: "install"}
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(stderr)
	specPath := fs.String("spec", "", "path to the unit spec JSON (\"-\" for stdin)")
	credentialStdin := fs.Bool("credential-stdin", false, "read the plugin token from stdin")
	flags := addInstallFlags(fs)
	if err := fs.Parse(args); err != nil {
		return privilegedParseError(err)
	}
	if *specPath == "" {
		fmt.Fprintln(stderr, "qwq privileged install: -spec is required")
		return 2
	}
	if *credentialStdin && *specPath == "-" {
		fmt.Fprintln(stderr, "qwq privileged install: -spec - and -credential-stdin cannot share stdin")
		return 2
	}
	spec, err := readSpec(*specPath, stdin)
	if err != nil {
		return privilegedFail(stdout, stderr, out, err)
	}
	var credential []byte
	if *credentialStdin {
		if credential, err = readToken(stdin); err != nil {
			return privilegedFail(stdout, stderr, out, err)
		}
	}
	res, err := flags.installer().Install(context.Background(), spec, credential)
	out.ID, out.Group = res.ID, res.Group
	out.Files, out.Dirs = res.UnitFiles, res.Dirs
	out.Tmpfiles, out.Credential = res.Tmpfiles, res.Credential
	if err != nil {
		return privilegedFail(stdout, stderr, out, err)
	}
	return privilegedSucceed(stdout, stderr, out)
}

// privilegedRemove deletes everything install created. The caller must have
// stopped the plugin first; removing a unit file does not stop a service.
func privilegedRemove(args []string, stdout, stderr io.Writer) int {
	out := privilegedOutcome{Command: "remove"}
	fs := flag.NewFlagSet("remove", flag.ContinueOnError)
	fs.SetOutput(stderr)
	id := fs.String("id", "", "plugin id")
	flags := addInstallFlags(fs)
	if err := fs.Parse(args); err != nil {
		return privilegedParseError(err)
	}
	if *id == "" {
		fmt.Fprintln(stderr, "qwq privileged remove: -id is required")
		return 2
	}
	res, err := flags.installer().Remove(context.Background(), *id)
	out.ID, out.Group = res.ID, res.Group
	out.Files = res.UnitFiles
	out.Files = append(out.Files, res.Removed...)
	if err != nil {
		return privilegedFail(stdout, stderr, out, err)
	}
	return privilegedSucceed(stdout, stderr, out)
}

// privilegedVerifyEntrypoint is the ExecStartPre check: the unit runs it as
// root ("+" prefix) before every start, so a modified entrypoint never runs.
func privilegedVerifyEntrypoint(args []string, stdout, stderr io.Writer) int {
	out := privilegedOutcome{Command: "verify-entrypoint"}
	fs := flag.NewFlagSet("verify-entrypoint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "installed version directory")
	entrypoint := fs.String("entrypoint", "", "manifest entrypoint, relative to -dir")
	digest := fs.String("digest", "", "expected \"sha256:<hex>\" digest")
	if err := fs.Parse(args); err != nil {
		return privilegedParseError(err)
	}
	if *dir == "" || *entrypoint == "" || *digest == "" {
		fmt.Fprintln(stderr, "qwq privileged verify-entrypoint: -dir, -entrypoint and -digest are required")
		return 2
	}
	if err := sandbox.VerifyEntrypoint(*dir, *entrypoint, *digest); err != nil {
		return privilegedFail(stdout, stderr, out, err)
	}
	out.Files = []string{filepath.Join(*dir, filepath.FromSlash(*entrypoint))}
	return privilegedSucceed(stdout, stderr, out)
}

func privilegedParseError(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	return 2
}

// readSpec decodes one unit spec. Unknown fields are rejected so a typo cannot
// silently fall back to a default limit.
func readSpec(path string, stdin io.Reader) (sandbox.UnitSpec, error) {
	var spec sandbox.UnitSpec
	var b []byte
	var err error
	if path == "-" {
		b, err = io.ReadAll(io.LimitReader(stdin, maxSpecBytes+1))
	} else {
		if !filepath.IsAbs(path) {
			return spec, fmt.Errorf("sandbox: -spec %q must be an absolute path", path)
		}
		b, err = os.ReadFile(path)
	}
	if err != nil {
		return spec, fmt.Errorf("reading spec: %w", err)
	}
	if len(b) > maxSpecBytes {
		return spec, fmt.Errorf("spec is larger than %d bytes", maxSpecBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&spec); err != nil {
		return spec, fmt.Errorf("decoding spec: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return spec, errors.New("spec contains trailing data")
	}
	return spec, nil
}

// readToken reads the plugin token from stdin and drops one trailing newline.
func readToken(stdin io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(stdin, maxCredentialBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading credential: %w", err)
	}
	if len(b) > maxCredentialBytes {
		return nil, fmt.Errorf("credential is larger than %d bytes", maxCredentialBytes)
	}
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b, nil
}
