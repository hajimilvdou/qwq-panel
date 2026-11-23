// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/qwq-panel/qwq/sdk/manifest"
	"github.com/qwq-panel/qwq/sdk/pkgfile"
)

const (
	placeholderKeyID = "ed25519:0000000000000000000000000000000000000000000000000000000000000000"
	devPrivMode      = fs.FileMode(0o600)
	devPubMode       = fs.FileMode(0o644)
	devPkgMode       = fs.FileMode(0o644)
)

var (
	devPluginIDPattern    = regexp.MustCompile(`^[a-z][a-z0-9]*([.-][a-z0-9]+)*$`)
	devPublisherIDPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	devKeyIDPattern       = regexp.MustCompile(`^ed25519:[a-f0-9]{64}$`)
)

func runPlugin(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		out := stderr
		rc := 2
		if len(args) > 0 {
			out = stdout
			rc = 0
		}
		pluginUsage(out)
		return rc
	}
	switch args[0] {
	case "bootstrap":
		return runPluginBootstrap(args[1:], stdout, stderr, defaultBootstrapSessionFactory)
	case "keygen":
		return runPluginKeygen(args[1:], stdout, stderr)
	case "init":
		return runPluginInit(args[1:], stdout, stderr)
	case "pack":
		return runPluginPack(args[1:], stdout, stderr)
	case "verify":
		return runPluginVerify(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "qwq plugin: unknown subcommand %q\n\n", args[0])
		pluginUsage(stderr)
		return 2
	}
}

func pluginUsage(w io.Writer) {
	fmt.Fprint(w, `usage: qwq plugin <subcommand> [flags]

subcommands:
  keygen     generate an Ed25519 publisher keypair (PKCS#8 private + PKIX public PEM)
  init       scaffold a starter qwq plugin project (manifest 1.3, Go SDK, optional CSP-safe UI)
  pack       compute file digests, validate manifest.json, and build a signed .qwqpkg archive
  verify     verify a .qwqpkg signature, manifest, and every file digest offline
  bootstrap  install or update signed .qwqpkg packages on the local host (root only)
`)
}

// reorderFlags moves flags before positional arguments so invocations like
// `qwq plugin init ./myplugin --id acme.hello --name "Hello"` work cleanly
// with Go's standard flag.FlagSet.
func reorderFlags(args []string, valueFlags map[string]bool) []string {
	var flagsPart, posPart []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			posPart = append(posPart, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			trimmed := strings.TrimLeft(a, "-")
			if !strings.Contains(trimmed, "=") && valueFlags[trimmed] && i+1 < len(args) {
				flagsPart = append(flagsPart, a)
				i++
				flagsPart = append(flagsPart, args[i])
			} else if !strings.Contains(trimmed, "=") && !valueFlags[trimmed] && i+1 < len(args) {
				nextLower := strings.ToLower(strings.TrimSpace(args[i+1]))
				if nextLower == "true" || nextLower == "false" {
					flagsPart = append(flagsPart, a+"="+nextLower)
					i++
				} else {
					flagsPart = append(flagsPart, a)
				}
			} else {
				flagsPart = append(flagsPart, a)
			}
			continue
		}
		posPart = append(posPart, a)
	}
	return append(flagsPart, posPart...)
}

// runPluginKeygen implements:
//
//	qwq plugin keygen --out-priv <priv.pem> --out-pub <pub.pem>
func runPluginKeygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("qwq plugin keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	outPriv := fs.String("out-priv", "", "output path for Ed25519 private key (PKCS#8 PEM, mode 0600)")
	outPub := fs.String("out-pub", "", "output path for Ed25519 public key (PKIX PEM, mode 0644)")
	if err := fs.Parse(reorderFlags(args, map[string]bool{"out-priv": true, "out-pub": true})); err != nil {
		return 2
	}
	if strings.TrimSpace(*outPriv) == "" || strings.TrimSpace(*outPub) == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: qwq plugin keygen --out-priv <priv.pem> --out-pub <pub.pem>")
		return 2
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(stderr, "qwq plugin keygen: %v\n", err)
		return 1
	}
	privPEM, err := pkgfile.MarshalPrivateKeyPEM(priv)
	if err != nil {
		fmt.Fprintf(stderr, "qwq plugin keygen: %v\n", err)
		return 1
	}
	pubPEM, err := pkgfile.MarshalPublicKeyPEM(pub)
	if err != nil {
		fmt.Fprintf(stderr, "qwq plugin keygen: %v\n", err)
		return 1
	}
	if err := writeNewFile(*outPriv, privPEM, devPrivMode); err != nil {
		fmt.Fprintf(stderr, "qwq plugin keygen: write private key: %v\n", err)
		return 1
	}
	if err := writeNewFile(*outPub, pubPEM, devPubMode); err != nil {
		_ = os.Remove(*outPriv)
		fmt.Fprintf(stderr, "qwq plugin keygen: write public key: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "key_id:      %s\n", manifest.KeyID(pub))
	fmt.Fprintf(stdout, "private key: %s\n", *outPriv)
	fmt.Fprintf(stdout, "public key:  %s\n", *outPub)
	return 0
}

// runPluginInit implements:
//
//	qwq plugin init <dir> --id <vendor.name> --name "<Title>" [--with-ui]
func runPluginInit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("qwq plugin init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pluginID := fs.String("id", "", "plugin id (e.g. acme.hello)")
	title := fs.String("name", "", "human-readable plugin name")
	withUI := fs.Bool("with-ui", true, "include CSP-safe starter UI using @qwq/kit v2 MessageChannel handshake")
	publisher := fs.String("publisher", "", "publisher id (defaults to plugin id prefix)")
	keyID := fs.String("key-id", placeholderKeyID, "publisher key_id (ed25519:<64hex>)")
	target := fs.String("target", defaultPluginTarget(), "target platform (linux/amd64, linux/arm64, ...)")
	if err := fs.Parse(reorderFlags(args, map[string]bool{
		"id": true, "name": true, "publisher": true, "key-id": true, "target": true,
	})); err != nil {
		return 2
	}
	if fs.NArg() != 1 || strings.TrimSpace(*pluginID) == "" || strings.TrimSpace(*title) == "" {
		fmt.Fprintln(stderr, `usage: qwq plugin init <dir> --id <vendor.name> --name "<Title>" [--with-ui] [--publisher <id>] [--key-id <ed25519:...>]`)
		return 2
	}
	id := strings.TrimSpace(*pluginID)
	name := strings.TrimSpace(*title)
	if !devPluginIDPattern.MatchString(id) || len(id) > 26 {
		fmt.Fprintf(stderr, "qwq plugin init: invalid plugin id %q (must match ^[a-z][a-z0-9]*([.-][a-z0-9]+)*$ and length <= 26 for Linux qwq-p-<id> user)\n", id)
		return 2
	}
	if id == "host" || strings.HasPrefix(id, "host.") || id == "qwq" || strings.HasPrefix(id, "qwq.") {
		fmt.Fprintf(stderr, "qwq plugin init: plugin id %q uses reserved namespace host/qwq\n", id)
		return 2
	}
	if !devKeyIDPattern.MatchString(*keyID) {
		fmt.Fprintf(stderr, "qwq plugin init: invalid --key-id %q (want ed25519:<64 lower-case hex>)\n", *keyID)
		return 2
	}
	pubID := strings.TrimSpace(*publisher)
	if pubID == "" {
		pubID = derivePublisherID(id)
	}
	if !devPublisherIDPattern.MatchString(pubID) || len(pubID) > 64 {
		fmt.Fprintf(stderr, "qwq plugin init: invalid --publisher %q\n", pubID)
		return 2
	}

	dir := fs.Arg(0)
	if st, err := os.Stat(dir); err == nil {
		if !st.IsDir() {
			fmt.Fprintf(stderr, "qwq plugin init: %q exists and is not a directory\n", dir)
			return 1
		}
		entries, rerr := os.ReadDir(dir)
		if rerr != nil {
			fmt.Fprintf(stderr, "qwq plugin init: %v\n", rerr)
			return 1
		}
		if len(entries) > 0 {
			fmt.Fprintf(stderr, "qwq plugin init: directory %q is not empty\n", dir)
			return 1
		}
	}

	files := buildScaffoldFiles(scaffoldSpec{
		ID:        id,
		Name:      name,
		Publisher: pubID,
		KeyID:     *keyID,
		Target:    *target,
		WithUI:    *withUI,
	})
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, rel := range paths {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			fmt.Fprintf(stderr, "qwq plugin init: create dir: %v\n", err)
			return 1
		}
		if err := os.WriteFile(full, []byte(files[rel]), 0o644); err != nil {
			fmt.Fprintf(stderr, "qwq plugin init: write %s: %v\n", rel, err)
			return 1
		}
	}

	fmt.Fprintf(stdout, "scaffolded plugin %s (%s) in %s\n", id, name, dir)
	fmt.Fprintf(stdout, "files: %d (with_ui=%v)\n", len(paths), *withUI)
	fmt.Fprintf(stdout, "next: keep signing keys outside %s, build linux binary to bin/plugin, then run:\n", dir)
	fmt.Fprintf(stdout, "  qwq plugin pack %s --out %s.qwqpkg --key ./publisher.key.pem [--entrypoint ./plugin-bin]\n", dir, id)
	return 0
}

// runPluginPack implements:
//
//	qwq plugin pack <dir> --out <out.qwqpkg> --key <priv.pem> [--entrypoint <bin>]
func runPluginPack(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("qwq plugin pack", flag.ContinueOnError)
	fs.SetOutput(stderr)
	outPath := fs.String("out", "", "output .qwqpkg archive path")
	keyPath := fs.String("key", "", "Ed25519 private key (PKCS#8 PEM) for signing")
	entrypointBin := fs.String("entrypoint", "", "optional compiled binary path to copy into manifest.entrypoint")
	if err := fs.Parse(reorderFlags(args, map[string]bool{
		"out": true, "key": true, "entrypoint": true,
	})); err != nil {
		return 2
	}
	if fs.NArg() != 1 || strings.TrimSpace(*outPath) == "" || strings.TrimSpace(*keyPath) == "" {
		fmt.Fprintln(stderr, "usage: qwq plugin pack <dir> --out <out.qwqpkg> --key <priv.pem> [--entrypoint <bin>]")
		return 2
	}
	srcDir := fs.Arg(0)

	rawKey, err := os.ReadFile(*keyPath)
	if err != nil {
		fmt.Fprintf(stderr, "qwq plugin pack: read private key: %v\n", err)
		return 1
	}
	priv, err := pkgfile.ParsePrivateKeyPEM(rawKey)
	if err != nil {
		fmt.Fprintf(stderr, "qwq plugin pack: parse private key: %v\n", err)
		return 1
	}
	signingKeyID := manifest.KeyID(priv.Public().(ed25519.PublicKey))

	var excludeInfos []os.FileInfo
	for _, p := range []string{*keyPath, *outPath, *entrypointBin} {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if fi, serr := os.Stat(p); serr == nil {
			excludeInfos = append(excludeInfos, fi)
		}
	}

	stageDir, err := os.MkdirTemp("", "qwq-pack-*")
	if err != nil {
		fmt.Fprintf(stderr, "qwq plugin pack: create temp staging dir: %v\n", err)
		return 1
	}
	defer os.RemoveAll(stageDir)

	if err := copyPackSource(srcDir, stageDir, excludeInfos); err != nil {
		fmt.Fprintf(stderr, "qwq plugin pack: stage source tree: %v\n", err)
		return 1
	}

	manifestPath := filepath.Join(stageDir, pkgfile.ManifestPath)
	entryRel, err := prepareStagedManifest(manifestPath, signingKeyID)
	if err != nil {
		fmt.Fprintf(stderr, "qwq plugin pack: prepare manifest.json: %v\n", err)
		return 1
	}

	dstBin, cleanEntry, err := resolvePackEntrypoint(stageDir, entryRel)
	if err != nil {
		fmt.Fprintf(stderr, "qwq plugin pack: invalid manifest.entrypoint %q: %v\n", entryRel, err)
		return 1
	}

	if strings.TrimSpace(*entrypointBin) != "" {
		if err := copyFileExact(*entrypointBin, dstBin, 0o755); err != nil {
			fmt.Fprintf(stderr, "qwq plugin pack: copy entrypoint %q -> %s: %v\n", *entrypointBin, cleanEntry, err)
			return 1
		}
	}

	if err := os.MkdirAll(filepath.Dir(filepath.Clean(*outPath)), 0o755); err != nil {
		fmt.Fprintf(stderr, "qwq plugin pack: create output directory: %v\n", err)
		return 1
	}

	var pkg *pkgfile.Package
	err = writeAtomicFile(*outPath, devPkgMode, func(f *os.File) error {
		p, perr := pkgfile.Pack(stageDir, f, pkgfile.PackOptions{SigningKey: priv})
		if perr != nil {
			return perr
		}
		pkg = p
		return nil
	})
	if err != nil {
		fmt.Fprintf(stderr, "qwq plugin pack: %v\n", err)
		return 1
	}

	printPluginPackageSummary(stdout, *outPath, pkg)
	return 0
}

// runPluginVerify implements:
//
//	qwq plugin verify <file.qwqpkg> --trust <pub.pem-or-dir>
func runPluginVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("qwq plugin verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var trustSpecs devStringList
	fs.Var(&trustSpecs, "trust", "trusted publisher public key (.pem file or directory of *.pem); repeatable or comma-separated")
	if err := fs.Parse(reorderFlags(args, map[string]bool{"trust": true})); err != nil {
		return 2
	}
	if fs.NArg() != 1 || len(trustSpecs) == 0 {
		fmt.Fprintln(stderr, "usage: qwq plugin verify <file.qwqpkg> --trust <pub.pem-or-dir>")
		return 2
	}

	keys, err := loadVerifyTrustKeys(trustSpecs)
	if err != nil {
		fmt.Fprintf(stderr, "qwq plugin verify: %v\n", err)
		return 1
	}
	ts, err := manifest.NewStaticTrustStore(keys...)
	if err != nil {
		fmt.Fprintf(stderr, "qwq plugin verify: %v\n", err)
		return 1
	}

	pkgPath := fs.Arg(0)
	f, err := os.Open(pkgPath)
	if err != nil {
		fmt.Fprintf(stderr, "qwq plugin verify: %v\n", err)
		return 1
	}
	defer f.Close()

	pkg, err := pkgfile.Read(f, ts, pkgfile.ReadOptions{})
	if err != nil {
		fmt.Fprintf(stderr, "qwq plugin verify: %v\n", err)
		return 1
	}
	printPluginPackageSummary(stdout, pkgPath, pkg)
	if len(pkg.Manifest.Capabilities) == 0 {
		fmt.Fprintln(stdout, "capabilities: (none)")
	} else {
		fmt.Fprintln(stdout, "capabilities:")
		for _, c := range pkg.Manifest.Capabilities {
			fmt.Fprintf(stdout, "  - %s (%s): %s\n", c.Name, c.Scope, c.Reason)
		}
	}
	fmt.Fprintln(stdout, "verified:     OK")
	return 0
}

func loadVerifyTrustKeys(specs []string) ([]manifest.TrustedKey, error) {
	seen := make(map[string]bool)
	var keys []manifest.TrustedKey
	addFile := func(path string) error {
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read trust key %s: %w", path, err)
		}
		pub, err := pkgfile.ParsePublicKeyPEM(raw)
		if err != nil {
			return fmt.Errorf("parse trust key %s: %w", path, err)
		}
		id := manifest.KeyID(pub)
		if seen[id] {
			return nil
		}
		seen[id] = true
		keys = append(keys, manifest.TrustedKey{PublicKey: pub})
		return nil
	}
	for _, spec := range specs {
		st, err := os.Stat(spec)
		if err != nil {
			return nil, fmt.Errorf("trust path %s: %w", spec, err)
		}
		if !st.IsDir() {
			if err := addFile(spec); err != nil {
				return nil, err
			}
			continue
		}
		entries, err := os.ReadDir(spec)
		if err != nil {
			return nil, fmt.Errorf("read trust dir %s: %w", spec, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pem") {
				continue
			}
			if err := addFile(filepath.Join(spec, entry.Name())); err != nil {
				return nil, err
			}
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("no valid Ed25519 .pem public keys found in --trust")
	}
	return keys, nil
}

func printPluginPackageSummary(w io.Writer, path string, pkg *pkgfile.Package) {
	m := pkg.Manifest
	fmt.Fprintf(w, "package:      %s\n", path)
	fmt.Fprintf(w, "id:           %s\n", m.ID)
	fmt.Fprintf(w, "version:      %s\n", m.Version)
	fmt.Fprintf(w, "name:         %s\n", m.Name)
	fmt.Fprintf(w, "target:       %s\n", m.Target)
	fmt.Fprintf(w, "entrypoint:   %s\n", m.Entrypoint)
	fmt.Fprintf(w, "publisher:    %s\n", m.Publisher.ID)
	fmt.Fprintf(w, "key_id:       %s\n", m.Publisher.KeyID)
	fmt.Fprintf(w, "files:        %d (%d bytes)\n", len(pkg.Files), pkg.Size)
	sum := sha256.Sum256(pkg.ManifestBytes)
	fmt.Fprintf(w, "manifest:     sha256:%x\n", sum)
}

func copyPackSource(srcDir, dstDir string, excludeInfos []os.FileInfo) error {
	info, err := os.Stat(srcDir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", srcDir)
	}
	return filepath.WalkDir(srcDir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		rel, err := filepath.Rel(srcDir, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		slash := filepath.ToSlash(rel)
		base := d.Name()
		if d.IsDir() {
			if base == ".git" || base == ".hg" || base == ".svn" || slash == "signatures" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dstDir, rel), 0o755)
		}
		if strings.HasSuffix(strings.ToLower(base), ".qwqpkg") || strings.HasPrefix(slash, "signatures/") {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("symbolic links cannot be packed: %s", slash)
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("only regular files and directories can be packed: %s", slash)
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		for _, ex := range excludeInfos {
			if os.SameFile(fi, ex) {
				return nil
			}
		}
		lowerBase := strings.ToLower(base)
		if strings.HasSuffix(lowerBase, ".pem") || strings.HasSuffix(lowerBase, ".key") {
			return fmt.Errorf("refusing to pack key/PEM file %q; keep signing keys outside the plugin source directory", slash)
		}
		hasPriv, err := fileContainsPrivateKeyPEM(p)
		if err != nil {
			return err
		}
		if hasPriv {
			return fmt.Errorf("refusing to pack file %q containing private key material", slash)
		}
		mode := fs.FileMode(0o644)
		if fi.Mode()&0o111 != 0 {
			mode = 0o755
		}
		return copyFileExact(p, filepath.Join(dstDir, rel), mode)
	})
}

// resolvePackEntrypoint validates manifest.entrypoint before joining with
// stageDir, ensuring it is a clean relative POSIX path strictly under bin/ and
// cannot escape stageDir.
func resolvePackEntrypoint(stageDir, entryRel string) (string, string, error) {
	if entryRel == "" {
		entryRel = "bin/plugin"
	}
	if strings.Contains(entryRel, "\\") || strings.HasPrefix(entryRel, "/") || strings.ContainsRune(entryRel, 0) || filepath.IsAbs(entryRel) {
		return "", "", errors.New("must be a relative forward-slash path under bin/")
	}
	for _, seg := range strings.Split(entryRel, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", "", errors.New("must not contain empty, '.', or '..' path segments")
		}
	}
	clean := path.Clean(entryRel)
	if !strings.HasPrefix(clean, "bin/") || len(clean) <= len("bin/") {
		return "", "", errors.New("must reside strictly under bin/")
	}
	dstBin := filepath.Join(stageDir, filepath.FromSlash(clean))
	rel, err := filepath.Rel(stageDir, dstBin)
	if err != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || !strings.HasPrefix(filepath.ToSlash(rel), "bin/") {
		return "", "", errors.New("escapes staging directory")
	}
	return dstBin, clean, nil
}

func fileContainsPrivateKeyPEM(filePath string) (bool, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer f.Close()

	const (
		chunkSize = 64 * 1024
		overlap   = 256
	)
	buf := make([]byte, overlap+chunkSize)
	carry := 0
	for {
		n, rerr := f.Read(buf[carry:])
		total := carry + n
		if total > 0 && containsPrivateKeyHeader(buf[:total]) {
			return true, nil
		}
		if rerr == io.EOF {
			return false, nil
		}
		if rerr != nil {
			return false, rerr
		}
		if total > overlap {
			copy(buf[:overlap], buf[total-overlap:total])
			carry = overlap
		} else {
			carry = total
		}
	}
}

func containsPrivateKeyHeader(buf []byte) bool {
	const (
		beginMarker = "-----BEGIN "
		endMarker   = "PRIVATE KEY-----"
	)
	data := buf
	for {
		idx := bytes.Index(data, []byte(beginMarker))
		if idx < 0 {
			return false
		}
		rest := data[idx+len(beginMarker):]
		line := rest
		if nl := bytes.IndexAny(rest, "\r\n"); nl >= 0 {
			line = rest[:nl]
		}
		if len(line) > 128 {
			line = line[:128]
		}
		if bytes.Contains(line, []byte(endMarker)) {
			return true
		}
		data = rest
	}
}

// prepareStagedManifest fills publisher.key_id when manifest.json still uses
// the empty/all-zero placeholder, and returns manifest.entrypoint.
func prepareStagedManifest(manifestPath, signingKeyID string) (string, error) {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return "", err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return "", err
	}
	changed := false
	if pub, ok := obj["publisher"].(map[string]any); ok {
		cur, _ := pub["key_id"].(string)
		if cur == "" || cur == placeholderKeyID {
			pub["key_id"] = signingKeyID
			changed = true
		}
	}
	entry, _ := obj["entrypoint"].(string)
	if changed {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(obj); err != nil {
			return "", err
		}
		if err := os.WriteFile(manifestPath, buf.Bytes(), 0o644); err != nil {
			return "", err
		}
	}
	return entry, nil
}

func copyFileExact(src, dst string, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func writeNewFile(path string, data []byte, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(filepath.Clean(path)), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}

func writeAtomicFile(path string, mode fs.FileMode, fn func(f *os.File) error) error {
	dir := filepath.Dir(filepath.Clean(path))
	tmp, err := os.CreateTemp(dir, ".qwq-pkg-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := fn(tmp); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

type devStringList []string

func (s *devStringList) String() string { return strings.Join(*s, ",") }

func (s *devStringList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			*s = append(*s, p)
		}
	}
	return nil
}

func defaultPluginTarget() string {
	switch runtime.GOARCH {
	case "arm64":
		return "linux/arm64"
	default:
		return "linux/amd64"
	}
}

func derivePublisherID(pluginID string) string {
	prefix, _, _ := strings.Cut(pluginID, ".")
	cleaned := strings.Trim(strings.ToLower(prefix), "-")
	if devPublisherIDPattern.MatchString(cleaned) && len(cleaned) <= 64 {
		return cleaned
	}
	return "community"
}

type scaffoldSpec struct {
	ID        string
	Name      string
	Publisher string
	KeyID     string
	Target    string
	WithUI    bool
}

func buildScaffoldFiles(spec scaffoldSpec) map[string]string {
	routeSlug := "/" + strings.ReplaceAll(spec.ID, ".", "-")
	if len(routeSlug) > 64 {
		routeSlug = routeSlug[:64]
	}
	navTitle := spec.Name
	if runes := []rune(navTitle); len(runes) > 32 {
		navTitle = string(runes[:32])
	}

	manifestObj := map[string]any{
		"schema_version":    "1.3",
		"id":                spec.ID,
		"version":           "0.1.0",
		"name":              spec.Name,
		"summary":           spec.Name + " starter plugin for qwq",
		"description":       "Starter plugin generated by qwq plugin init.",
		"license":           "Apache-2.0",
		"publisher":         map[string]any{"id": spec.Publisher, "key_id": spec.KeyID},
		"abi":               map[string]any{"major": 1, "minimum_minor": 0},
		"engine_constraint": ">=0.1.0 <1.0.0",
		"target":            spec.Target,
		"entrypoint":        "bin/plugin",
		"files": map[string]string{
			"bin/plugin":                  "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			"attestations/sbom.spdx.json": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			"schemas/config.schema.json":  "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			"schemas/hello.request.json":  "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			"schemas/hello.response.json": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		},
		"provenance": map[string]any{
			"sbom": "attestations/sbom.spdx.json",
		},
		"placement": "node",
		"lifecycle": map[string]any{
			"startup":         "on_demand",
			"background":      false,
			"update_strategy": "restart",
			"overlap_safe":    false,
		},
		"operations": []map[string]any{
			{
				"name":            "hello",
				"api_version":     "v1",
				"permission":      spec.ID + ":read",
				"mode":            "invoke",
				"effect":          "read",
				"risk":            "low",
				"idempotent":      true,
				"timeout_ms":      5000,
				"summary":         "Return a greeting from the plugin",
				"request_schema":  "schemas/hello.request.json",
				"response_schema": "schemas/hello.response.json",
			},
		},
		"capabilities": []any{},
		"dependencies": []any{},
		"state": map[string]any{
			"schema_version":           "1",
			"minimum_rollback_version": "0.1.0",
			"backup_paths":             []string{},
		},
		"config": map[string]any{
			"schema":    "schemas/config.schema.json",
			"hot_apply": true,
		},
		"resources": map[string]any{
			"memory_max_mb":     24,
			"cpu_quota_percent": 10,
			"pids_max":          16,
			"fds_max":           128,
			"disk_max_mb":       32,
			"kv_max_kb":         128,
		},
	}

	if spec.WithUI {
		manifestObj["ui"] = map[string]any{
			"entry":           "ui/index.html",
			"sandbox":         true,
			"kit_major":       1,
			"connect_sources": []string{},
			"routes": []map[string]any{
				{
					"path":       routeSlug,
					"title":      navTitle,
					"nav":        true,
					"permission": spec.ID + ":read",
				},
			},
			"widgets": []any{},
		}
		filesMap := manifestObj["files"].(map[string]string)
		filesMap["ui/index.html"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		filesMap["ui/plugin.css"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		filesMap["ui/plugin.js"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	}

	var manBuf bytes.Buffer
	enc := json.NewEncoder(&manBuf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(manifestObj)

	out := map[string]string{
		"manifest.json":               manBuf.String(),
		"main.go":                     renderScaffoldMainGo(spec),
		"schemas/config.schema.json":  "{\n  \"$schema\": \"https://json-schema.org/draft/2020-12/schema\",\n  \"type\": \"object\",\n  \"additionalProperties\": false,\n  \"properties\": {\n    \"greeting_prefix\": {\n      \"type\": \"string\",\n      \"default\": \"Hello\",\n      \"maxLength\": 64\n    }\n  }\n}\n",
		"schemas/hello.request.json":  "{\n  \"$schema\": \"https://json-schema.org/draft/2020-12/schema\",\n  \"type\": \"object\",\n  \"additionalProperties\": false,\n  \"properties\": {\n    \"name\": {\n      \"type\": \"string\",\n      \"maxLength\": 64\n    }\n  }\n}\n",
		"schemas/hello.response.json": "{\n  \"$schema\": \"https://json-schema.org/draft/2020-12/schema\",\n  \"type\": \"object\",\n  \"additionalProperties\": false,\n  \"required\": [\"message\", \"plugin_id\", \"timestamp\"],\n  \"properties\": {\n    \"message\": { \"type\": \"string\" },\n    \"plugin_id\": { \"type\": \"string\" },\n    \"timestamp\": { \"type\": \"string\" }\n  }\n}\n",
		"attestations/sbom.spdx.json": fmt.Sprintf("{\n  \"spdxVersion\": \"SPDX-2.3\",\n  \"dataLicense\": \"CC0-1.0\",\n  \"SPDXID\": \"SPDXRef-DOCUMENT\",\n  \"name\": %q,\n  \"documentNamespace\": \"https://spdx.org/spdxdocs/%s-0.1.0\",\n  \"creationInfo\": {\n    \"created\": \"2026-01-01T00:00:00Z\",\n    \"creators\": [\"Tool: qwq-plugin-init\"]\n  },\n  \"packages\": []\n}\n", spec.ID, spec.ID),
		"README.md":                   renderScaffoldREADME(spec),
	}

	if spec.WithUI {
		out["ui/index.html"] = renderScaffoldHTML(spec)
		out["ui/plugin.css"] = renderScaffoldCSS()
		out["ui/plugin.js"] = renderScaffoldJS(spec)
	}
	return out
}

func renderScaffoldMainGo(spec scaffoldSpec) string {
	return fmt.Sprintf(`// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

//go:embed manifest.json
var manifestJSON []byte

type pluginConfig struct {
	GreetingPrefix string `+"`json:\"greeting_prefix\"`"+`
}

type helloPlugin struct{}

type helloInstance struct {
	*pluginsdk.InstanceBase
	mu     sync.RWMutex
	prefix string
}

func (p *helloPlugin) NewInstance(_ context.Context, info pluginsdk.InstanceInfo) (pluginsdk.Instance, error) {
	cfg := pluginConfig{GreetingPrefix: "Hello"}
	if len(info.Config) > 0 {
		_ = json.Unmarshal(info.Config, &cfg)
	}
	if strings.TrimSpace(cfg.GreetingPrefix) == "" {
		cfg.GreetingPrefix = "Hello"
	}
	inst := &helloInstance{
		InstanceBase: pluginsdk.NewInstanceBase(info),
		prefix:       cfg.GreetingPrefix,
	}
	inst.HandleInvoke("hello", inst.handleHello)
	return inst, nil
}

func (i *helloInstance) ApplyConfig(_ context.Context, raw []byte) error {
	cfg := pluginConfig{GreetingPrefix: "Hello"}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return err
		}
	}
	if strings.TrimSpace(cfg.GreetingPrefix) == "" {
		cfg.GreetingPrefix = "Hello"
	}
	i.mu.Lock()
	i.prefix = cfg.GreetingPrefix
	i.mu.Unlock()
	return nil
}

func (i *helloInstance) handleHello(_ context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in struct {
		Name string `+"`json:\"name\"`"+`
	}
	if len(req.Payload) > 0 {
		if err := json.Unmarshal(req.Payload, &in); err != nil {
			return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "invalid payload: %%v", err)
		}
	}
	who := strings.TrimSpace(in.Name)
	if who == "" {
		who = "qwq"
	}
	i.mu.RLock()
	prefix := i.prefix
	i.mu.RUnlock()
	body, err := json.Marshal(map[string]string{
		"message":   fmt.Sprintf("%%s, %%s!", prefix, who),
		"plugin_id": %q,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return pluginsdk.Response{}, err
	}
	return pluginsdk.Response{Payload: body}, nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := pluginsdk.ServeSystemd(ctx,
		pluginsdk.SystemdOptions{PluginID: os.Getenv(pluginsdk.EnvPluginID)},
		pluginsdk.Options{Plugin: &helloPlugin{}, Manifest: manifestJSON},
	); err != nil {
		fmt.Fprintln(os.Stderr, "%s:", err)
		os.Exit(1)
	}
}
`, spec.ID, spec.ID)
}

func renderScaffoldHTML(spec scaffoldSpec) string {
	safeName := html.EscapeString(spec.Name)
	safeID := html.EscapeString(spec.ID)
	return fmt.Sprintf(`<!-- SPDX-License-Identifier: Apache-2.0 -->
<!doctype html>
<html lang="zh-CN" data-theme="light">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>%s</title>
  <link rel="stylesheet" href="/plugin-ui/_kit/v1/kit-base.css" />
  <link rel="stylesheet" href="./plugin.css" />
</head>
<body>
  <main id="plugin-root">
    <header class="topbar">
      <div>
        <h1 class="title">%s</h1>
        <p class="sub">%s · <span id="bridge-status">连接宿主桥中…</span></p>
      </div>
    </header>
    <section class="card">
      <div class="row">
        <label class="field">
          <span>称呼</span>
          <input id="hello-name" type="text" value="qwq" maxlength="64" />
        </label>
        <button id="btn-hello" class="btn" type="button">调用 hello</button>
        <button id="btn-copy" class="btn ghost" type="button">复制结果</button>
      </div>
      <pre id="hello-output" class="output">等待调用…</pre>
    </section>
  </main>
  <script src="./plugin.js"></script>
</body>
</html>
`, safeName, safeName, safeID)
}

func renderScaffoldCSS() string {
	return `/* SPDX-License-Identifier: Apache-2.0 */
:root {
  --bg: #f8fafc;
  --surface: #ffffff;
  --text: #0f172a;
  --muted: #64748b;
  --line: #e2e8f0;
  --accent: #2563eb;
  --accent-fg: #ffffff;
}
:root[data-theme="dark"] {
  --bg: #0b1120;
  --surface: #111827;
  --text: #f1f5f9;
  --muted: #94a3b8;
  --line: #1e293b;
  --accent: #3b82f6;
  --accent-fg: #ffffff;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 16px;
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: var(--bg);
  color: var(--text);
}
.topbar { margin-bottom: 16px; }
.title { margin: 0; font-size: 20px; }
.sub { margin: 4px 0 0; font-size: 13px; color: var(--muted); }
.card {
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 16px;
}
.row { display: flex; flex-wrap: wrap; align-items: flex-end; gap: 10px; }
.field { display: flex; flex-direction: column; gap: 6px; font-size: 13px; color: var(--muted); }
.field input {
  height: 36px;
  padding: 0 10px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--bg);
  color: var(--text);
}
.btn {
  height: 36px;
  padding: 0 14px;
  border: 1px solid var(--accent);
  border-radius: 8px;
  background: var(--accent);
  color: var(--accent-fg);
  cursor: pointer;
  font-size: 13px;
}
.btn.ghost {
  background: transparent;
  color: var(--text);
  border-color: var(--line);
}
.output {
  margin: 14px 0 0;
  padding: 12px;
  border-radius: 8px;
  background: var(--bg);
  border: 1px solid var(--line);
  font-size: 13px;
  overflow-x: auto;
}
`
}

func renderScaffoldJS(spec scaffoldSpec) string {
	return fmt.Sprintf(`// SPDX-License-Identifier: Apache-2.0
// Zero-inline CSP starter UI using @qwq/kit v2 MessageChannel handshake.
(() => {
  'use strict';
  const root = document.documentElement;
  const hash = new URLSearchParams(location.hash.slice(1));
  if (hash.get('theme') === 'dark') root.dataset.theme = 'dark';

  const statusEl = document.getElementById('bridge-status');
  const outputEl = document.getElementById('hello-output');
  const nameInput = document.getElementById('hello-name');

  let port = null;
  let seq = 0;
  let lastResultText = '';
  const pending = new Map();
  const pendingCopy = new Map();

  const send = (msg) => { if (port) port.postMessage(msg); };
  const setStatus = (t) => { statusEl.textContent = t; };

  const invoke = (operation, payload = {}) => new Promise((resolve, reject) => {
    if (!port) return reject(new Error('宿主桥尚未就绪'));
    const id = 'req_' + (++seq);
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error('宿主响应超时'));
    }, 15000);
    pending.set(id, { resolve, reject, timer });
    send({ t: 'api.invoke', id, operation, payload });
  });

  const hostCopy = (text, label) => new Promise((resolve, reject) => {
    if (!port) return reject(new Error('宿主桥尚未就绪'));
    const id = 'cp_' + (++seq);
    const timer = setTimeout(() => {
      pendingCopy.delete(id);
      reject(new Error('复制响应超时'));
    }, 8000);
    pendingCopy.set(id, { resolve, reject, timer });
    send({ t: 'ui.copy', id, text: String(text), label });
  });

  async function runHello() {
    try {
      setStatus('调用中…');
      const data = await invoke('hello', { name: nameInput.value.trim() || 'qwq' });
      lastResultText = JSON.stringify(data, null, 2);
      outputEl.textContent = lastResultText;
      setStatus('已连接');
    } catch (err) {
      if (err && err.awaitingApproval) {
        setStatus('等待审批确认');
        send({ t: 'ui.toast', text: '操作已提交，等待审批确认' });
        return;
      }
      outputEl.textContent = '错误: ' + (err?.message || '未知错误');
      setStatus('调用失败');
    }
  }

  document.getElementById('btn-hello').addEventListener('click', () => void runHello());
  document.getElementById('btn-copy').addEventListener('click', async () => {
    if (!lastResultText) return;
    try {
      await hostCopy(lastResultText, '已复制 %s 返回结果');
      setStatus('已复制');
    } catch (err) {
      setStatus('复制失败: ' + (err?.message || '未知错误'));
    }
  });

  function accept(data) {
    if (!data || typeof data !== 'object') return;
    if (data.t === 'api.result' && pending.has(data.id)) {
      const req = pending.get(data.id);
      clearTimeout(req.timer);
      pending.delete(data.id);
      if (data.ok === true) {
        const env = data.data;
        if (env && typeof env === 'object' && (env.status === 'AWAITING_APPROVAL' || env.approval_id)) {
          const err = new Error('等待审批确认');
          err.awaitingApproval = true;
          req.reject(err);
          return;
        }
        if (env && typeof env === 'object' && (env.error || env.status === 'FAILED' || env.status === 'REJECTED')) {
          const msg = env.error?.detail || env.error?.message || env.status || '操作失败';
          req.reject(new Error(msg));
          return;
        }
        const res = env && typeof env === 'object' && 'result' in env && env.result !== undefined ? env.result : env;
        req.resolve(res ?? {});
      } else {
        const p = data.problem || data.error;
        req.reject(new Error((p && (p.detail || p.message || p.code)) || '请求失败'));
      }
      return;
    }
    if (data.t === 'ui.copy.result' && pendingCopy.has(data.id)) {
      const req = pendingCopy.get(data.id);
      clearTimeout(req.timer);
      pendingCopy.delete(data.id);
      if (data.ok) req.resolve(true);
      else req.reject(new Error(data.problem?.detail || '复制失败'));
      return;
    }
    if (data.t === 'ui.settings' && (data.theme === 'light' || data.theme === 'dark')) {
      root.dataset.theme = data.theme;
    }
  }

  const ro = new ResizeObserver(() => {
    const h = Math.ceil(document.getElementById('plugin-root').getBoundingClientRect().height) + 24;
    send({ t: 'ui.resize', height: h });
  });
  ro.observe(document.getElementById('plugin-root'));

  window.addEventListener('message', (event) => {
    if (event.source !== window.parent || event.data?.t !== 'plugin.port' || !event.ports[0] || port) return;
    port = event.ports[0];
    port.onmessage = (m) => accept(m.data);
    send({ t: 'ui.ready' });
    setStatus('已连接');
    void runHello();
  });

  window.addEventListener('pagehide', () => {
    ro.disconnect();
    for (const req of pending.values()) {
      clearTimeout(req.timer);
      req.reject(new Error('页面已关闭'));
    }
    pending.clear();
    for (const req of pendingCopy.values()) {
      clearTimeout(req.timer);
      req.reject(new Error('页面已关闭'));
    }
    pendingCopy.clear();
    if (port) {
      port.onmessage = null;
      if (typeof port.close === 'function') port.close();
      port = null;
    }
  });

  window.parent.postMessage({ t: 'plugin.hello', kit_major: 1 }, '*');
})();
`, spec.ID)
}

func renderScaffoldREADME(spec scaffoldSpec) string {
	return fmt.Sprintf(`# %s (`+"`%s`"+`)

Starter plugin scaffolded by `+"`qwq plugin init`"+`.

## Build, Sign, Verify & Install

1. Generate an Ed25519 publisher keypair **outside** the plugin source directory (once):
   `+"```bash"+`
   qwq plugin keygen --out-priv ../publisher.key.pem --out-pub ../publisher.pub.pem
   `+"```"+`
2. Initialize the Go module and build the Linux plugin binary directly into `+"`./bin/plugin`"+`:
   `+"```bash"+`
   go mod init %s
   go get github.com/qwq-panel/qwq/sdk
   GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ./bin/plugin .
   `+"```"+`
3. Pack & sign `+"`.qwqpkg`"+` (writing the archive outside the source directory):
   `+"```bash"+`
   qwq plugin pack . --out ../%s-0.1.0.qwqpkg --key ../publisher.key.pem
   `+"```"+`
4. Verify offline:
   `+"```bash"+`
   qwq plugin verify ../%s-0.1.0.qwqpkg --trust ../publisher.pub.pem
   `+"```"+`
5. In the qwq Web UI (`+"`/apps/install`"+`):
   - Import `+"`../publisher.pub.pem`"+` in **开发者信任公钥管理**
   - Drag & drop `+"`%s-0.1.0.qwqpkg`"+` or pull it from an HTTPS / GitHub Release URL.
`, spec.Name, spec.ID, spec.ID, spec.ID, spec.ID, spec.ID)
}
