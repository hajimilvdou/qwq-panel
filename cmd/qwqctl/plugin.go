// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/qwq-panel/qwq/sdk/manifest"
	"github.com/qwq-panel/qwq/sdk/pkgfile"
)

// Paths keygen writes. A .key file is matched by the repository's ignore
// rules, and O_EXCL makes keygen refuse to overwrite an existing key: a
// signing key that silently changed would invalidate every package built with
// the old one.
const (
	keySuffix   = ".key"
	pubSuffix   = ".pub"
	keyFileMode = fs.FileMode(0o600)
	pubFileMode = fs.FileMode(0o644)
	pkgFileMode = fs.FileMode(0o644)
)

// runKeygen implements "qwqctl keygen -out <prefix>".
func runKeygen(args []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("keygen", stderr)
	out := flags.String("out", "", "path prefix of the key files to create")
	flags.Usage = func() {
		fmt.Fprint(flags.Output(), `usage: qwqctl keygen -out <prefix>

Creates <prefix>.key (PKCS#8 PEM, mode 0600) and <prefix>.pub (PKIX PEM,
mode 0644) and prints the key id that belongs in manifest.publisher.key_id.
Existing files are never overwritten.
`)
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *out == "" || flags.NArg() != 0 {
		flags.Usage()
		return 2
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		fail(stderr, "keygen", err)
		return 1
	}
	privPEM, err := pkgfile.MarshalPrivateKeyPEM(priv)
	if err != nil {
		fail(stderr, "keygen", err)
		return 1
	}
	pubPEM, err := pkgfile.MarshalPublicKeyPEM(pub)
	if err != nil {
		fail(stderr, "keygen", err)
		return 1
	}
	keyPath := *out + keySuffix
	pubPath := *out + pubSuffix
	if err := writeNew(keyPath, privPEM, keyFileMode); err != nil {
		fail(stderr, "keygen", err)
		return 1
	}
	if err := writeNew(pubPath, pubPEM, pubFileMode); err != nil {
		_ = os.Remove(keyPath) // never leave half a key pair behind
		fail(stderr, "keygen", err)
		return 1
	}
	fmt.Fprintf(stdout, "key_id:      %s\n", manifest.KeyID(pub))
	fmt.Fprintf(stdout, "private key: %s\n", keyPath)
	fmt.Fprintf(stdout, "public key:  %s\n", pubPath)
	return 0
}

// runPack implements "qwqctl pack -src <dir> -out <file.ppkg> [-key <priv>]".
func runPack(args []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("pack", stderr)
	src := flags.String("src", "", "source directory holding manifest.json")
	out := flags.String("out", "", "package file to write")
	keyPath := flags.String("key", "", "optional Ed25519 private key (PKCS#8 PEM) to sign with")
	flags.Usage = func() {
		fmt.Fprint(flags.Output(), `usage: qwqctl pack -src <dir> -out <file.ppkg> [-key <priv.pem>]

Packs every regular file below <dir> into a deterministic .ppkg package,
rewriting manifest.files with the computed digests. With -key the package is
signed; manifest.publisher.key_id must then be that key's id.
`)
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *src == "" || *out == "" || flags.NArg() != 0 {
		flags.Usage()
		return 2
	}
	priv, code := loadSigningKey(*keyPath, stderr, "pack")
	if code != 0 {
		return code
	}
	var pkg *pkgfile.Package
	err := atomicFile(*out, pkgFileMode, func(f *os.File) error {
		p, perr := pkgfile.Pack(*src, f, pkgfile.PackOptions{SigningKey: priv})
		if perr != nil {
			return perr
		}
		pkg = p
		return nil
	})
	if err != nil {
		fail(stderr, "pack", err)
		return 1
	}
	printPackage(stdout, *out, pkg)
	return 0
}

// runSign implements "qwqctl sign -key <priv> [-out <file>] <file.ppkg>".
func runSign(args []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("sign", stderr)
	keyPath := flags.String("key", "", "Ed25519 private key (PKCS#8 PEM)")
	outPath := flags.String("out", "", "write the result here instead of rewriting the input")
	flags.Usage = func() {
		fmt.Fprint(flags.Output(), `usage: qwqctl sign -key <priv.pem> [-out <file.ppkg>] <file.ppkg>

Replaces signatures/manifest.sig with a signature by this key. Without -out
the package is rewritten in place through a temporary file and a rename, so a
failure leaves the original untouched. Every other entry is copied unchanged,
and manifest.publisher.key_id must be the signing key's id.
`)
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *keyPath == "" || flags.NArg() != 1 {
		flags.Usage()
		return 2
	}
	inPath := flags.Arg(0)
	dest := *outPath
	if dest == "" {
		dest = inPath
	}
	priv, code := loadSigningKey(*keyPath, stderr, "sign")
	if code != 0 {
		return code
	}
	in, err := os.Open(inPath)
	if err != nil {
		fail(stderr, "sign", err)
		return 1
	}
	var pkg *pkgfile.Package
	err = atomicFile(dest, pkgFileMode, func(f *os.File) error {
		p, rerr := pkgfile.Resign(in, f, priv, pkgfile.DefaultLimits())
		// The input is closed here so that rewriting a package in place can
		// rename over it on every platform.
		cerr := in.Close()
		if rerr != nil {
			return rerr
		}
		pkg = p
		return cerr
	})
	if err != nil {
		_ = in.Close()
		fail(stderr, "sign", err)
		return 1
	}
	printPackage(stdout, dest, pkg)
	return 0
}

// runVerify implements "qwqctl verify -trust <pub> [-trust <pub>...] <ppkg>".
func runVerify(args []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("verify", stderr)
	var trustPaths stringList
	flags.Var(&trustPaths, "trust", "trusted publisher public key (PKIX PEM); repeat or comma-separate")
	listFiles := flags.Bool("files", false, "list every verified file with its digest")
	flags.Usage = func() {
		fmt.Fprint(flags.Output(), `usage: qwqctl verify -trust <pub.pem> [-trust <pub.pem>] [-files] <file.ppkg>

Verifies the signature, the manifest and every content digest, then prints the
manifest summary. It exits non-zero when any check fails.
`)
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if len(trustPaths) == 0 || flags.NArg() != 1 {
		flags.Usage()
		return 2
	}
	keys := make([]manifest.TrustedKey, 0, len(trustPaths))
	for _, name := range trustPaths {
		pub, err := loadPublicKey(name)
		if err != nil {
			fail(stderr, "verify", err)
			return 1
		}
		keys = append(keys, manifest.TrustedKey{PublicKey: pub})
	}
	ts, err := manifest.NewStaticTrustStore(keys...)
	if err != nil {
		fail(stderr, "verify", err)
		return 1
	}
	path := flags.Arg(0)
	f, err := os.Open(path)
	if err != nil {
		fail(stderr, "verify", err)
		return 1
	}
	defer f.Close() //nolint:errcheck // read only
	pkg, err := pkgfile.Read(f, ts, pkgfile.ReadOptions{})
	if err != nil {
		fail(stderr, "verify", err)
		return 1
	}
	printPackage(stdout, path, pkg)
	if *listFiles {
		for _, file := range pkg.Files {
			fmt.Fprintf(stdout, "  %-40s %10d  %s\n", file.Path, file.Size, file.Digest)
		}
	}
	fmt.Fprintln(stdout, "result:     OK")
	return 0
}

// newFlagSet returns a flag set that reports problems the way the CLI does.
func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet("qwqctl "+name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	return flags
}

// loadSigningKey reads an optional private key. An empty path means "pack
// unsigned" and yields a nil key.
func loadSigningKey(path string, stderr io.Writer, cmd string) (ed25519.PrivateKey, int) {
	if path == "" {
		return nil, 0
	}
	b, err := os.ReadFile(path)
	if err != nil {
		fail(stderr, cmd, err)
		return nil, 1
	}
	priv, err := pkgfile.ParsePrivateKeyPEM(b)
	if err != nil {
		fail(stderr, cmd, err)
		return nil, 1
	}
	return priv, 0
}

// loadPublicKey reads one trust store key.
func loadPublicKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return pkgfile.ParsePublicKeyPEM(b)
}

// printPackage prints the manifest summary shared by pack, sign and verify.
func printPackage(w io.Writer, path string, pkg *pkgfile.Package) {
	m := pkg.Manifest
	fmt.Fprintf(w, "package:    %s\n", path)
	fmt.Fprintf(w, "id:         %s\n", m.ID)
	fmt.Fprintf(w, "version:    %s\n", m.Version)
	fmt.Fprintf(w, "name:       %s\n", m.Name)
	fmt.Fprintf(w, "target:     %s\n", m.Target)
	fmt.Fprintf(w, "entrypoint: %s\n", m.Entrypoint)
	fmt.Fprintf(w, "publisher:  %s (%s)\n", m.Publisher.ID, m.Publisher.KeyID)
	if pkg.Signature != nil {
		fmt.Fprintf(w, "signed by:  %s\n", pkg.Signature.KeyID)
	} else {
		fmt.Fprintln(w, "signed by:  (unsigned)")
	}
	fmt.Fprintf(w, "files:      %d (%d bytes)\n", len(pkg.Files), pkg.Size)
	sum := sha256.Sum256(pkg.ManifestBytes)
	fmt.Fprintf(w, "manifest:   sha256:%x\n", sum)
}

// fail reports one command failure on stderr.
func fail(w io.Writer, cmd string, err error) {
	fmt.Fprintf(w, "qwqctl %s: %v\n", cmd, err)
}

// stringList is a flag.Value that appends every occurrence and splits
// comma-separated values, so "-trust a.pem,b.pem" and two -trust flags work.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

// Set implements flag.Value.
func (s *stringList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			*s = append(*s, p)
		}
	}
	return nil
}

// atomicFile creates path by writing a temporary file next to it and renaming
// it into place once fn returns without an error. A failure never leaves a
// partial package behind.
func atomicFile(path string, mode fs.FileMode, fn func(f *os.File) error) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".qwqctl-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	discard := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := fn(tmp); err != nil {
		discard()
		return err
	}
	if err := tmp.Sync(); err != nil {
		discard()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		discard()
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

// writeNew creates a file that must not exist yet.
func writeNew(path string, data []byte, mode fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, werr := f.Write(data); werr != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return werr
	}
	if cerr := f.Chmod(mode); cerr != nil { // defeat the umask
		_ = f.Close()
		_ = os.Remove(path)
		return cerr
	}
	if serr := f.Sync(); serr != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return serr
	}
	return f.Close()
}
