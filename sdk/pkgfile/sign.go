// SPDX-License-Identifier: Apache-2.0

package pkgfile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/qwq-panel/qwq/sdk/manifest"
)

// Sign returns the detached signature envelope for manifestBytes: the JSON
// document {"key_id": "ed25519:<hex>", "signature": "<base64>"} that belongs
// at signatures/manifest.sig (ARCH §5.1). The signature is a plain Ed25519
// signature over the raw bytes, and key_id is manifest.KeyID of priv's public
// key, so a host can find the key before it parses anything.
//
// Sign refuses a manifest that manifest.Parse rejects: signing it would only
// move the rejection to the installer.
func Sign(manifestBytes []byte, priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, single("", CodeKeyInvalid,
			fmt.Sprintf("private key is %d bytes, want %d", len(priv), ed25519.PrivateKeySize))
	}
	if _, err := manifest.Parse(manifestBytes); err != nil {
		return nil, fmt.Errorf("pkgfile: refusing to sign a manifest that does not parse: %w", err)
	}
	return signatureFor(manifestBytes, priv).Encode(), nil
}

// Resign rewrites the package read from r to w with a signature by priv.
//
// Every other entry is copied byte for byte in its original order, so the
// result is as deterministic as its input; the input may be unsigned or
// signed by any key. Resign verifies the container and all content digests
// while it copies, and it parses the manifest strictly, so it never signs a
// package whose content contradicts its manifest. It also requires
// manifest.publisher.key_id to be priv's key, the same rule Pack applies: the
// manifest is not part of manifest.files, so re-signing never needs to change
// it, and a key rotation has to rewrite the manifest (which means re-packing).
// On error w holds a partial archive and the caller must discard it.
//
// limits bounds the input; the zero value means DefaultLimits.
func Resign(r io.Reader, w io.Writer, priv ed25519.PrivateKey, limits Limits) (*Package, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, single("", CodeKeyInvalid,
			fmt.Sprintf("private key is %d bytes, want %d", len(priv), ed25519.PrivateKeySize))
	}
	if w == nil {
		return nil, errors.New("pkgfile: nil writer")
	}
	aw, err := newArchiveWriter(w)
	if err != nil {
		return nil, err
	}
	want := manifest.KeyID(priv.Public().(ed25519.PublicKey))
	var newSig *manifest.Signature
	emit := func(rawManifest []byte, _ *manifest.Signature) error {
		m, perr := manifest.Parse(rawManifest)
		if perr != nil {
			return perr
		}
		if m.Publisher.KeyID != want {
			return single(ManifestPath, CodePublisherMismatch,
				"manifest publisher.key_id is not the signing key "+want)
		}
		sig := signatureFor(rawManifest, priv)
		if werr := aw.writeBytes(ManifestPath, rawManifest); werr != nil {
			return werr
		}
		if werr := aw.writeBytes(SignaturePath, sig.Encode()); werr != nil {
			return werr
		}
		newSig = sig
		return nil
	}
	pkg, rerr := readPackage(r, nil, ReadOptions{Limits: limits, Sink: archiveSink{aw: aw}}, false, emit)
	if rerr != nil {
		return nil, rerr
	}
	if cerr := aw.close(); cerr != nil {
		return nil, cerr
	}
	pkg.Signature = newSig
	return pkg, nil
}

// signatureFor builds the envelope for one manifest.
func signatureFor(raw []byte, priv ed25519.PrivateKey) *manifest.Signature {
	pub := priv.Public().(ed25519.PublicKey)
	return &manifest.Signature{KeyID: manifest.KeyID(pub), Sig: ed25519.Sign(priv, raw)}
}

// archiveSink re-emits the entries Resign reads.
type archiveSink struct{ aw *archiveWriter }

func (s archiveSink) CreateDir(path string) error { return s.aw.writeDir(path) }

func (s archiveSink) CreateFile(path string, size int64, mode fs.FileMode) (io.WriteCloser, error) {
	w, err := s.aw.writeFile(path, size, mode)
	if err != nil {
		return nil, err
	}
	return nopWriteCloser{w}, nil
}

// nopWriteCloser adapts the tar writer to io.WriteCloser. The archive is
// closed once, after every entry has been written.
type nopWriteCloser struct{ io.Writer }

// Close implements io.Closer.
func (nopWriteCloser) Close() error { return nil }

// Key file formats written by qwqctl keygen: PKCS#8 for the private key and
// PKIX SubjectPublicKeyInfo for the public key, both PEM encoded.
const (
	// PrivateKeyPEMType is the PEM block type of a PKCS#8 Ed25519 private key.
	PrivateKeyPEMType = "PRIVATE KEY"
	// PublicKeyPEMType is the PEM block type of a PKIX Ed25519 public key.
	PublicKeyPEMType = "PUBLIC KEY"
)

// MarshalPrivateKeyPEM encodes priv as a PKCS#8 PEM block. The caller is
// responsible for the file being readable only by its owner (qwqctl keygen
// creates it with mode 0600).
func MarshalPrivateKeyPEM(priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, single("", CodeKeyInvalid,
			fmt.Sprintf("private key is %d bytes, want %d", len(priv), ed25519.PrivateKeySize))
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("pkgfile: encoding private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: PrivateKeyPEMType, Bytes: der}), nil
}

// MarshalPublicKeyPEM encodes pub as a PKIX PEM block.
func MarshalPublicKeyPEM(pub ed25519.PublicKey) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, single("", CodeKeyInvalid,
			fmt.Sprintf("public key is %d bytes, want %d", len(pub), ed25519.PublicKeySize))
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("pkgfile: encoding public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: PublicKeyPEMType, Bytes: der}), nil
}

// ParsePrivateKeyPEM decodes a PKCS#8 Ed25519 private key.
func ParsePrivateKeyPEM(b []byte) (ed25519.PrivateKey, error) {
	block, err := decodePEMBlock(b, PrivateKeyPEMType)
	if err != nil {
		return nil, err
	}
	key, perr := x509.ParsePKCS8PrivateKey(block.Bytes)
	if perr != nil {
		return nil, single("", CodeKeyInvalid, "PKCS#8 decode failed: "+excerpt(perr.Error()))
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, single("", CodeKeyInvalid, "key is not an Ed25519 private key")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, single("", CodeKeyInvalid, "key has the wrong length")
	}
	return priv, nil
}

// ParsePublicKeyPEM decodes a PKIX Ed25519 public key, as written by qwqctl
// keygen and listed in a trust store.
func ParsePublicKeyPEM(b []byte) (ed25519.PublicKey, error) {
	block, err := decodePEMBlock(b, PublicKeyPEMType)
	if err != nil {
		return nil, err
	}
	key, perr := x509.ParsePKIXPublicKey(block.Bytes)
	if perr != nil {
		return nil, single("", CodeKeyInvalid, "PKIX decode failed: "+excerpt(perr.Error()))
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, single("", CodeKeyInvalid, "key is not an Ed25519 public key")
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, single("", CodeKeyInvalid, "key has the wrong length")
	}
	return pub, nil
}

// decodePEMBlock decodes exactly one unencrypted PEM block of the wanted type.
func decodePEMBlock(b []byte, want string) (*pem.Block, error) {
	block, rest := pem.Decode(b)
	if block == nil {
		return nil, single("", CodeKeyInvalid, "no PEM block found")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, single("", CodeKeyInvalid, "more than one PEM block")
	}
	if block.Type != want {
		return nil, single("", CodeKeyInvalid, "PEM block is "+excerpt(block.Type)+", want "+excerpt(want))
	}
	if len(block.Headers) != 0 {
		return nil, single("", CodeKeyInvalid, "encrypted or headered PEM blocks are not supported")
	}
	return block, nil
}

// DigestFile returns the "sha256:<lower-case hex>" digest of dir/relPath.
//
// The path is opened with os.OpenInRoot, so it cannot escape dir, and only a
// regular file is accepted. This is the check ARCH §6.2 wants in ExecStartPre
// before a plugin process is started.
func DigestFile(dir, relPath string) (string, error) {
	f, err := openInRoot(dir, relPath)
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck // read only
	fi, serr := f.Stat()
	if serr != nil {
		return "", serr
	}
	if !fi.Mode().IsRegular() {
		return "", single(excerpt(relPath), CodeSourceInvalid, "not a regular file")
	}
	h := sha256.New()
	if _, cerr := io.Copy(h, f); cerr != nil {
		return "", cerr
	}
	return digestString(h.Sum(nil)), nil
}

// VerifyFile checks that dir/relPath is a regular file with digest want.
func VerifyFile(dir, relPath, want string) error {
	if !validDigest(want) {
		return single(excerpt(want), CodeDigestMalformed,
			`digest must be "sha256:" and 64 lower-case hex digits`)
	}
	got, err := DigestFile(dir, relPath)
	if err != nil {
		return err
	}
	if got != want {
		return single(relPath, CodeDigestMismatch, "content does not match the expected digest")
	}
	return nil
}

// openInRoot opens relPath below dir without allowing it to escape.
func openInRoot(dir, relPath string) (*os.File, error) {
	if !fs.ValidPath(relPath) {
		return nil, single(excerpt(relPath), CodePathInvalid, "not a clean relative path")
	}
	return os.OpenInRoot(dir, relPath)
}

// validDigest reports whether s is "sha256:" followed by 64 lower-case hex
// digits, the form manifest.files uses.
func validDigest(s string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(s, prefix) || len(s) != len(prefix)+64 {
		return false
	}
	for i := len(prefix); i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
