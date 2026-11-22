// SPDX-License-Identifier: Apache-2.0

package pkgfile

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/sdk/manifest"
)

// TestSignEnvelope pins the envelope format and the signature it carries.
func TestSignEnvelope(t *testing.T) {
	f := newFixture(t)
	if _, err := Sign(f.pkg, f.priv); err == nil {
		t.Fatal("Sign accepted a tar archive as a manifest")
	}
	raw := rawEntries(t, f.pkg)[0].data
	env, err := Sign(raw, f.priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sig, err := manifest.ParseSignature(env)
	if err != nil {
		t.Fatalf("ParseSignature: %v", err)
	}
	if sig.KeyID != manifest.KeyID(f.pub) {
		t.Errorf("key_id = %s, want %s", sig.KeyID, manifest.KeyID(f.pub))
	}
	if !ed25519.Verify(f.pub, raw, sig.Sig) {
		t.Error("the signature does not verify over the manifest bytes")
	}
	if !bytes.Equal(env, sig.Encode()) {
		t.Error("Sign did not return the canonical envelope encoding")
	}
	// A signature is deterministic, so signing twice gives the same bytes.
	again, err := Sign(raw, f.priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.Equal(env, again) {
		t.Error("signing the same manifest twice produced different envelopes")
	}
}

// TestSignRejects covers the two things Sign must never do: sign a manifest
// that does not parse, and accept a key of the wrong size.
func TestSignRejects(t *testing.T) {
	raw := rawEntries(t, newFixture(t).pkg)[0].data
	if _, err := Sign([]byte(`{"id":`), testKey(1)); err == nil {
		t.Fatal("Sign accepted invalid JSON")
	}
	if _, err := Sign([]byte(`{"schema_version":"9.9"}`), testKey(1)); err == nil {
		t.Fatal("Sign accepted an invalid manifest")
	}
	if _, err := Sign(raw, testKey(1)[:16]); err == nil {
		t.Fatal("Sign accepted a short key")
	} else {
		wantCode(t, err, CodeKeyInvalid)
	}
}

// TestPEMRoundTrip covers the key file format qwqctl keygen writes.
func TestPEMRoundTrip(t *testing.T) {
	priv := testKey(3)
	pub := priv.Public().(ed25519.PublicKey)

	privPEM, err := MarshalPrivateKeyPEM(priv)
	if err != nil {
		t.Fatalf("MarshalPrivateKeyPEM: %v", err)
	}
	gotPriv, err := ParsePrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM: %v", err)
	}
	if !gotPriv.Equal(priv) {
		t.Error("private key round trip changed the key")
	}

	pubPEM, err := MarshalPublicKeyPEM(pub)
	if err != nil {
		t.Fatalf("MarshalPublicKeyPEM: %v", err)
	}
	gotPub, err := ParsePublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("ParsePublicKeyPEM: %v", err)
	}
	if !gotPub.Equal(pub) {
		t.Error("public key round trip changed the key")
	}

	// Cross-type and garbage inputs are refused with the key code.
	if _, err := ParsePrivateKeyPEM(pubPEM); err == nil {
		t.Error("ParsePrivateKeyPEM accepted a public key")
	} else {
		wantCode(t, err, CodeKeyInvalid)
	}
	if _, err := ParsePublicKeyPEM(privPEM); err == nil {
		t.Error("ParsePublicKeyPEM accepted a private key")
	} else {
		wantCode(t, err, CodeKeyInvalid)
	}
	if _, err := ParsePublicKeyPEM([]byte("not a pem file")); err == nil {
		t.Error("ParsePublicKeyPEM accepted garbage")
	} else {
		wantCode(t, err, CodeKeyInvalid)
	}
	if _, err := ParsePublicKeyPEM(append(pubPEM, pubPEM...)); err == nil {
		t.Error("ParsePublicKeyPEM accepted two PEM blocks")
	} else {
		wantCode(t, err, CodeKeyInvalid)
	}
	if _, err := MarshalPublicKeyPEM(pub[:16]); err == nil {
		t.Error("MarshalPublicKeyPEM accepted a short key")
	}
	if _, err := MarshalPrivateKeyPEM(priv[:16]); err == nil {
		t.Error("MarshalPrivateKeyPEM accepted a short key")
	}
}

// TestDigestAndVerifyFile covers the helper an ExecStartPre check uses.
func TestDigestAndVerifyFile(t *testing.T) {
	f := newFixture(t)
	entry := f.manifest.Files["bin/plugin"]
	got, err := DigestFile(f.dir, "bin/plugin")
	if err != nil {
		t.Fatalf("DigestFile: %v", err)
	}
	if got != entry {
		t.Errorf("DigestFile = %s, want %s", got, entry)
	}
	if err := VerifyFile(f.dir, "bin/plugin", entry); err != nil {
		t.Errorf("VerifyFile: %v", err)
	}
	wrong := "sha256:" + strings.Repeat("0", 64)
	if err := VerifyFile(f.dir, "bin/plugin", wrong); err == nil {
		t.Fatal("VerifyFile accepted a wrong digest")
	} else {
		wantCode(t, err, CodeDigestMismatch)
	}
	if err := VerifyFile(f.dir, "bin/plugin", "sha256:abc"); err == nil {
		t.Fatal("VerifyFile accepted a malformed digest")
	} else {
		wantCode(t, err, CodeDigestMalformed)
	}
	if _, err := DigestFile(f.dir, "../manifest.json"); err == nil {
		t.Fatal("DigestFile accepted a path outside the directory")
	} else {
		wantCode(t, err, CodePathInvalid)
	}
	if _, err := DigestFile(f.dir, "bin"); err == nil {
		t.Fatal("DigestFile accepted a directory")
	}
	if _, err := DigestFile(f.dir, "bin/missing"); err == nil {
		t.Fatal("DigestFile accepted a missing file")
	}
	// A symlink inside the tree is read through, but a device or directory is
	// not a digestible file; the name check is the important part here.
	if err := os.Symlink("plugin", filepath.Join(f.dir, "bin", "link")); err == nil {
		if _, derr := DigestFile(f.dir, "bin/link"); derr != nil {
			t.Logf("symlink not digestible: %v", derr)
		}
	}
}

// TestResign: re-signing a canonical package reproduces it byte for byte, and
// re-signing with another key makes the package verifiable under that key.
func TestResign(t *testing.T) {
	f := newFixture(t)
	var a bytes.Buffer
	pkg, err := Resign(bytes.NewReader(f.pkg), &a, f.priv, Limits{})
	if err != nil {
		t.Fatalf("Resign: %v", err)
	}
	if !bytes.Equal(f.pkg, a.Bytes()) {
		t.Errorf("re-signing a canonical package changed %d bytes into %d", len(f.pkg), a.Len())
	}
	if pkg.Signature == nil || pkg.Signature.KeyID != manifest.KeyID(f.pub) {
		t.Errorf("Resign reported signature %+v", pkg.Signature)
	}

	// A second pass over the output is still identical.
	var b bytes.Buffer
	if _, err := Resign(bytes.NewReader(a.Bytes()), &b, f.priv, Limits{}); err != nil {
		t.Fatalf("Resign twice: %v", err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("re-signing is not idempotent")
	}

	// A key the manifest does not name is refused, exactly like Pack: the
	// manifest stays byte-for-byte, so a rotation has to re-pack.
	var c bytes.Buffer
	_, err = Resign(bytes.NewReader(f.pkg), &c, testKey(2), Limits{})
	wantCode(t, err, CodePublisherMismatch)
}

// TestResignUnsigned: an unsigned package can be signed.
func TestResignUnsigned(t *testing.T) {
	f := newFixture(t)
	var unsigned bytes.Buffer
	if _, err := Pack(f.dir, &unsigned, PackOptions{}); err != nil {
		t.Fatalf("Pack: %v", err)
	}
	var signed bytes.Buffer
	if _, err := Resign(bytes.NewReader(unsigned.Bytes()), &signed, f.priv, Limits{}); err != nil {
		t.Fatalf("Resign: %v", err)
	}
	if _, err := Read(bytes.NewReader(signed.Bytes()), trust(t, f.pub), ReadOptions{}); err != nil {
		t.Fatalf("Read: %v", err)
	}
}

// TestResignRejectsBrokenInput: Resign must not bless a package whose content
// contradicts its manifest.
func TestResignRejectsBrokenInput(t *testing.T) {
	f := newFixture(t)
	entries := replaceEntryData(rawEntries(t, f.pkg), "bin/plugin", []byte("tampered"))
	var out bytes.Buffer
	_, err := Resign(bytes.NewReader(buildArchive(t, entries)), &out, f.priv, Limits{})
	wantCode(t, err, CodeDigestMismatch)
	if _, err := Resign(bytes.NewReader(f.pkg), &out, testKey(1)[:5], Limits{}); err == nil {
		t.Fatal("Resign accepted a short key")
	}
}
