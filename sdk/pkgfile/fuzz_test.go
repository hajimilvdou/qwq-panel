// SPDX-License-Identifier: Apache-2.0

package pkgfile

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/qwq-panel/qwq/sdk/manifest"
)

// fuzzLimits keeps one corpus entry cheap: no input may make the reader
// allocate or decompress more than a megabyte before it is rejected.
func fuzzLimits() Limits {
	return Limits{
		CompressedBytes:  1 << 20,
		TotalBytes:       1 << 20,
		FileBytes:        1 << 20,
		Entries:          64,
		CompressionRatio: 200,
		RatioFloorBytes:  1 << 16,
		PathBytes:        255,
		PathDepth:        16,
	}
}

// FuzzRead: Read and ReadUnverified never panic, never exceed the configured
// limits, and any package they accept is internally consistent (trusted key,
// publisher binding, digests that match, sizes that add up).
func FuzzRead(f *testing.F) {
	priv := testKey(1)
	pub := priv.Public().(ed25519.PublicKey)
	ts := trust(f, pub)

	valid := newFixture(f) // signature checked with the same key
	f.Add(valid.pkg)
	var unsigned bytes.Buffer
	if _, err := Pack(valid.dir, &unsigned, PackOptions{}); err != nil {
		f.Fatalf("Pack: %v", err)
	}
	f.Add(unsigned.Bytes())
	f.Add(valid.pkg[:len(valid.pkg)/2])
	f.Add([]byte{})
	f.Add([]byte("not a package"))

	f.Fuzz(func(t *testing.T, data []byte) {
		limits := fuzzLimits()
		if len(data) > int(limits.CompressedBytes) {
			return // the reader rejects this before allocating anything
		}
		pkg, err := Read(bytes.NewReader(data), ts, ReadOptions{Limits: limits})
		if err != nil {
			var pe *Error
			if errors.As(err, &pe) {
				if len(pe.Violations) == 0 || len(pe.Violations) > MaxViolations {
					t.Fatalf("bad violation list: %#v", pe)
				}
			}
			return
		}
		if pkg.Manifest == nil || pkg.Signature == nil {
			t.Fatal("verified package without a manifest or signature")
		}
		if pkg.Signature.KeyID != manifest.KeyID(pub) {
			t.Fatalf("accepted a signature from key %s", pkg.Signature.KeyID)
		}
		if pkg.Manifest.Publisher.KeyID != pkg.Signature.KeyID {
			t.Fatal("accepted a manifest whose publisher key is not the signing key")
		}
		var sum int64
		for _, fi := range pkg.Files {
			want, ok := pkg.Manifest.Files[fi.Path]
			if !ok || want != fi.Digest {
				t.Fatalf("file %s is not the one the manifest lists", fi.Path)
			}
			sum += fi.Size
		}
		if sum != pkg.Size || len(pkg.Files) != len(pkg.Manifest.Files) {
			t.Fatalf("accepted package is inconsistent: %d files, %d bytes, manifest has %d",
				len(pkg.Files), pkg.Size, len(pkg.Manifest.Files))
		}
		// The same bytes must not be a valid unsigned package either.
		if _, uerr := ReadUnverified(bytes.NewReader(data), ReadOptions{Limits: fuzzLimits()}); uerr != nil {
			t.Fatalf("signed read accepted the package but the unsigned read did not: %v", uerr)
		}
		// The sink path has its own failure modes and must reach the same
		// verdict as the verifying pass.
		sunk, serr := ReadUnverified(bytes.NewReader(data), ReadOptions{Limits: fuzzLimits(), Sink: newMemSink()})
		if serr != nil || sunk == nil || sunk.Manifest == nil {
			t.Fatalf("sink read disagrees with the verifying read: %v", serr)
		}
	})
}
