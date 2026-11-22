// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Detached signature (ARCH §5.1, §10.4).
//
// signatures/manifest.sig is a small JSON envelope:
//
//	{"key_id": "ed25519:<64 hex>", "signature": "<standard base64 of 64 bytes>"}
//
// "signature" is a plain Ed25519 signature (RFC 8032, no prehash, no context)
// over the raw bytes of manifest.json. The envelope carries key_id because
// the key must be found before the manifest is parsed. It is decoded with the
// same strict decoder as manifests (no duplicate or unknown keys).
const (
	SignaturePath    = "signatures/manifest.sig"
	MaxSignatureSize = 1024
)

const keyIDPrefix = "ed25519:"

// keyIDPattern is the exact KeyID format: full SHA-256, lower-case hex. It is
// the same pattern as publisher.key_id in the manifest schema.
var keyIDPattern = regexp.MustCompile(`^ed25519:[a-f0-9]{64}$`)

// KeyID returns "ed25519:" + hex(SHA-256(pub)). The full 256-bit digest is
// used: key ids are lookup keys into the trust root, and a truncated id
// would let a second key (honest or crafted) collide with a trusted one.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return keyIDPrefix + hex.EncodeToString(sum[:])
}

// Signature is the decoded signatures/manifest.sig.
type Signature struct {
	KeyID string
	Sig   []byte // 64 bytes
}

// Encode returns the canonical envelope bytes.
func (s Signature) Encode() []byte {
	b, _ := json.Marshal(struct {
		KeyID     string `json:"key_id"`
		Signature string `json:"signature"`
	}{s.KeyID, base64.StdEncoding.EncodeToString(s.Sig)})
	return append(b, '\n')
}

// ParseSignature strictly decodes a signature envelope. On failure the error
// is an *Error with code SIGNATURE_MALFORMED; pointers refer to the envelope.
func ParseSignature(b []byte) (*Signature, error) {
	bad := func(ptr, msg string) (*Signature, error) {
		return nil, single(ptr, CodeSignatureMalformed, msg)
	}
	if len(b) > MaxSignatureSize {
		return bad("", fmt.Sprintf("signature file is larger than %d bytes", MaxSignatureSize))
	}
	tree, derr := decodeStrict(b)
	if derr != nil {
		return bad(derr.Violations[0].Pointer, "invalid signature envelope: "+derr.Violations[0].Message)
	}
	obj, ok := tree.(map[string]any)
	if !ok {
		return bad("", "signature envelope must be an object")
	}
	for k := range obj {
		if k != "key_id" && k != "signature" {
			return bad(join("", k), "unknown field in signature envelope")
		}
	}
	keyID, _ := obj["key_id"].(string)
	if !keyIDPattern.MatchString(keyID) {
		return bad("/key_id", "key_id must be \"ed25519:\" followed by 64 lower-case hex digits")
	}
	enc, _ := obj["signature"].(string)
	sig, err := base64.StdEncoding.Strict().DecodeString(enc)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return bad("/signature", "signature must be standard base64 of 64 bytes")
	}
	return &Signature{KeyID: keyID, Sig: sig}, nil
}

// TrustedKey is a public key from the local trust root.
type TrustedKey struct {
	PublicKey ed25519.PublicKey
	// Publisher, if set, is the only publisher.id this key may sign for.
	Publisher string
	// PluginIDs, if not nil, are the only plugin ids this key may sign for:
	// exact ids, or a prefix written as "acme.*" (ADR-0015). nil is unrestricted;
	// an empty list allows nothing.
	PluginIDs []string
}

// allowsPlugin reports whether the key may sign for the plugin id.
func (k TrustedKey) allowsPlugin(id string) bool {
	if k.PluginIDs == nil {
		return true
	}
	for _, pattern := range k.PluginIDs {
		if prefix, wild := strings.CutSuffix(pattern, "*"); wild && strings.HasSuffix(prefix, ".") {
			if strings.HasPrefix(id, prefix) {
				return true
			}
		} else if id == pattern {
			return true
		}
	}
	return false
}

// ErrKeyNotFound is returned by TrustStore.LookupKey for unknown key ids.
var ErrKeyNotFound = errors.New("manifest: key not in trust store")

// TrustStore is the local trust root (ARCH §10.2, §10.4). Implementations
// must return ErrKeyNotFound (possibly wrapped) for unknown ids; any other
// error aborts verification and is returned as is.
type TrustStore interface {
	LookupKey(keyID string) (TrustedKey, error)
}

// StaticTrustStore is an immutable in-memory TrustStore.
type StaticTrustStore struct{ keys map[string]TrustedKey }

// NewStaticTrustStore indexes keys by KeyID(PublicKey). It rejects keys of the
// wrong length and duplicates.
func NewStaticTrustStore(keys ...TrustedKey) (*StaticTrustStore, error) {
	s := &StaticTrustStore{keys: make(map[string]TrustedKey, len(keys))}
	for _, k := range keys {
		if len(k.PublicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("manifest: public key must be %d bytes", ed25519.PublicKeySize)
		}
		id := KeyID(k.PublicKey)
		if _, dup := s.keys[id]; dup {
			return nil, fmt.Errorf("manifest: duplicate trusted key %s", id)
		}
		k.PublicKey = append(ed25519.PublicKey(nil), k.PublicKey...)
		s.keys[id] = k
	}
	return s, nil
}

// LookupKey implements TrustStore.
func (s *StaticTrustStore) LookupKey(keyID string) (TrustedKey, error) {
	k, ok := s.keys[keyID]
	if !ok {
		return TrustedKey{}, ErrKeyNotFound
	}
	return k, nil
}

// VerifyAndParse verifies the detached signature over raw, then parses raw.
// Order (ARCH §6.2): size → signature envelope → trusted key → Ed25519 verify
// → Parse → publisher.key_id equals the signing key (and publisher.id equals
// the key's bound publisher, if any). Nothing from raw is interpreted before
// the signature is verified. Verification failures are *Error; trust store
// failures other than ErrKeyNotFound are returned wrapped.
func VerifyAndParse(raw, sig []byte, ts TrustStore) (*Manifest, error) {
	if len(raw) > MaxSize {
		return nil, single("", CodeTooLarge, fmt.Sprintf("manifest is %d bytes, more than %d", len(raw), MaxSize))
	}
	s, err := ParseSignature(sig)
	if err != nil {
		return nil, err
	}
	key, err := ts.LookupKey(s.KeyID)
	if errors.Is(err, ErrKeyNotFound) {
		return nil, single("", CodeKeyUnknown, "signing key "+s.KeyID+" is not trusted")
	}
	if err != nil {
		return nil, fmt.Errorf("manifest: trust store: %w", err)
	}
	if len(key.PublicKey) != ed25519.PublicKeySize || KeyID(key.PublicKey) != s.KeyID {
		return nil, fmt.Errorf("manifest: trust store returned a key that does not match %s", s.KeyID)
	}
	if !ed25519.Verify(key.PublicKey, raw, s.Sig) {
		return nil, single("", CodeSignatureInvalid, "signature does not verify with key "+s.KeyID)
	}
	m, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	var vs []Violation
	if m.Publisher.KeyID != s.KeyID {
		vs = append(vs, Violation{"/publisher/key_id", CodeKeyIDMismatch, "publisher.key_id is not the signing key " + s.KeyID})
	}
	if key.Publisher != "" && m.Publisher.ID != key.Publisher {
		vs = append(vs, Violation{"/publisher/id", CodePublisherMismatch, "signing key may only sign for publisher " + excerpt(key.Publisher)})
	}
	if !key.allowsPlugin(m.ID) {
		vs = append(vs, Violation{"/id", CodePluginNamespaceMismatch, "signing key may not sign for plugin " + excerpt(m.ID)})
	}
	if e := newError(vs); e != nil {
		return nil, e
	}
	return m, nil
}
