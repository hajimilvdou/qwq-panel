// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// aadDomain separates these ciphertexts from any other use of the same key.
const aadDomain = "qwq.secret.v1"

// aad returns the additional authenticated data that binds a ciphertext to its
// row: the id, owner and purpose it was stored with.
//
// The encoding is injective: a version domain followed by length-prefixed
// fields, so no two distinct triples produce the same bytes even when a field
// contains the separator. A ciphertext copied into another row, or relabelled
// with another purpose, therefore fails to open instead of decrypting.
func aad(id, owner, purpose string) []byte {
	b := make([]byte, 0, len(aadDomain)+len(id)+len(owner)+len(purpose)+12)
	b = append(b, aadDomain...)
	for _, f := range [...]string{id, owner, purpose} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
		b = append(b, f...)
	}
	return b
}

// seal encrypts plaintext for the row (id, owner, purpose) and returns the
// random nonce and the ciphertext with its GCM tag.
func seal(aead cipher.AEAD, id, owner, purpose string, plaintext []byte) (nonce, ciphertext []byte, err error) {
	nonce = make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("secrets: read nonce: %w", err)
	}
	return nonce, aead.Seal(nil, nonce, plaintext, aad(id, owner, purpose)), nil
}

// open decrypts a row's ciphertext. A failure means the row was tampered with,
// moved, relabelled, or encrypted with a key that is not in the ring.
func open(aead cipher.AEAD, nonce, ciphertext []byte, id, owner, purpose string) ([]byte, error) {
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("secrets: stored nonce has the wrong size")
	}
	if len(ciphertext) < aead.Overhead() {
		return nil, errors.New("secrets: stored ciphertext is too short")
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad(id, owner, purpose))
	if err != nil {
		return nil, errors.New("secrets: ciphertext authentication failed")
	}
	return plaintext, nil
}
