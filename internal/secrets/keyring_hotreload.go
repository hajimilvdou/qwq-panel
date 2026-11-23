// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"crypto/cipher"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// primaryStatInterval bounds how frequently Primary() stats master.key on the
// hot path (at most once per second), keeping normal seals free of I/O while
// hot-reloading an external CLI rotation within 1 second.
const primaryStatInterval = time.Second

type hotReloadState struct {
	lastCheckUnixNano atomic.Int64
	masterModNano     int64
	masterSize        int64
}

// Reload rescans master.key and retired-*.key from disk and merges new keys
// into the in-memory ring without dropping previously loaded keys (preventing
// in-flight transactions from failing while an operator rotates keys online).
func (r *KeyRing) Reload() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reloadLocked()
}

func (r *KeyRing) reloadLocked() error {
	masterPath := filepath.Join(r.dir, masterKeyName)
	fi, err := os.Lstat(masterPath)
	if err != nil {
		return fmt.Errorf("secrets: stat master key on reload: %w", err)
	}
	pk, err := readKeyFile(masterPath)
	if err != nil {
		return err
	}
	if _, exists := r.keys[pk.ID]; !exists {
		paead, err := newAEAD(pk)
		if err != nil {
			return err
		}
		r.keys[pk.ID] = pk
		r.aeads[pk.ID] = paead
	}
	r.primary = pk

	if err := r.loadRetired(); err != nil {
		return err
	}
	for id, k := range r.keys {
		if _, ok := r.aeads[id]; !ok {
			a, err := newAEAD(k)
			if err != nil {
				return err
			}
			r.aeads[id] = a
		}
	}
	r.hot.masterModNano = fi.ModTime().UnixNano()
	r.hot.masterSize = fi.Size()
	return nil
}

// PrimaryHotSafe checks master.key at most once per primaryStatInterval and
// hot-switches r.primary when an external CLI (`qwq rotate-master-key`) rotates
// the master key on disk.
func (r *KeyRing) PrimaryHotSafe(state *hotReloadState) Key {
	now := time.Now().UnixNano()
	last := state.lastCheckUnixNano.Load()
	if now-last >= int64(primaryStatInterval) && state.lastCheckUnixNano.CompareAndSwap(last, now) {
		if fi, err := os.Lstat(filepath.Join(r.dir, masterKeyName)); err == nil {
			mod := fi.ModTime().UnixNano()
			size := fi.Size()
			r.mu.RLock()
			changed := mod != state.masterModNano || size != state.masterSize
			r.mu.RUnlock()
			if changed {
				r.mu.Lock()
				_ = r.reloadLocked()
				pk := r.primary
				r.mu.Unlock()
				return pk
			}
		}
	}
	r.mu.RLock()
	pk := r.primary
	r.mu.RUnlock()
	return pk
}

// aeadHotSafe looks up the AEAD for id, rescanning the keys directory once on
// a cache miss so ciphertexts encrypted by a freshly rotated external key can
// be decrypted seamlessly without restarting the controller.
func (r *KeyRing) aeadHotSafe(id string) (cipher.AEAD, error) {
	r.mu.RLock()
	a, ok := r.aeads[id]
	r.mu.RUnlock()
	if ok {
		return a, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.aeads[id]; ok {
		return a, nil
	}
	_ = r.reloadLocked()
	if a, ok := r.aeads[id]; ok {
		return a, nil
	}
	return nil, fmt.Errorf("secrets: key %s is not in the key ring; restore its retired key file before the values it encrypted are lost", id)
}
