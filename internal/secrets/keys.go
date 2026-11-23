// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// MasterKeySize is the size of the AES-256 key in master.key.
const MasterKeySize = 32

// keyIDBytes is how much of SHA-256(key) becomes the key id: 8 bytes (64 bits)
// are enough that a collision never happens by accident, and the 16 hex
// characters stay readable in log lines and database rows.
const keyIDBytes = 8

// File names inside the keys directory. Retired keys are kept next to the
// primary one; the name carries their id so a key is never guessed.
const (
	masterKeyName = "master.key"
	retiredPrefix = "retired-"
	keyFileSuffix = ".key"
)

// Key is one AES-256 master key and its identifier.
//
// Key material must not leak: String, GoString and LogValue print the id only,
// and the bytes are unexported so printing a Key by accident cannot reveal it.
type Key struct {
	// ID is the lower-case hex of the first keyIDBytes bytes of SHA-256(key).
	ID string

	raw [MasterKeySize]byte
}

// String returns the key id, never the key.
func (k Key) String() string { return "key " + k.ID }

// GoString implements fmt.GoStringer so that %#v cannot print the key bytes.
func (k Key) GoString() string { return "secrets.Key{ID: " + k.ID + "}" }

// LogValue implements slog.LogValuer.
func (k Key) LogValue() slog.Value { return slog.StringValue("key " + k.ID) }

// keyID derives the public identifier of a key.
func keyID(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:keyIDBytes])
}

// newKey generates a fresh AES-256 key from crypto/rand.
func newKey() (Key, error) {
	var k Key
	if _, err := io.ReadFull(rand.Reader, k.raw[:]); err != nil {
		return Key{}, fmt.Errorf("secrets: read random bytes: %w", err)
	}
	k.ID = keyID(k.raw[:])
	return k, nil
}

// KeyRing is the set of master keys the host knows: the primary key that
// encrypts new values plus the retired keys that still open old rows.
//
// The ring is safe for concurrent use; it is read on every reveal and written
// only when an operator rotates keys.
type KeyRing struct {
	dir string

	mu      sync.RWMutex
	primary Key
	keys    map[string]Key
	aeads   map[string]cipher.AEAD
	hot     hotReloadState
}

// LoadKeyRing loads (and on first start creates) the key ring under
// dataDir/keys.
//
// The primary key is dataDir/keys/master.key: exactly MasterKeySize random
// bytes, mode 0600, in a directory with mode 0700. A key file or key directory
// that group or others can access is refused instead of silently repaired,
// because that is how a key leaks; the error names the file and the required
// mode (ADR-0008 §7).
func LoadKeyRing(dataDir string) (*KeyRing, error) {
	if dataDir == "" {
		return nil, errors.New("secrets: a data directory is required for the key ring")
	}
	dir := filepath.Join(dataDir, "keys")
	if err := ensureKeyDir(dir); err != nil {
		return nil, err
	}
	primary, err := loadOrCreatePrimary(filepath.Join(dir, masterKeyName))
	if err != nil {
		return nil, err
	}
	r := &KeyRing{
		dir:     dir,
		primary: primary,
		keys:    map[string]Key{primary.ID: primary},
		aeads:   make(map[string]cipher.AEAD),
	}
	if err := r.loadRetired(); err != nil {
		return nil, err
	}
	for id, k := range r.keys {
		aead, err := newAEAD(k)
		if err != nil {
			return nil, err
		}
		r.aeads[id] = aead
	}
	if fi, err := os.Lstat(filepath.Join(dir, masterKeyName)); err == nil {
		r.hot.masterModNano = fi.ModTime().UnixNano()
		r.hot.masterSize = fi.Size()
	}
	r.hot.lastCheckUnixNano.Store(time.Now().UnixNano())
	return r, nil
}

// Dir returns the directory that holds the key files.
func (r *KeyRing) Dir() string { return r.dir }

// Primary returns the key that encrypts new values, hot-reloading master.key
// if an external CLI rotation updated it on disk.
func (r *KeyRing) Primary() Key {
	return r.PrimaryHotSafe(&r.hot)
}

// IDs returns every key id, the primary first and the retired keys sorted after
// it. The ids are safe to log and to store.
func (r *KeyRing) IDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.keys))
	ids = append(ids, r.primary.ID)
	retired := make([]string, 0, len(r.keys)-1)
	for id := range r.keys {
		if id != r.primary.ID {
			retired = append(retired, id)
		}
	}
	sort.Strings(retired)
	return append(ids, retired...)
}

// Retired returns the ids of the keys that no longer encrypt new values.
func (r *KeyRing) Retired() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.keys)-1)
	for id := range r.keys {
		if id != r.primary.ID {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// aead returns the AEAD of a key id, rescanning the keys directory on a cache
// miss so newly rotated keys become visible without restarting the process.
func (r *KeyRing) aead(id string) (cipher.AEAD, error) {
	return r.aeadHotSafe(id)
}

// Rotate makes a new primary key and keeps the previous one as a retired key.
// It does not touch the database: Store.Rotate re-encrypts rows in batches.
//
// The retired copy of the old key is written before master.key is replaced, so
// a crash at any point leaves every existing ciphertext decryptable.
func (r *KeyRing) Rotate() (Key, error) {
	nk, err := newKey()
	if err != nil {
		return Key{}, err
	}
	aead, err := newAEAD(nk)
	if err != nil {
		return Key{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	old := r.primary
	if err := writeKeyFileAtomic(filepath.Join(r.dir, retiredPrefix+old.ID+keyFileSuffix), old); err != nil {
		return Key{}, err
	}
	if err := writeKeyFileAtomic(filepath.Join(r.dir, masterKeyName), nk); err != nil {
		return Key{}, err
	}
	r.keys[old.ID] = old
	r.keys[nk.ID] = nk
	r.aeads[nk.ID] = aead
	r.primary = nk
	if fi, err := os.Lstat(filepath.Join(r.dir, masterKeyName)); err == nil {
		r.hot.masterModNano = fi.ModTime().UnixNano()
		r.hot.masterSize = fi.Size()
	}
	return nk, nil
}

// DropRetired deletes the key file of a retired key. Call it only after
// Store.Rotate re-encrypted every row that used it; Store.KeyUsage reports
// which ids are still in use.
func (r *KeyRing) DropRetired(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if id == r.primary.ID {
		return errors.New("secrets: the primary key cannot be dropped")
	}
	if _, ok := r.keys[id]; !ok {
		return fmt.Errorf("secrets: key %s is not in the key ring", id)
	}
	if err := os.Remove(filepath.Join(r.dir, retiredPrefix+id+keyFileSuffix)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("secrets: remove retired key: %w", err)
	}
	if err := fsyncDir(r.dir); err != nil {
		return err
	}
	delete(r.keys, id)
	delete(r.aeads, id)
	return nil
}

// ensureKeyDir creates the keys directory with mode 0700 and refuses an
// existing one that is wider.
func ensureKeyDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("secrets: create key directory: %w", err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("secrets: stat key directory: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("secrets: %s is not a directory", dir)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("secrets: key directory %s has mode %04o; it must not be accessible by group or others (chmod 700 %s)", dir, perm, dir)
	}
	return nil
}

// loadOrCreatePrimary reads master.key, creating it atomically when it does not
// exist. Creation uses an exclusive link so that two processes starting at once
// cannot replace each other's key.
func loadOrCreatePrimary(path string) (Key, error) {
	for range 2 {
		k, err := readKeyFile(path)
		if err == nil {
			return k, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return Key{}, err
		}
		nk, err := newKey()
		if err != nil {
			return Key{}, err
		}
		created, err := createFileExclusive(path, nk.raw[:], 0o600)
		if err != nil {
			return Key{}, err
		}
		if created {
			return nk, nil
		}
		// Another process won the race; read the key it wrote.
	}
	return Key{}, fmt.Errorf("secrets: %s could not be read or created", path)
}

// readKeyFile reads one key file and enforces its permissions.
func readKeyFile(path string) (Key, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return Key{}, err
	}
	if !fi.Mode().IsRegular() {
		return Key{}, fmt.Errorf("secrets: %s is not a regular file", path)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return Key{}, fmt.Errorf("secrets: %s has mode %04o; the master key must not be accessible by group or others (chmod 600 %s)", path, perm, path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Key{}, fmt.Errorf("secrets: read %s: %w", path, err)
	}
	defer clear(raw)
	if len(raw) != MasterKeySize {
		return Key{}, fmt.Errorf("secrets: %s must contain exactly %d bytes, found %d", path, MasterKeySize, len(raw))
	}
	var k Key
	copy(k.raw[:], raw)
	k.ID = keyID(k.raw[:])
	return k, nil
}

// loadRetired reads all retired key files and checks that each file name
// matches the key it contains.
func (r *KeyRing) loadRetired() error {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return fmt.Errorf("secrets: read key directory: %w", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, retiredPrefix) || !strings.HasSuffix(name, keyFileSuffix) {
			continue
		}
		k, err := readKeyFile(filepath.Join(r.dir, name))
		if err != nil {
			return err
		}
		want := strings.TrimSuffix(strings.TrimPrefix(name, retiredPrefix), keyFileSuffix)
		if want != k.ID {
			return fmt.Errorf("secrets: retired key file %s holds key %s; rename it rather than guessing which key it is", name, k.ID)
		}
		r.keys[k.ID] = k
	}
	return nil
}

// writeKeyFileAtomic writes one key file with mode 0600.
func writeKeyFileAtomic(path string, k Key) error {
	return writeFileAtomic(path, k.raw[:], 0o600)
}

// writeFileAtomic replaces path with data via a temporary file in the same
// directory, fsync, rename and directory fsync. A crash leaves either the old
// or the new content, never a truncated key.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := writeTemp(dir, filepath.Base(path), data, perm)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }()
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("secrets: replace %s: %w", path, err)
	}
	return fsyncDir(dir)
}

// createFileExclusive writes path only if it does not exist yet. The final step
// is a hard link, which fails with EEXIST instead of replacing a file that
// another process just created; a rename would silently overwrite the key.
func createFileExclusive(path string, data []byte, perm os.FileMode) (bool, error) {
	dir := filepath.Dir(path)
	tmp, err := writeTemp(dir, filepath.Base(path), data, perm)
	if err != nil {
		return false, err
	}
	defer func() { _ = os.Remove(tmp) }()
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, fmt.Errorf("secrets: install %s: %w", path, err)
	}
	if err := fsyncDir(dir); err != nil {
		return false, err
	}
	return true, nil
}

// writeTemp creates and fsyncs a temporary file next to its final location and
// returns its path.
func writeTemp(dir, base string, data []byte, perm os.FileMode) (string, error) {
	f, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("secrets: create temporary file: %w", err)
	}
	tmp := f.Name()
	fail := func(err error) (string, error) {
		f.Close()
		_ = os.Remove(tmp)
		return "", err
	}
	if err := f.Chmod(perm); err != nil {
		return fail(fmt.Errorf("secrets: set mode on %s: %w", tmp, err))
	}
	if _, err := f.Write(data); err != nil {
		return fail(fmt.Errorf("secrets: write %s: %w", tmp, err))
	}
	if err := f.Sync(); err != nil {
		return fail(fmt.Errorf("secrets: sync %s: %w", tmp, err))
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("secrets: close %s: %w", tmp, err)
	}
	return tmp, nil
}

// fsyncDir makes a rename or link durable. Windows cannot fsync a directory
// handle, so the call is skipped there; the host itself only runs on Linux.
func fsyncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("secrets: open directory for sync: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("secrets: sync directory: %w", err)
	}
	return nil
}

// newAEAD builds the AES-256-GCM AEAD of a key.
func newAEAD(k Key) (cipher.AEAD, error) {
	block, err := aes.NewCipher(k.raw[:])
	if err != nil {
		return nil, fmt.Errorf("secrets: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secrets: gcm: %w", err)
	}
	return aead, nil
}
