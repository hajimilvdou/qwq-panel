// SPDX-License-Identifier: AGPL-3.0-only

// Package trust implements a dynamic composite publisher trust root combining
// read-only system keys (/etc/qwq/trust/*.pem) and administrator-managed custom
// developer keys (<DataDir>/trust/publishers/*.pem).
package trust

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/sdk/manifest"
	"github.com/qwq-panel/qwq/sdk/pkgfile"
)

const (
	// SourceOfficial marks read-only system trust keys from /etc/qwq/trust.
	SourceOfficial = "official"
	// SourceCustom marks administrator-managed developer keys from DataDir.
	SourceCustom = "custom"

	maxLabelRunes = 120
	maxCustomKeys = 128
)

var (
	// ErrOfficialKey is returned when attempting to remove a system trust key.
	ErrOfficialKey = errors.New("trust: official system keys cannot be removed")
	// ErrDuplicateKey is returned when adding a key that is already trusted.
	ErrDuplicateKey = errors.New("trust: public key is already trusted")
	// ErrKeyNotFound matches manifest.ErrKeyNotFound for unknown key IDs.
	ErrKeyNotFound = manifest.ErrKeyNotFound
	// ErrInvalidKey is returned when a public key PEM is not a valid Ed25519 PKIX key.
	ErrInvalidKey = errors.New("trust: invalid Ed25519 public key PEM")
	// ErrInvalidLabel is returned when a key label fails validation.
	ErrInvalidLabel = errors.New("trust: label must be 1-120 printable characters")
	// ErrInvalidKeyID is returned when a key_id does not match ed25519:<64hex>.
	ErrInvalidKeyID = errors.New("trust: invalid key_id format")
	// ErrTooManyKeys is returned when custom trust keys reach maxCustomKeys.
	ErrTooManyKeys = errors.New("trust: custom trust key limit reached")
)

var keyIDPattern = regexp.MustCompile(`^ed25519:([a-f0-9]{64})$`)

// TrustKeyInfo describes one trusted publisher public key.
type TrustKeyInfo struct {
	KeyID        string    `json:"key_id"`
	Label        string    `json:"label"`
	Source       string    `json:"source"`
	PublicKeyPEM string    `json:"public_key_pem"`
	AddedBy      string    `json:"added_by,omitempty"`
	AddedAt      time.Time `json:"added_at,omitempty"`
}

type customKeyMeta struct {
	KeyID   string    `json:"key_id"`
	Label   string    `json:"label"`
	AddedBy string    `json:"added_by,omitempty"`
	AddedAt time.Time `json:"added_at"`
}

// CompositeTrustStore implements manifest.TrustStore over a read-only system
// directory and a writable custom developer key directory.
type CompositeTrustStore struct {
	systemDir string
	customDir string
	clock     clock.Clock
	mu        sync.RWMutex
}

var _ manifest.TrustStore = (*CompositeTrustStore)(nil)

// NewCompositeTrustStore constructs a thread-safe CompositeTrustStore. Either
// directory may be empty or not yet created on disk.
func NewCompositeTrustStore(systemDir, customDir string, clk clock.Clock) *CompositeTrustStore {
	if clk == nil {
		clk = clock.System{}
	}
	var sysClean, custClean string
	if strings.TrimSpace(systemDir) != "" {
		sysClean = filepath.Clean(systemDir)
	}
	if strings.TrimSpace(customDir) != "" {
		custClean = filepath.Clean(customDir)
	}
	return &CompositeTrustStore{
		systemDir: sysClean,
		customDir: custClean,
		clock:     clk,
	}
}

// LookupKey implements manifest.TrustStore by dynamically consulting both
// system keys and custom developer keys so runtime updates take effect
// immediately without restarting the controller.
func (s *CompositeTrustStore) LookupKey(keyID string) (manifest.TrustedKey, error) {
	if !keyIDPattern.MatchString(keyID) {
		return manifest.TrustedKey{}, manifest.ErrKeyNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	sysKeys, err := s.loadSystemKeysLocked()
	if err != nil {
		return manifest.TrustedKey{}, err
	}
	if k, ok := sysKeys[keyID]; ok {
		return k.trusted, nil
	}
	custKeys, err := s.loadCustomKeysLocked()
	if err != nil {
		return manifest.TrustedKey{}, err
	}
	if k, ok := custKeys[keyID]; ok {
		return k.trusted, nil
	}
	return manifest.TrustedKey{}, manifest.ErrKeyNotFound
}

// List returns all currently trusted official and custom publisher keys.
func (s *CompositeTrustStore) List() ([]TrustKeyInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sysKeys, err := s.loadSystemKeysLocked()
	if err != nil {
		return nil, err
	}
	custKeys, err := s.loadCustomKeysLocked()
	if err != nil {
		return nil, err
	}

	out := make([]TrustKeyInfo, 0, len(sysKeys)+len(custKeys))
	for _, entry := range sysKeys {
		out = append(out, entry.info)
	}
	for id, entry := range custKeys {
		if _, isOfficial := sysKeys[id]; isOfficial {
			continue
		}
		out = append(out, entry.info)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source == SourceOfficial
		}
		if out[i].Source == SourceCustom && !out[i].AddedAt.Equal(out[j].AddedAt) {
			return out[i].AddedAt.After(out[j].AddedAt)
		}
		return out[i].KeyID < out[j].KeyID
	})
	return out, nil
}

// Add validates and persists a custom developer Ed25519 public key.
func (s *CompositeTrustStore) Add(label, pubPEM, addedBy string) (TrustKeyInfo, error) {
	cleanLabel, err := validateLabel(label)
	if err != nil {
		return TrustKeyInfo{}, err
	}
	pub, err := pkgfile.ParsePublicKeyPEM([]byte(strings.TrimSpace(pubPEM)))
	if err != nil {
		return TrustKeyInfo{}, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	canonPEM, err := pkgfile.MarshalPublicKeyPEM(pub)
	if err != nil {
		return TrustKeyInfo{}, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	keyID := manifest.KeyID(pub)
	hexPart := strings.TrimPrefix(keyID, "ed25519:")

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.customDir == "" {
		return TrustKeyInfo{}, errors.New("trust: custom trust key directory is not configured")
	}
	sysKeys, err := s.loadSystemKeysLocked()
	if err != nil {
		return TrustKeyInfo{}, err
	}
	if _, dup := sysKeys[keyID]; dup {
		return TrustKeyInfo{}, ErrDuplicateKey
	}
	custKeys, err := s.loadCustomKeysLocked()
	if err != nil {
		return TrustKeyInfo{}, err
	}
	if _, dup := custKeys[keyID]; dup {
		return TrustKeyInfo{}, ErrDuplicateKey
	}
	if len(custKeys) >= maxCustomKeys {
		return TrustKeyInfo{}, ErrTooManyKeys
	}

	if err := os.MkdirAll(s.customDir, 0o700); err != nil {
		return TrustKeyInfo{}, fmt.Errorf("trust: create custom trust directory: %w", err)
	}

	now := s.clock.Now().UTC()
	meta := customKeyMeta{
		KeyID:   keyID,
		Label:   cleanLabel,
		AddedBy: strings.TrimSpace(addedBy),
		AddedAt: now,
	}
	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return TrustKeyInfo{}, fmt.Errorf("trust: marshal key metadata: %w", err)
	}
	metaBytes = append(metaBytes, '\n')

	pemPath := filepath.Join(s.customDir, hexPart+".pem")
	metaPath := filepath.Join(s.customDir, hexPart+".meta.json")
	if err := writeFileAtomic(pemPath, canonPEM, 0o644); err != nil {
		return TrustKeyInfo{}, fmt.Errorf("trust: write public key: %w", err)
	}
	if err := writeFileAtomic(metaPath, metaBytes, 0o600); err != nil {
		_ = os.Remove(pemPath)
		return TrustKeyInfo{}, fmt.Errorf("trust: write key metadata: %w", err)
	}

	return TrustKeyInfo{
		KeyID:        keyID,
		Label:        cleanLabel,
		Source:       SourceCustom,
		PublicKeyPEM: string(canonPEM),
		AddedBy:      meta.AddedBy,
		AddedAt:      now,
	}, nil
}

// Remove deletes a custom developer key by key_id. Official keys are protected
// and return ErrOfficialKey.
func (s *CompositeTrustStore) Remove(keyID string) error {
	if !keyIDPattern.MatchString(keyID) {
		return ErrInvalidKeyID
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	sysKeys, err := s.loadSystemKeysLocked()
	if err != nil {
		return err
	}
	if _, isOfficial := sysKeys[keyID]; isOfficial {
		return ErrOfficialKey
	}
	custKeys, err := s.loadCustomKeysLocked()
	if err != nil {
		return err
	}
	entry, ok := custKeys[keyID]
	if !ok {
		return ErrKeyNotFound
	}
	if err := os.Remove(entry.pemPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("trust: remove public key: %w", err)
	}
	if entry.metaPath != "" {
		if err := os.Remove(entry.metaPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("trust: remove key metadata: %w", err)
		}
	}
	return nil
}

type loadedKey struct {
	trusted  manifest.TrustedKey
	info     TrustKeyInfo
	pemPath  string
	metaPath string
}

func (s *CompositeTrustStore) loadSystemKeysLocked() (map[string]loadedKey, error) {
	out := make(map[string]loadedKey)
	if s.systemDir == "" {
		return out, nil
	}
	entries, err := os.ReadDir(s.systemDir)
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("trust: read system trust dir %s: %w", s.systemDir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pem") {
			continue
		}
		path := filepath.Join(s.systemDir, entry.Name())
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil, fmt.Errorf("trust: read official key %s: %w", entry.Name(), rerr)
		}
		pub, perr := pkgfile.ParsePublicKeyPEM(raw)
		if perr != nil {
			return nil, fmt.Errorf("trust: parse official key %s: %w", entry.Name(), perr)
		}
		key := manifest.TrustedKey{PublicKey: pub}
		if err := loadTrustPolicy(strings.TrimSuffix(path, ".pem")+".policy.json", &key); err != nil {
			return nil, fmt.Errorf("trust: parse policy for official key %s: %w", entry.Name(), err)
		}
		canonPEM, merr := pkgfile.MarshalPublicKeyPEM(pub)
		if merr != nil {
			return nil, merr
		}
		keyID := manifest.KeyID(pub)
		label := strings.TrimSuffix(entry.Name(), ".pem")
		if key.Publisher != "" {
			label = key.Publisher
		}
		var addedAt time.Time
		if fi, serr := entry.Info(); serr == nil {
			addedAt = fi.ModTime().UTC()
		}
		out[keyID] = loadedKey{
			trusted: key,
			info: TrustKeyInfo{
				KeyID:        keyID,
				Label:        label,
				Source:       SourceOfficial,
				PublicKeyPEM: string(canonPEM),
				AddedAt:      addedAt,
			},
			pemPath: path,
		}
	}
	return out, nil
}

func (s *CompositeTrustStore) loadCustomKeysLocked() (map[string]loadedKey, error) {
	out := make(map[string]loadedKey)
	if s.customDir == "" {
		return out, nil
	}
	entries, err := os.ReadDir(s.customDir)
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("trust: read custom trust dir %s: %w", s.customDir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pem") {
			continue
		}
		pemPath := filepath.Join(s.customDir, entry.Name())
		raw, rerr := os.ReadFile(pemPath)
		if rerr != nil {
			return nil, fmt.Errorf("trust: read custom key %s: %w", entry.Name(), rerr)
		}
		pub, perr := pkgfile.ParsePublicKeyPEM(raw)
		if perr != nil {
			// Skip corrupted leftover files in customDir? Fail closed for safety.
			return nil, fmt.Errorf("trust: parse custom key %s: %w", entry.Name(), perr)
		}
		canonPEM, merr := pkgfile.MarshalPublicKeyPEM(pub)
		if merr != nil {
			return nil, merr
		}
		keyID := manifest.KeyID(pub)
		metaPath := strings.TrimSuffix(pemPath, ".pem") + ".meta.json"
		label := strings.TrimSuffix(entry.Name(), ".pem")
		var addedBy string
		var addedAt time.Time
		if metaRaw, err := os.ReadFile(metaPath); err == nil {
			var meta customKeyMeta
			if jerr := json.Unmarshal(metaRaw, &meta); jerr == nil {
				if meta.Label != "" {
					label = meta.Label
				}
				addedBy = meta.AddedBy
				addedAt = meta.AddedAt.UTC()
			}
		} else if fi, serr := entry.Info(); serr == nil {
			addedAt = fi.ModTime().UTC()
		}
		out[keyID] = loadedKey{
			trusted: manifest.TrustedKey{PublicKey: pub},
			info: TrustKeyInfo{
				KeyID:        keyID,
				Label:        label,
				Source:       SourceCustom,
				PublicKeyPEM: string(canonPEM),
				AddedBy:      addedBy,
				AddedAt:      addedAt,
			},
			pemPath:  pemPath,
			metaPath: metaPath,
		}
	}
	return out, nil
}

func loadTrustPolicy(path string, key *manifest.TrustedKey) error {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var policy struct {
		Publisher string   `json:"publisher"`
		PluginIDs []string `json:"plugin_ids"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&policy); err != nil {
		return err
	}
	key.Publisher, key.PluginIDs = policy.Publisher, policy.PluginIDs
	return nil
}

func validateLabel(label string) (string, error) {
	trimmed := strings.TrimSpace(label)
	n := utf8.RuneCountInString(trimmed)
	if n == 0 || n > maxLabelRunes {
		return "", ErrInvalidLabel
	}
	for _, r := range trimmed {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return "", ErrInvalidLabel
		}
	}
	return trimmed, nil
}

func writeFileAtomic(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".trust-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if _, err := tmp.Write(data); err != nil {
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
