// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

const (
	// stateFormat is the version of the built-in state file.
	stateFormat = 1
	// stateFileName is the file below Config.StateDir.
	stateFileName = "state.json"
	// stateFileMode is private to the Agent: the state may contain data the
	// plugin would not expose to other local users.
	stateFileMode fs.FileMode = 0o600
)

// errInvalidPageToken marks a ListState token that is not one this store
// issued.
var errInvalidPageToken = errors.New("hostsvc: invalid page token")

// stateService implements HostStateService. Every handler validates the
// key/value grammar and size before it touches the store, so a custom
// StateStore never sees malformed input from the ABI.
type stateService struct {
	platformv1.UnimplementedHostStateServiceServer
	s *Server
}

// GetState reads one key.
func (x *stateService) GetState(ctx context.Context, req *platformv1.GetStateRequest) (*platformv1.GetStateResponse, error) {
	if !validStateKey(req.GetKey(), x.s.lim.MaxKeyBytes, false) {
		return nil, invalidArg("invalid state key")
	}
	entry, found, err := x.s.store.Get(ctx, req.GetKey())
	if err != nil {
		return nil, x.s.stateError("get state", err)
	}
	if !found {
		return &platformv1.GetStateResponse{Found: false}, nil
	}
	return &platformv1.GetStateResponse{
		ValueJson: append([]byte(nil), entry.Value...),
		Found:     true,
		Revision:  entry.Revision,
	}, nil
}

// PutState writes one key and returns its new revision. A failed
// must_not_exist/expected_revision guard is ABORTED, which the SDK maps to
// REVISION_CONFLICT.
func (x *stateService) PutState(ctx context.Context, req *platformv1.PutStateRequest) (*platformv1.PutStateResponse, error) {
	if !validStateKey(req.GetKey(), x.s.lim.MaxKeyBytes, false) {
		return nil, invalidArg("invalid state key")
	}
	if len(req.GetValueJson()) > x.s.lim.MaxValueBytes {
		return nil, limitError("state.value_bytes", int64(x.s.lim.MaxValueBytes))
	}
	if !jsonValid(req.GetValueJson()) {
		return nil, invalidArg("the state value must be a JSON document")
	}
	var guard StateGuard
	switch pre := req.GetPrecondition().(type) {
	case *platformv1.PutStateRequest_MustNotExist:
		guard.MustNotExist = pre.MustNotExist
	case *platformv1.PutStateRequest_ExpectedRevision:
		// The oneof is set, so the plugin asked for a guard. An empty
		// revision cannot match a stored revision; treat it as "must not
		// exist" (the same rule Precondition uses for an empty revision)
		// instead of silently turning it into an unconditional write.
		if pre.ExpectedRevision == "" {
			guard.MustNotExist = true
		} else {
			guard.ExpectedRevision = pre.ExpectedRevision
		}
	}
	revision, err := x.s.store.Put(ctx, req.GetKey(), req.GetValueJson(), guard)
	if err != nil {
		return nil, x.s.stateError("put state", err)
	}
	return &platformv1.PutStateResponse{Revision: revision}, nil
}

// DeleteState deletes one key. An empty expected_revision is unconditional.
func (x *stateService) DeleteState(ctx context.Context, req *platformv1.DeleteStateRequest) (*platformv1.DeleteStateResponse, error) {
	if !validStateKey(req.GetKey(), x.s.lim.MaxKeyBytes, false) {
		return nil, invalidArg("invalid state key")
	}
	if err := x.s.store.Delete(ctx, req.GetKey(), req.GetExpectedRevision()); err != nil {
		return nil, x.s.stateError("delete state", err)
	}
	return &platformv1.DeleteStateResponse{}, nil
}

// ListState lists keys in byte order, one bounded page at a time.
func (x *stateService) ListState(ctx context.Context, req *platformv1.ListStateRequest) (*platformv1.ListStateResponse, error) {
	if !validStateKey(req.GetPrefix(), x.s.lim.MaxKeyBytes, true) {
		return nil, invalidArg("invalid state prefix")
	}
	pageSize := int(req.GetPageSize())
	if pageSize <= 0 {
		pageSize = x.s.lim.PageSize
	}
	if pageSize > x.s.lim.MaxPageSize {
		pageSize = x.s.lim.MaxPageSize
	}
	page, err := x.s.store.List(ctx, req.GetPrefix(), req.GetPageToken(), pageSize, req.GetIncludeValues())
	if err != nil {
		return nil, x.s.stateError("list state", err)
	}
	// page_size counts entries, but a page must also fit one gRPC message. Cut
	// it by bytes, always keeping one entry so the listing makes progress; the
	// token continues after the last entry returned.
	budget := x.s.lim.MaxRequestBytes - listEnvelopeBytes
	used := 0
	next := page.NextPageToken
	entries := make([]*platformv1.StateEntry, 0, len(page.Entries))
	for _, entry := range page.Entries {
		size := len(entry.Key) + len(entry.Revision) + len(entry.Value) + listEntryOverhead
		if len(entries) > 0 && used+size > budget {
			next = encodePageToken(entries[len(entries)-1].GetKey())
			break
		}
		used += size
		out := &platformv1.StateEntry{Key: entry.Key, Revision: entry.Revision}
		if req.GetIncludeValues() {
			out.ValueJson = append([]byte(nil), entry.Value...)
		}
		entries = append(entries, out)
	}
	return &platformv1.ListStateResponse{Entries: entries, NextPageToken: next}, nil
}

const (
	// listEnvelopeBytes is the room a ListState page leaves below the message
	// limit for the page token and gRPC framing.
	listEnvelopeBytes = 64 << 10
	// listEntryOverhead covers the protobuf tags and lengths of one entry.
	listEntryOverhead = 32
)

// stateError maps store failures to the ABI status codes.
func (s *Server) stateError(operation string, err error) error {
	var conflict *StateConflictError
	if errors.As(err, &conflict) {
		// ABORTED is the gRPC code for a failed compare-and-swap; the SDK
		// maps it to REVISION_CONFLICT (see sdk/pluginsdk/errors.go).
		return status.Errorf(codes.Aborted, "state revision conflict (current revision %q)", conflict.Current)
	}
	if errors.Is(err, errInvalidPageToken) {
		return invalidArg("invalid page token")
	}
	if errors.Is(err, errInvalidValue) {
		return invalidArg("the state value must be a JSON document")
	}
	if errors.Is(err, errInvalidKey) {
		return invalidArg("invalid state key")
	}
	return s.dependencyError(operation, err)
}

// stateDocument is the JSON layout of the built-in state file:
//
//	{"format":1,"next_revision":12,"entries":{"key":{"revision":"11","value":...}}}
//
// encoding/json sorts map keys, so the file is deterministic and diffable. A
// key carries its own opaque decimal revision; next_revision keeps revisions
// monotonic across restarts and deletions.
type stateDocument struct {
	Format       int                    `json:"format"`
	NextRevision uint64                 `json:"next_revision"`
	Entries      map[string]stateRecord `json:"entries"`
}

// stateRecord is one value in the state file.
type stateRecord struct {
	Revision string          `json:"revision"`
	Value    json.RawMessage `json:"value"`
}

// fileState is the built-in StateStore: one JSON file per instance, rewritten
// atomically (temp file, fsync, rename, fsync directory) on every mutation.
// One file is one instance and one Server owns it, so a process mutex is
// enough; cross-process access is not supported and is a wiring error.
type fileState struct {
	mu      sync.Mutex
	path    string
	limits  Limits
	entries map[string]stateRecord
	total   int64
	next    uint64
	closed  bool
}

// openFileState creates the state directory and loads state.json. A corrupt or
// oversized file fails startup instead of serving truncated state.
func openFileState(dir string, limits Limits) (*fileState, error) {
	if err := ensureDir(dir); err != nil {
		return nil, fmt.Errorf("hostsvc: create state directory: %w", err)
	}
	store := &fileState{
		path:    filepath.Join(dir, stateFileName),
		limits:  limits,
		entries: make(map[string]stateRecord),
		next:    1,
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

// load reads state.json when it exists.
func (f *fileState) load() error {
	raw, err := os.ReadFile(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("hostsvc: read state file: %w", err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	var doc stateDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("%w: %v", errStateCorrupt, err)
	}
	if doc.Format != stateFormat {
		return fmt.Errorf("%w: unsupported format %d", errStateCorrupt, doc.Format)
	}
	entries := doc.Entries
	if entries == nil {
		entries = make(map[string]stateRecord)
	}
	var (
		total  int64
		maxRev uint64
	)
	for key, record := range entries {
		if !validStateKey(key, f.limits.MaxKeyBytes, false) {
			return fmt.Errorf("%w: invalid key", errStateCorrupt)
		}
		if len(record.Value) == 0 || !jsonValid(record.Value) {
			return fmt.Errorf("%w: value of a key is not JSON", errStateCorrupt)
		}
		if int64(len(record.Value)) > int64(f.limits.MaxValueBytes) {
			return &LimitError{Name: "state.value_bytes", Max: int64(f.limits.MaxValueBytes)}
		}
		revision, err := strconv.ParseUint(record.Revision, 10, 64)
		if err != nil || revision == 0 {
			return fmt.Errorf("%w: invalid revision", errStateCorrupt)
		}
		maxRev = max(maxRev, revision)
		total += int64(len(key)) + int64(len(record.Value))
	}
	if total > f.limits.MaxTotalBytes {
		return &LimitError{Name: "state.total_bytes", Max: f.limits.MaxTotalBytes}
	}
	f.entries = entries
	f.total = total
	f.next = max(doc.NextRevision, maxRev+1)
	if f.next == 0 {
		f.next = 1
	}
	return nil
}

// Get implements StateStore.
func (f *fileState) Get(ctx context.Context, key string) (StateEntry, bool, error) {
	if err := ctx.Err(); err != nil {
		return StateEntry{}, false, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return StateEntry{}, false, os.ErrClosed
	}
	record, ok := f.entries[key]
	if !ok {
		return StateEntry{}, false, nil
	}
	return StateEntry{
		Key:      key,
		Revision: record.Revision,
		Value:    append([]byte(nil), record.Value...),
	}, true, nil
}

// Put implements StateStore. The in-memory map is rolled back when the atomic
// write fails, so a failed RPC never leaves the store ahead of the file.
func (f *fileState) Put(ctx context.Context, key string, valueJSON []byte, guard StateGuard) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !validStateKey(key, f.limits.MaxKeyBytes, false) {
		return "", errInvalidKey
	}
	if !jsonValid(valueJSON) {
		return "", errInvalidValue
	}
	if len(valueJSON) > f.limits.MaxValueBytes {
		return "", &LimitError{Name: "state.value_bytes", Max: int64(f.limits.MaxValueBytes)}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return "", os.ErrClosed
	}
	current, exists := f.entries[key]
	if guard.MustNotExist && exists {
		return "", &StateConflictError{Key: key, Current: current.Revision}
	}
	if !guard.MustNotExist && guard.ExpectedRevision != "" {
		if !exists || current.Revision != guard.ExpectedRevision {
			return "", &StateConflictError{Key: key, Current: currentRevision(current, exists)}
		}
	}
	oldValue := current.Value
	oldTotal := f.total
	oldNext := f.next
	valueCopy := append(json.RawMessage(nil), valueJSON...)
	if exists {
		f.total += int64(len(valueCopy)) - int64(len(oldValue))
	} else {
		f.total += int64(len(key)) + int64(len(valueCopy))
	}
	if f.total > f.limits.MaxTotalBytes {
		f.total = oldTotal
		return "", &LimitError{Name: "state.total_bytes", Max: f.limits.MaxTotalBytes}
	}
	revision := strconv.FormatUint(f.next, 10)
	f.entries[key] = stateRecord{Revision: revision, Value: valueCopy}
	f.next++
	if err := f.persistLocked(); err != nil {
		f.total = oldTotal
		f.next = oldNext
		if exists {
			f.entries[key] = current
		} else {
			delete(f.entries, key)
		}
		return "", err
	}
	return revision, nil
}

// Delete implements StateStore. Deleting an absent key without a guard is a
// successful no-op; with a guard it is a conflict, because the caller expected
// the key to exist.
func (f *fileState) Delete(ctx context.Context, key, expectedRevision string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validStateKey(key, f.limits.MaxKeyBytes, false) {
		return errInvalidKey
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return os.ErrClosed
	}
	current, exists := f.entries[key]
	if expectedRevision != "" {
		if !exists || current.Revision != expectedRevision {
			return &StateConflictError{Key: key, Current: currentRevision(current, exists)}
		}
	}
	if !exists {
		return nil
	}
	oldTotal := f.total
	f.total -= int64(len(key)) + int64(len(current.Value))
	delete(f.entries, key)
	if err := f.persistLocked(); err != nil {
		f.total = oldTotal
		f.entries[key] = current
		return err
	}
	return nil
}

// List implements StateStore.
func (f *fileState) List(ctx context.Context, prefix, pageToken string, pageSize int, includeValues bool) (StatePage, error) {
	if err := ctx.Err(); err != nil {
		return StatePage{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return StatePage{}, os.ErrClosed
	}
	keys := make([]string, 0, len(f.entries))
	for key := range f.entries {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	start := 0
	if pageToken != "" {
		last, err := decodePageToken(pageToken)
		if err != nil {
			return StatePage{}, err
		}
		start = sort.SearchStrings(keys, last)
		if start < len(keys) && keys[start] == last {
			start++
		}
	}
	if pageSize <= 0 {
		pageSize = 1
	}
	end := min(start+pageSize, len(keys))
	page := StatePage{Entries: make([]StateEntry, 0, end-start)}
	for _, key := range keys[start:end] {
		record := f.entries[key]
		entry := StateEntry{Key: key, Revision: record.Revision}
		if includeValues {
			entry.Value = append([]byte(nil), record.Value...)
		}
		page.Entries = append(page.Entries, entry)
	}
	if end < len(keys) {
		page.NextPageToken = encodePageToken(keys[end-1])
	}
	return page, nil
}

// Close implements io.Closer. Further calls fail; the server only closes the
// store during shutdown.
func (f *fileState) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

// persistLocked writes the whole state atomically. The caller holds f.mu.
func (f *fileState) persistLocked() error {
	doc := stateDocument{Format: stateFormat, NextRevision: f.next, Entries: f.entries}
	raw, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("hostsvc: encode state: %w", err)
	}
	if err := writeFileAtomic(f.path, raw, stateFileMode); err != nil {
		return fmt.Errorf("hostsvc: write state: %w", err)
	}
	return nil
}

// currentRevision returns the revision of an existing record, or "".
func currentRevision(record stateRecord, exists bool) string {
	if !exists {
		return ""
	}
	return record.Revision
}

// encodePageToken makes the last key of a page opaque. The token is not a
// security boundary; it only keeps plugins from depending on the store layout.
func encodePageToken(key string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(key))
}

// decodePageToken validates a token issued by encodePageToken.
func decodePageToken(token string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || !validStateKey(string(raw), DefaultMaxKeyBytes, false) {
		return "", errInvalidPageToken
	}
	return string(raw), nil
}

// errInvalidKey marks a key a StateStore receives from a caller other than the
// ABI handler.
var errInvalidKey = errors.New("hostsvc: invalid state key")

// writeFileAtomic writes data to path via a temporary file in the same
// directory: write, chmod, fsync, rename, fsync the directory. A crash leaves
// either the old or the new file, never a partial one.
func writeFileAtomic(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	discard := func() { _ = os.Remove(name) }
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		discard()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		discard()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		discard()
		return err
	}
	if err := tmp.Close(); err != nil {
		discard()
		return err
	}
	if err := os.Rename(name, path); err != nil {
		discard()
		return err
	}
	if dirHandle, err := os.Open(dir); err == nil {
		_ = dirHandle.Sync()
		_ = dirHandle.Close()
	}
	return nil
}
