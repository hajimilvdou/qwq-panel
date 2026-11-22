// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/diskfree"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// DefaultPluginUploadTTL is how long an uploaded package may be installed.
const DefaultPluginUploadTTL = 15 * time.Minute

// pluginUploadField is the multipart field a package must be sent in.
const pluginUploadField = "package"

const (
	// maxPendingUploads bounds staged and in-flight packages on the whole host
	// so an authenticated caller cannot fill the staging filesystem.
	maxPendingUploads = 32
	// maxUploadsPerPrincipal bounds staged and in-flight packages per
	// principal (GW-07): one account can never occupy the whole staging quota.
	maxUploadsPerPrincipal = 4
	// uploadDiskReserve is the free space kept beside one package: staging
	// must not fill the filesystem the host's database and journals live on.
	uploadDiskReserve = 256 << 20
	// maxUploadParts bounds the multipart fields of one upload request.
	maxUploadParts = 16
)

// pluginUploadIDPattern is the grammar of an opaque upload id. It is checked
// before any map lookup, so a request can never smuggle a path: the store only
// ever returns a file it created itself.
var pluginUploadIDPattern = regexp.MustCompile(`^upl_[0-9a-f]{32}$`)

// PluginUpload is one staged package. Path is deliberately unexported: an HTTP
// caller only ever sees the id, never a filesystem location.
type PluginUpload struct {
	ID        string
	Size      int64
	SHA256    string
	ExpiresAt time.Time

	path string
	// principal is who staged the package; it backs the per-principal quota.
	principal string
}

// PluginUploads stages plugin packages in a private directory until they are
// installed or expire. Files are created with mode 0600 and random names; the
// original multipart filename is never used.
type PluginUploads struct {
	dir      string
	ttl      time.Duration
	maxBytes int64
	clock    clock.Clock

	// statfs reports the free bytes of the staging filesystem; tests replace
	// it. A statfs failure skips the space check instead of blocking uploads.
	statfs func(dir string) (uint64, error)

	mu    sync.Mutex
	items map[string]*PluginUpload
	// reserved counts uploads being received right now, in total and per
	// principal, so the caps cover in-flight requests and not only registered
	// uploads (GW-07).
	reserved   int
	reservedBy map[string]int
}

// NewPluginUploads opens the staging directory used for package uploads. dir
// must be absolute; it is created with mode 0700 when missing. A non-positive
// ttl uses DefaultPluginUploadTTL.
func NewPluginUploads(dir string, ttl time.Duration, clk clock.Clock) (*PluginUploads, error) {
	if dir == "" || !filepath.IsAbs(dir) {
		return nil, errors.New("api: the plugin upload directory must be an absolute path")
	}
	if ttl <= 0 {
		ttl = DefaultPluginUploadTTL
	}
	if clk == nil {
		clk = clock.System{}
	}
	dir = filepath.Clean(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("api: create the plugin upload directory: %w", err)
	}
	// Upload ids are only in memory: a file left by a previous process can
	// never be resolved again. Remove its private staging files at startup so
	// a crash cannot accumulate package bytes forever.
	if entries, err := os.ReadDir(dir); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasPrefix(name, "upload-") || !strings.HasSuffix(name, ".pkg") {
				continue
			}
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
	return &PluginUploads{
		dir:        dir,
		ttl:        ttl,
		maxBytes:   gateway.MaxPackageBytes,
		clock:      clk,
		statfs:     diskfree.Bytes,
		items:      make(map[string]*PluginUpload),
		reservedBy: make(map[string]int),
	}, nil
}

// Receive streams the `package` part of a multipart/form-data request into a
// private staging file and returns the created upload. Nothing else in the
// request is trusted: the filename and any other part are ignored. principal
// identifies the uploader for the per-principal quota.
func (s *PluginUploads) Receive(ctx context.Context, r *http.Request, principal string) (PluginUpload, error) {
	if err := ctx.Err(); err != nil {
		return PluginUpload{}, problem.From(err)
	}
	// Take the pending-upload slot before anything is written, so N concurrent
	// requests cannot stage more than the caps allow (GW-07).
	release, err := s.reserve(principal)
	if err != nil {
		return PluginUpload{}, err
	}
	defer release()
	mr, err := r.MultipartReader()
	if err != nil {
		return PluginUpload{}, multipartProblem()
	}
	var (
		found    bool
		received PluginUpload
		parts    int
	)
	for {
		if err := ctx.Err(); err != nil {
			_ = s.removeFile(received.path)
			return PluginUpload{}, problem.From(err)
		}
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			_ = s.removeFile(received.path)
			return PluginUpload{}, uploadReadProblem(err)
		}
		parts++
		if parts > maxUploadParts {
			_ = part.Close()
			_ = s.removeFile(received.path)
			return PluginUpload{}, problem.Validation(problem.Violation{
				Pointer: "/package", Code: "TOO_MANY_PARTS",
				Message: fmt.Sprintf("A package upload may have at most %d parts.", maxUploadParts),
			})
		}
		if part.FormName() != pluginUploadField {
			_ = part.Close()
			continue
		}
		if found {
			_ = part.Close()
			_ = s.removeFile(received.path)
			return PluginUpload{}, problem.Validation(problem.Violation{
				Pointer: "/package", Code: "DUPLICATE",
				Message: "The request has more than one package part.",
			})
		}
		found = true
		received, err = s.store(part, principal)
		_ = part.Close()
		if err != nil {
			return PluginUpload{}, err
		}
		// Keep scanning: a second package part is ambiguous even when the
		// first one was already written, and other fields are drained.
	}
	if !found {
		return PluginUpload{}, problem.Validation(problem.Violation{
			Pointer: "/package", Code: "REQUIRED",
			Message: "The multipart request needs one file part named package.",
		})
	}
	if err := s.register(&received); err != nil {
		_ = s.removeFile(received.path)
		return PluginUpload{}, err
	}
	return received, nil
}

// store copies one part to a 0600 file, hashing while it writes. The
// filesystem must have room for the whole package plus the host's reserve
// before a single byte is written (GW-07).
func (s *PluginUploads) store(part io.Reader, principal string) (PluginUpload, error) {
	if avail, err := s.statfs(s.dir); err == nil && avail < uint64(s.maxBytes)+uploadDiskReserve {
		return PluginUpload{}, &problem.Error{
			Code:   problem.InsufficientStorage,
			Detail: "The staging filesystem does not have room for another plugin package.",
		}
	}
	f, err := os.CreateTemp(s.dir, "upload-*.pkg")
	if err != nil {
		return PluginUpload{}, &problem.Error{
			Code:   problem.Internal,
			Detail: "The plugin package could not be staged.",
			Cause:  err,
		}
	}
	path := f.Name()
	discard := func() {
		_ = f.Close()
		_ = s.removeFile(path)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(part, s.maxBytes+1))
	if err != nil {
		discard()
		return PluginUpload{}, uploadReadProblem(err)
	}
	switch {
	case n > s.maxBytes:
		discard()
		return PluginUpload{}, packageTooLarge(s.maxBytes)
	case n == 0:
		discard()
		return PluginUpload{}, problem.Validation(problem.Violation{
			Pointer: "/package", Code: "EMPTY",
			Message: "The package part is empty.",
		})
	}
	if err := f.Sync(); err != nil {
		discard()
		return PluginUpload{}, &problem.Error{
			Code:   problem.Internal,
			Detail: "The plugin package could not be staged.",
			Cause:  err,
		}
	}
	if err := f.Close(); err != nil {
		_ = s.removeFile(path)
		return PluginUpload{}, &problem.Error{
			Code:   problem.Internal,
			Detail: "The plugin package could not be staged.",
			Cause:  err,
		}
	}
	// os.CreateTemp already uses 0600; set it again so a future change of the
	// standard library default cannot widen the permissions silently.
	if err := os.Chmod(path, 0o600); err != nil {
		_ = s.removeFile(path)
		return PluginUpload{}, &problem.Error{
			Code:   problem.Internal,
			Detail: "The plugin package could not be staged.",
			Cause:  err,
		}
	}
	return PluginUpload{
		Size:      n,
		SHA256:    hex.EncodeToString(h.Sum(nil)),
		path:      path,
		principal: principal,
	}, nil
}

// register adds a staged upload to the in-memory index, evicting expired ones
// first. The id is random and never derived from request data. The caps were
// already enforced by reserve, which counted this upload as in flight.
func (s *PluginUploads) register(u *PluginUpload) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now().UTC()
	s.sweepLocked(now)
	for {
		id, err := newPluginUploadID()
		if err != nil {
			return &problem.Error{
				Code:   problem.Internal,
				Detail: "An upload id could not be generated.",
				Cause:  err,
			}
		}
		if _, exists := s.items[id]; exists {
			continue
		}
		u.ID = id
		u.ExpiresAt = now.Add(s.ttl)
		stored := *u
		s.items[id] = &stored
		return nil
	}
}

// Resolve returns the staged package named by id. An unknown, malformed or
// expired id reports false; the caller answers NOT_FOUND without revealing
// which of the three happened.
func (s *PluginUploads) Resolve(id string) (PluginUpload, bool) {
	if !pluginUploadIDPattern.MatchString(id) {
		return PluginUpload{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.items[id]
	if !ok {
		return PluginUpload{}, false
	}
	if !u.ExpiresAt.After(s.clock.Now().UTC()) {
		s.removeLocked(id, u)
		return PluginUpload{}, false
	}
	return *u, true
}

// filePath returns the private file of an upload. It is unexported so the path
// never crosses the package boundary.
func (s *PluginUploads) filePath(id string) (string, bool) {
	u, ok := s.Resolve(id)
	if !ok {
		return "", false
	}
	return u.path, true
}

// Remove drops an upload and its file. It is called after a successful install
// and is idempotent.
func (s *PluginUploads) Remove(id string) error {
	s.mu.Lock()
	u, ok := s.items[id]
	if !ok {
		s.mu.Unlock()
		return nil
	}
	delete(s.items, id)
	s.mu.Unlock()
	return s.removeFile(u.path)
}

// Sweep removes every expired upload and returns how many were removed. It is
// safe to call while other requests receive or resolve uploads.
func (s *PluginUploads) Sweep() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sweepLocked(s.clock.Now().UTC())
}

// Run sweeps expired uploads every interval until ctx ends. The host starts it
// once: without it, a staged package was only removed when the next request
// happened to look (GW-07).
func (s *PluginUploads) Run(ctx context.Context, every time.Duration) {
	if s == nil {
		return
	}
	if every <= 0 {
		every = time.Minute
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.Sweep()
		}
	}
}

// reserve takes one pending-upload slot for principal. Both caps count uploads
// still being received and uploads already staged. The returned release runs
// when the request ends; it is idempotent.
func (s *PluginUploads) reserve(principal string) (func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.clock.Now().UTC())
	if len(s.items)+s.reserved >= maxPendingUploads {
		return nil, problem.New(problem.Unavailable,
			"Too many plugin packages are waiting to be installed; retry after one expires.")
	}
	if s.reservedBy[principal]+s.stagedByPrincipalLocked(principal) >= maxUploadsPerPrincipal {
		return nil, problem.New(problem.RateLimited,
			"At most %d plugin packages may be staged per account; install or wait out the pending ones.",
			maxUploadsPerPrincipal)
	}
	s.reserved++
	s.reservedBy[principal]++
	released := false
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if released {
			return
		}
		released = true
		s.reserved--
		if s.reservedBy[principal] <= 1 {
			delete(s.reservedBy, principal)
		} else {
			s.reservedBy[principal]--
		}
	}, nil
}

// stagedByPrincipalLocked counts the registered uploads of principal. The
// caller holds s.mu.
func (s *PluginUploads) stagedByPrincipalLocked(principal string) int {
	n := 0
	for _, u := range s.items {
		if u.principal == principal {
			n++
		}
	}
	return n
}

// Count returns how many uploads are currently staged (for diagnostics/tests).
func (s *PluginUploads) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.clock.Now().UTC())
	return len(s.items)
}

func (s *PluginUploads) sweepLocked(now time.Time) int {
	removed := 0
	for id, u := range s.items {
		if u.ExpiresAt.After(now) {
			continue
		}
		s.removeLocked(id, u)
		removed++
	}
	return removed
}

func (s *PluginUploads) removeLocked(id string, u *PluginUpload) {
	delete(s.items, id)
	// The file is private and the entry is gone; a leftover cannot be installed
	// because no id maps to it. Startup cleanup removes it.
	_ = s.removeFile(u.path)
}

// removeFile deletes a path only when it is a direct child of the staging
// directory. Every path the store records was created there with CreateTemp.
func (s *PluginUploads) removeFile(path string) error {
	if path == "" {
		return nil
	}
	if filepath.Dir(filepath.Clean(path)) != s.dir {
		return fmt.Errorf("api: refusing to remove a path outside the upload directory")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// newPluginUploadID returns 128 bits of entropy in a fixed, path-free form.
func newPluginUploadID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "upl_" + hex.EncodeToString(raw[:]), nil
}

// multipartProblem reports a body that is not multipart/form-data.
func multipartProblem() *problem.Error {
	return problem.Validation(problem.Violation{
		Pointer: "/package", Code: "MULTIPART_REQUIRED",
		Message: "The request body must be multipart/form-data with one file part named package.",
	})
}

// uploadReadProblem maps a read failure to the documented problem. A body over
// the route limit is PAYLOAD_TOO_LARGE even when the gateway sees it only while
// the handler streams it.
func uploadReadProblem(err error) error {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		limit := maxErr.Limit
		if limit <= 0 {
			limit = gateway.MaxPackageBytes
		}
		return packageTooLarge(limit)
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return problem.New(problem.Timeout, "The package upload did not finish before the read deadline.")
	}
	return problem.Validation(problem.Violation{
		Pointer: "/package", Code: "MALFORMED",
		Message: "The multipart package could not be read.",
	})
}

// packageTooLarge is the 413 of the package limit.
func packageTooLarge(max int64) *problem.Error {
	e := problem.New(problem.PayloadTooLarge,
		"The plugin package exceeds max_package_bytes (%d).", max)
	e.Limit = &problem.Limit{Name: "max_package_bytes", Max: max}
	return e
}
