// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/qwq-panel/qwq/sdk/abi"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// DefaultGracePeriod is used when Deactivate or Stop does not set
// grace_period_ms. It bounds how long in-flight calls and background work may
// take to finish.
const DefaultGracePeriod = 10 * time.Second

// DefaultReleaseGracePeriod bounds the waits of ReleaseInstance, which has no
// grace_period_ms field.
const DefaultReleaseGracePeriod = 5 * time.Second

// Options configures [Serve].
type Options struct {
	// Plugin is the author implementation. Required.
	Plugin Plugin
	// Manifest is the raw manifest.json embedded in the plugin package. It is
	// parsed with sdk/manifest.Parse and must match the operations the plugin
	// registers. Required.
	Manifest []byte
	// Registrar is the gRPC server (or any grpc.ServiceRegistrar) that the
	// PluginService is registered on. The transport owns it. Required.
	Registrar grpc.ServiceRegistrar
	// Host is the Agent's Host Service connection for this plugin. It may be
	// nil in development; host calls then fail with ErrNoHost.
	Host grpc.ClientConnInterface
	// Logger receives structured logs. The default writes JSON to stderr.
	Logger *slog.Logger
	// DefaultGracePeriod overrides DefaultGracePeriod when > 0.
	DefaultGracePeriod time.Duration
	// ReleaseGracePeriod overrides DefaultReleaseGracePeriod when > 0.
	ReleaseGracePeriod time.Duration
	// CrashOnPanic disables panic recovery around plugin code, for authors who
	// prefer a dead process over a recovered one. The default recovers: an
	// operation answers INTERNAL, a lifecycle hook or tracked goroutine fails its
	// instance, and the other instances of the process keep serving.
	CrashOnPanic bool
}

// Serve validates the embedded manifest, builds the descriptor derived from it
// and registers the PluginService implementation on opts.Registrar. It does not
// listen, accept connections, verify peer credentials or own the process
// lifetime; that is the transport's job, implemented by [ServeSystemd] for the
// systemd socket-activation path selected in ADR-0003.
func Serve(ctx context.Context, opts Options) (*Server, error) {
	if opts.Plugin == nil {
		return nil, errors.New("pluginsdk: Options.Plugin is required")
	}
	if opts.Registrar == nil {
		return nil, errors.New("pluginsdk: Options.Registrar is required")
	}
	if len(opts.Manifest) == 0 {
		return nil, errors.New("pluginsdk: Options.Manifest is required")
	}
	m, err := manifest.Parse(opts.Manifest)
	if err != nil {
		return nil, fmt.Errorf("pluginsdk: invalid manifest: %w", err)
	}
	// The SDK implements ABI abi.Major.abi.Minor; a manifest that requires a
	// newer minor asks for RPCs or semantics this SDK does not have.
	if m.ABI.Major != abi.Major || m.ABI.MinimumMinor > abi.Minor {
		return nil, fmt.Errorf("pluginsdk: manifest requires ABI %d.%d, this SDK implements %d.%d",
			m.ABI.Major, m.ABI.MinimumMinor, abi.Major, abi.Minor)
	}
	desc, err := buildDescriptor(m)
	if err != nil {
		return nil, fmt.Errorf("pluginsdk: invalid manifest: %w", err)
	}
	mem, err := MemoryLimitFromEnv()
	if err != nil {
		return nil, fmt.Errorf("pluginsdk: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	log := opts.Logger
	if log == nil {
		log = defaultLogger()
	}
	log = log.With(slog.String("plugin", m.ID))
	grace := opts.DefaultGracePeriod
	if grace <= 0 {
		grace = DefaultGracePeriod
	}
	relGrace := opts.ReleaseGracePeriod
	if relGrace <= 0 {
		relGrace = DefaultReleaseGracePeriod
	}
	s := &Server{
		plugin:     opts.Plugin,
		manifest:   m,
		descriptor: desc,
		hostConn:   opts.Host,
		log:        log,
		baseCtx:    ctx,
		grace:      grace,
		relGrace:   relGrace,
		memory:     mem,
		instances:  map[string]*instance{},

		crashOnPanic: opts.CrashOnPanic,
	}
	s.checkMemoryLimit()

	platformv1.RegisterPluginServiceServer(opts.Registrar, s)
	log.Info("plugin serving",
		slog.String("version", m.Version),
		slog.Uint64("abi_major", uint64(m.ABI.Major)),
		slog.Uint64("abi_minimum_minor", uint64(m.ABI.MinimumMinor)))
	return s, nil
}

// checkMemoryLimit warns when GOMEMLIMIT is absent or above the manifest's
// budget. A value above resources.memory_max_mb defeats the OOM order from
// ARCH §6.3: the kernel should kill the plugin before the host.
func (s *Server) checkMemoryLimit() {
	maxBytes := s.manifest.Resources.MemoryMaxMB << 20
	switch {
	case !s.memory.Set:
		s.log.Warn("GOMEMLIMIT is not set; the Go runtime has no soft memory limit",
			slog.Int64("memory_max_mb", s.manifest.Resources.MemoryMaxMB))
	case s.memory.Bytes > maxBytes:
		s.log.Warn("GOMEMLIMIT is above resources.memory_max_mb",
			slog.Int64("gomemlimit_bytes", s.memory.Bytes), slog.Int64("memory_max_mb", s.manifest.Resources.MemoryMaxMB))
	}
}

// MemoryLimit returns the validated GOMEMLIMIT value.
func (s *Server) MemoryLimit() MemoryLimit { return s.memory }

// Descriptor returns a copy of the descriptor derived from the manifest.
func (s *Server) Descriptor() *platformv1.PluginDescriptor {
	return proto.Clone(s.descriptor).(*platformv1.PluginDescriptor)
}

// Close releases every instance and their background goroutines. The transport
// calls it during shutdown; it is idempotent.
func (s *Server) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	instances := make([]*instance, 0, len(s.instances))
	for id, in := range s.instances {
		instances = append(instances, in)
		delete(s.instances, id)
	}
	s.mu.Unlock()

	for _, in := range instances {
		if !in.markReleased() {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), s.relGrace)
		s.releaseInstance(ctx, in)
		cancel()
	}
}

// releaseInstance cancels background work, waits for in-flight calls and calls
// the author's Releaser. The caller has already removed the instance from the
// table and marked it released, and ctx carries any call metadata.
func (s *Server) releaseInstance(ctx context.Context, in *instance) {
	// A wedged hook must not keep the instance alive: past the grace period the
	// release goes on without the lifecycle lock.
	if unlock, err := in.acquireLife(ctx); err != nil {
		in.log.Warn("a lifecycle call was still running at release")
	} else {
		defer unlock()
	}
	if !in.stopBackground(ctx, s.relGrace) {
		in.log.Warn("background work did not stop before release")
	}
	if !in.waitIdle(ctx, s.relGrace) {
		in.log.Warn("in-flight requests were still running at release")
	}
	if re, ok := in.author.(Releaser); ok {
		// Host-side cleanup does not depend on this hook; log and finish.
		if err := safelyRun(in, "release", func() error { return re.Release(ctx) }); err != nil {
			in.log.Error("release hook failed", slog.String("error", err.Error()))
		}
	}
	in.log.Info("instance released")
}
