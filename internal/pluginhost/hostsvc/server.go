// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/netlimit"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ============================================================================
//  资源上限（PLG-08）
// ----------------------------------------------------------------------------
//  插件是不可信代码。gRPC 在调用 handler 前就把整条消息读进内存，所以单靠
//  每连接的 MaxConcurrentStreams 挡不住"多开连接"：必须同时限制连接数与
//  每实例的在途调用数。最坏在途内存约 (maxConnections*maxConcurrentStreams)
//  条消息被读入，但只有 maxInflight 条能进入 handler。
// ============================================================================

const (
	// maxConnections bounds the simultaneously open connections of one
	// plugin instance; further dials wait in the kernel backlog.
	maxConnections = 2
	// maxConcurrentStreams bounds the in-flight RPCs of one connection.
	maxConcurrentStreams = 16
	// maxInflight bounds the RPCs of one instance running in handlers across
	// all its connections. A call over the budget fails at once with
	// RESOURCE_EXHAUSTED instead of queueing.
	maxInflight = 16
	// connectionTimeout bounds the connection handshake.
	connectionTimeout = 5 * time.Second
	// keepaliveMinTime is the shortest client ping interval tolerated.
	keepaliveMinTime = 10 * time.Second
)

// Server serves the six Host services of one plugin instance. It owns the
// listener, the gRPC server and the built-in state store, and it stops the
// event spool and in-flight streams on Close.
type Server struct {
	cfg   Config
	lim   Limits
	log   *slog.Logger
	clock clock.Clock
	store StateStore
	// ownsStore reports that the built-in file state was created by New and is
	// therefore closed on shutdown. A caller-provided StateStore belongs to
	// the caller.
	ownsStore bool

	state        *stateService
	events       *eventsService
	config       *configService
	secrets      *secretsService
	audit        *auditService
	invoke       *invokeService
	capabilities *capabilityGate

	auditQuota *auditQuota
	spool      *publishSpool
	// inflight holds one token per RPC running in a handler.
	inflight chan struct{}

	baseCtx    context.Context
	baseCancel context.CancelFunc

	gs *grpc.Server

	mu      sync.Mutex
	ln      net.Listener
	serving bool

	closeOnce sync.Once
	closed    chan struct{}
	closeErr  error
}

// New builds a Server. It validates the configuration, loads the built-in
// state store when Config.State is nil, and starts the bounded event spool.
// The socket itself is created by Serve; New performs no network I/O.
//
// A Server must be closed even when Serve was never called, because the event
// spool has a worker goroutine.
func New(cfg Config) (*Server, error) {
	cfg.GrantedCapabilities = cloneCapabilities(cfg.GrantedCapabilities)
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	limits := cfg.Limits.withDefaults()
	if err := limits.validate(); err != nil {
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	logger = logger.With("plugin_id", cfg.PluginID, "instance_id", cfg.InstanceID)
	clk := cfg.Clock
	if clk == nil {
		clk = clock.System{}
	}
	store := cfg.State
	ownsStore := false
	if store == nil {
		fileStore, err := openFileState(cfg.StateDir, limits)
		if err != nil {
			return nil, err
		}
		store = fileStore
		ownsStore = true
	}

	baseCtx, baseCancel := context.WithCancel(context.Background())
	s := &Server{
		cfg:        cfg,
		lim:        limits,
		log:        logger,
		clock:      clk,
		store:      store,
		ownsStore:  ownsStore,
		baseCtx:    baseCtx,
		baseCancel: baseCancel,
		closed:     make(chan struct{}),
		inflight:   make(chan struct{}, maxInflight),
	}
	s.auditQuota = newAuditQuota(limits.AuditQueue, limits.AuditPerMinute)
	s.state = &stateService{s: s}
	s.config = &configService{s: s}
	s.audit = &auditService{s: s}
	s.secrets = newSecretsService(s)
	s.invoke = &invokeService{s: s}
	s.capabilities = newCapabilityGate(cfg.GrantedCapabilities, limits)
	if cfg.Events != nil {
		s.spool = newPublishSpool(cfg.Events, limits.EventSpool)
	}
	s.events = newEventsService(s)

	options := []grpc.ServerOption{
		grpc.Creds(&peerCredentials{verify: cfg.Peer}),
		grpc.MaxRecvMsgSize(limits.MaxRequestBytes),
		grpc.MaxSendMsgSize(limits.MaxRequestBytes),
		grpc.MaxConcurrentStreams(maxConcurrentStreams),
		grpc.ConnectionTimeout(connectionTimeout),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: keepaliveMinTime}),
		grpc.UnaryInterceptor(s.unaryInterceptor),
		grpc.StreamInterceptor(s.streamInterceptor),
	}
	s.gs = grpc.NewServer(options...)
	platformv1.RegisterHostStateServiceServer(s.gs, s.state)
	platformv1.RegisterHostEventsServiceServer(s.gs, s.events)
	platformv1.RegisterHostConfigServiceServer(s.gs, s.config)
	platformv1.RegisterHostSecretsServiceServer(s.gs, s.secrets)
	platformv1.RegisterHostAuditServiceServer(s.gs, s.audit)
	platformv1.RegisterHostInvokeServiceServer(s.gs, s.invoke)
	s.registerCapabilityServices()
	return s, nil
}

// Serve creates the socket and serves until ctx is done, Close is called, or
// the listener fails. It returns nil for a clean shutdown.
func (s *Server) Serve(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ln, err := s.listen()
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.serving {
		s.mu.Unlock()
		_ = ln.Close()
		return errors.New("hostsvc: server is already serving")
	}
	s.serving = true
	s.ln = ln
	s.mu.Unlock()

	serveErr := make(chan error, 1)
	go func() { serveErr <- s.gs.Serve(ln) }()

	select {
	case <-ctx.Done():
		// The caller's context ending is the normal shutdown path.
		return s.Close()
	case <-s.closed:
		return nil
	case err := <-serveErr:
		if err == nil || errors.Is(err, grpc.ErrServerStopped) {
			return s.Close()
		}
		closeErr := s.Close()
		if closeErr != nil {
			return fmt.Errorf("hostsvc: serve: %w (close: %v)", err, closeErr)
		}
		return fmt.Errorf("hostsvc: serve: %w", err)
	}
}

// Close stops the server: in-flight streams are canceled, the listener and
// socket file are removed, queued publishes fail and the spool worker exits.
// Close is idempotent and safe to call concurrently with Serve.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		// Cancel the handler contexts first so long-lived subscriptions end and
		// GracefulStop can complete.
		s.baseCancel()
		done := make(chan struct{})
		go func() {
			s.gs.GracefulStop()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(s.lim.ShutdownTimeout):
			s.gs.Stop()
			<-done
		}
		s.mu.Lock()
		ln := s.ln
		s.ln = nil
		s.serving = false
		s.mu.Unlock()
		if ln != nil {
			_ = ln.Close()
		}
		if s.spool != nil {
			s.spool.close()
		}
		if s.ownsStore {
			if closer, ok := s.store.(io.Closer); ok {
				if err := closer.Close(); err != nil {
					s.closeErr = err
				}
			}
		}
		close(s.closed)
	})
	return s.closeErr
}

// Ingest hands one host-assigned event to the SubscribeEvents streams of this
// instance. The controller calls it when the node journal dispatches an event
// for the plugin; the event must carry its journal sequence (the value a
// subscriber acks) and a full subject. Ingest takes ownership of ev and the
// caller must not modify it afterwards.
//
// Ingest is not part of the ABI: it is the host-side seam between the journal
// and the plugin subscription, and it lets this package stay independent of
// internal/events and internal/storage.
func (s *Server) Ingest(ev *platformv1.Event) error {
	return s.events.ingest(ev)
}

// listen verifies the socket directory and creates the socket (0660). A stale
// socket left by a crash is removed after a probe proves no server answers it;
// a live or non-socket path is an error instead of being clobbered.
func (s *Server) listen() (net.Listener, error) {
	dir := filepath.Dir(s.cfg.SocketPath)
	if err := checkSocketDir(dir, s.cfg.CreateSocketDir); err != nil {
		return nil, fmt.Errorf("hostsvc: socket directory: %w", err)
	}
	if err := removeStaleSocket(s.cfg.SocketPath); err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", s.cfg.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("hostsvc: listen on %s: %w", s.cfg.SocketPath, err)
	}
	if err := os.Chmod(s.cfg.SocketPath, 0o660); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("hostsvc: chmod socket: %w", err)
	}
	s.log.Info("host service listening", "socket", s.cfg.SocketPath)
	return netlimit.LimitListener(ln, maxConnections), nil
}

// removeStaleSocket removes a socket file that no process is listening on. It
// refuses to touch a regular file: that would hide a misconfiguration.
func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("hostsvc: inspect socket path: %w", err)
	}
	if info.Mode()&fs.ModeSocket == 0 {
		return fmt.Errorf("hostsvc: %s exists and is not a Unix socket", path)
	}
	conn, dialErr := net.DialTimeout("unix", path, 200*time.Millisecond)
	if dialErr == nil {
		_ = conn.Close()
		return fmt.Errorf("hostsvc: socket %s is already in use", path)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("hostsvc: remove stale socket: %w", err)
	}
	return nil
}

// checkToken 在配置了单槽或双槽回调时逐次核验 token；双槽也不能代替 peer
// 先验。完整遍历最多两个 SHA-256，插件出示的明文不进入日志。
func (s *Server) checkToken(ctx context.Context) error {
	if s.cfg.TokenDigest == nil && s.cfg.TokenDigests == nil {
		return nil
	}
	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get(pluginsdk.HostTokenMetadataKey)
	if len(values) != 1 {
		return status.Error(codes.Unauthenticated, "the call carries no valid plugin token")
	}
	var digests [][]byte
	var err error
	if s.cfg.TokenDigests != nil {
		digests, err = s.cfg.TokenDigests(ctx)
	} else {
		var digest []byte
		digest, err = s.cfg.TokenDigest(ctx)
		digests = [][]byte{digest}
	}
	if err != nil {
		s.log.Warn("the plugin token digest is not available", "err", err)
		return status.Error(codes.Unauthenticated, "the call carries no valid plugin token")
	}
	got := sha256.Sum256([]byte(values[0]))
	if len(digests) == 0 || len(digests) > 2 {
		return status.Error(codes.Unauthenticated, "the call carries no valid plugin token")
	}
	matched, valid := 0, true
	for _, digest := range digests {
		valid = valid && len(digest) == sha256.Size
		matched |= subtle.ConstantTimeCompare(got[:], digest)
	}
	if !valid || matched != 1 {
		return status.Error(codes.Unauthenticated, "the call carries no valid plugin token")
	}
	return nil
}

// unaryInterceptor verifies the connection peer, installs the peer identity in
// the context, bounds the deadline and cancels the handler when the server
// closes.
func (s *Server) unaryInterceptor(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	ctx, cleanup, err := s.prepareCall(ctx, false)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	return handler(ctx, req)
}

// streamInterceptor is the streaming counterpart of unaryInterceptor.
func (s *Server) streamInterceptor(srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	ctx, cleanup, err := s.prepareCall(stream.Context(), true)
	if err != nil {
		return err
	}
	defer cleanup()
	return handler(srv, &serverStream{ServerStream: stream, ctx: ctx})
}

// prepareCall enforces kernel-verified peer identity and returns the context
// handlers see. It fails closed: an RPC whose connection has no peerAuthInfo
// (which should be impossible while peerCredentials is installed) is
// PERMISSION_DENIED rather than treated as an anonymous caller.
func (s *Server) prepareCall(ctx context.Context, stream bool) (context.Context, context.CancelFunc, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return nil, nil, status.Error(codes.PermissionDenied, "the connection has no verified peer")
	}
	auth, ok := p.AuthInfo.(*peerAuthInfo)
	if !ok {
		return nil, nil, status.Error(codes.PermissionDenied, "the connection has no verified peer")
	}
	if err := s.checkToken(ctx); err != nil {
		return nil, nil, err
	}
	select {
	case s.inflight <- struct{}{}:
	default:
		return nil, nil, status.Error(codes.ResourceExhausted, "too many concurrent host calls")
	}
	ctx = withPeer(ctx, auth.info)

	base, cancelBase := context.WithCancel(ctx)
	stop := context.AfterFunc(s.baseCtx, cancelBase)
	timeout := s.lim.RequestTimeout
	if stream {
		timeout = s.lim.StreamTimeout
	}
	var cancelTimeout context.CancelFunc = func() {}
	if deadline, hasDeadline := base.Deadline(); !hasDeadline || time.Until(deadline) > timeout {
		base, cancelTimeout = context.WithTimeout(base, timeout)
	}
	return base, func() {
		cancelTimeout()
		stop()
		cancelBase()
		<-s.inflight
	}, nil
}

// serverStream overrides the context of a server stream with the one prepared
// by the interceptor.
type serverStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the prepared context.
func (ss *serverStream) Context() context.Context { return ss.ctx }
