// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/qwq-panel/qwq/internal/buildinfo"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/install"
	"github.com/qwq-panel/qwq/internal/sandbox"
)

const (
	// maxConcurrentRequests bounds how many requests one activation handles at
	// the same time. Socket activation normally serves a single request, so
	// this is the ceiling rather than a target.
	maxConcurrentRequests = 4

	// requestTimeout bounds one request from the first byte to the response.
	requestTimeout = 30 * time.Second

	// maxCredentialBase64 bounds the decoded token. sandbox.MinTokenLen /
	// MaxTokenLen apply after decoding; the base64 form is at most 4/3 of it.
	maxCredentialBase64 = 4 << 10

	// maxVersionLen bounds the version path component accepted in a remove
	// request.
	maxVersionLen = 128

	// defaultPluginsRoot is where install.Staged publishes a package. It must
	// match controller.DefaultPluginsDir (cmd/qwq-privileged does not import the
	// controller).
	defaultPluginsRoot = "/var/lib/qwq-plugins"

	// defaultStagingRoot is the qwq-writable staging root. It must match
	// controller.DefaultStagingRoot; it is outside the plugins root because the
	// controller must not be able to write a published version directory.
	defaultStagingRoot = "/var/lib/qwq/staging"

	// maxTreeNameLen is the Linux NAME_MAX, the longest single path component
	// accepted in a staged tree.
	maxTreeNameLen = 255
)

// versionPattern is the version path component of a remove request. It is only
// used to reject separators and dot segments before the exact expected path is
// compared, so it stays deliberately narrow.
var versionPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]*$`)

// userPattern is the same conservative Linux user name sandbox uses.
var userPattern = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

// helperConfig is the root-controlled configuration. Nothing in a request can
// change these paths: the helper validates every request against them.
type helperConfig struct {
	// Socket is the listening Unix socket.
	Socket string
	// UnitDir is the systemd unit directory (/etc/systemd/system).
	UnitDir string
	// TmpfilesDir is the tmpfiles.d directory (/etc/tmpfiles.d).
	TmpfilesDir string
	// RuntimeBase is systemd's %t for system services (/run).
	RuntimeBase string
	// CredDir is the persistent token directory
	// (/var/lib/qwq-privileged/creds). Empty uses sandbox.DefaultCredDir.
	CredDir string
	// PluginsRoot is the immutable plugin version root
	// (/var/lib/qwq-plugins). It and every ancestor must be root-owned and
	// not group/world writable; see sandbox.TrustPolicy.
	PluginsRoot string
	// DataRoot 与 PrivateDataRoot 是逻辑与 DynamicUser 真实持久根。
	// 只由 root 配置提供，请求只能选择根下的当前插件 ID。
	DataRoot        string
	PrivateDataRoot string
	// StagingRoot is the qwq-writable staging root (/var/lib/qwq/staging).
	// The helper only reads it; publish never writes below it.
	StagingRoot string
	// AgentUser owns the plugin socket; it is the only agent user a request
	// may name.
	AgentUser string
	// SocketGroup owns the manually created socket; root runs the helper, so
	// only this group is granted the 0660 socket.
	SocketGroup string
	// Version is reported by ping.
	Version string
	// Trust is the ancestry policy of the plugins root and the runtime tree.
	// The zero value is the production policy; only tests relax it.
	Trust sandbox.TrustPolicy
}

// defaultHelperConfig returns the production configuration.
func defaultHelperConfig() helperConfig {
	return helperConfig{
		Socket:          sandbox.DefaultPrivilegedSocket,
		UnitDir:         sandbox.DefaultUnitDir,
		TmpfilesDir:     sandbox.DefaultTmpfilesDir,
		RuntimeBase:     sandbox.DefaultRuntimeBase,
		PluginsRoot:     defaultPluginsRoot,
		DataRoot:        sandbox.DefaultPluginDataRoot,
		PrivateDataRoot: sandbox.DefaultPrivatePluginDataRoot,
		StagingRoot:     defaultStagingRoot,
		AgentUser:       sandbox.DefaultAgentUser,
		SocketGroup:     sandbox.DefaultAgentUser,
		Version:         buildinfo.Read().Version, // one link-time variable for every binary (DEP-03)
	}
}

// helperServer serves the requests. It owns the root-only half of plugin
// installation and nothing else: it does not start, stop or supervise a plugin,
// and it never talks to one.
type helperServer struct {
	cfg       helperConfig
	installer sandbox.Installer
	runner    sandbox.Runner
	logger    *slog.Logger
	// generation 是独立 typed 接缝；本批生产不装配，缺失时必须拒绝。
	generation generationHelperBackend
	limiter    chan struct{}
	timeout    time.Duration
	// afterRootCheck runs right after publish opened the trusted plugins root.
	// It is nil in production; tests use it to swap paths mid-request.
	afterRootCheck func()
	// afterOpenStaged runs right after publish pinned the staged tree handle.
	// It is nil in production; tests use it to swap the staged path.
	afterOpenStaged func()
	// lookupUID resolves the agent user, the owner the staging tree must
	// have. Tests replace it; production reads the user database.
	lookupUID func(name string) (int, error)
	// afterPeerAuth 仅测试用：读取正文前固定实际请求ctx的预算证据。
	afterPeerAuth func(context.Context)
}

// newHelperServer validates the configuration and builds the installer. The
// runner is a fake in tests and sandbox.ExecRunner in production.
func newHelperServer(cfg helperConfig, runner sandbox.Runner, logger *slog.Logger) (*helperServer, error) {
	if cfg.UnitDir == "" {
		cfg.UnitDir = sandbox.DefaultUnitDir
	}
	if cfg.TmpfilesDir == "" {
		cfg.TmpfilesDir = sandbox.DefaultTmpfilesDir
	}
	if cfg.RuntimeBase == "" {
		cfg.RuntimeBase = sandbox.DefaultRuntimeBase
	}
	if cfg.PluginsRoot == "" {
		cfg.PluginsRoot = defaultPluginsRoot
	}
	if cfg.StagingRoot == "" {
		cfg.StagingRoot = defaultStagingRoot
	}
	if cfg.DataRoot == "" {
		cfg.DataRoot = sandbox.DefaultPluginDataRoot
	}
	if cfg.PrivateDataRoot == "" {
		cfg.PrivateDataRoot = sandbox.DefaultPrivatePluginDataRoot
	}
	if cfg.AgentUser == "" {
		cfg.AgentUser = sandbox.DefaultAgentUser
	}
	if cfg.SocketGroup == "" {
		cfg.SocketGroup = cfg.AgentUser
	}
	for _, p := range []struct{ field, path string }{
		{"unit dir", cfg.UnitDir},
		{"tmpfiles dir", cfg.TmpfilesDir},
		{"runtime base", cfg.RuntimeBase},
		{"plugins root", cfg.PluginsRoot},
		{"staging root", cfg.StagingRoot},
		{"plugin data root", cfg.DataRoot},
		{"private plugin data root", cfg.PrivateDataRoot},
	} {
		if _, err := cleanAbsPath(p.field, p.path); err != nil {
			return nil, err
		}
	}
	if pathWithin(cfg.PluginsRoot, cfg.StagingRoot) || pathWithin(cfg.StagingRoot, cfg.PluginsRoot) {
		return nil, fmt.Errorf("sandbox: staging root %s and plugins root %s must not overlap",
			cfg.StagingRoot, cfg.PluginsRoot)
	}
	if !userPattern.MatchString(cfg.AgentUser) {
		return nil, fmt.Errorf("sandbox: agent user %q is not a valid user name", cfg.AgentUser)
	}
	if !userPattern.MatchString(cfg.SocketGroup) {
		return nil, fmt.Errorf("sandbox: socket group %q is not a valid group name", cfg.SocketGroup)
	}
	if runner == nil {
		runner = sandbox.ExecRunner{}
	}
	if cfg.Version == "" {
		cfg.Version = buildinfo.Read().Version
	}
	return &helperServer{
		cfg: cfg,
		installer: sandbox.Installer{
			UnitDir:     cfg.UnitDir,
			TmpfilesDir: cfg.TmpfilesDir,
			RuntimeBase: cfg.RuntimeBase,
			CredDir:     cfg.CredDir,
			AgentUser:   cfg.AgentUser,
			Runner:      groupRunner{base: runner},
			Trust:       cfg.Trust,
		},
		runner:    runner,
		logger:    loggerOr(logger),
		limiter:   make(chan struct{}, maxConcurrentRequests),
		timeout:   requestTimeout,
		lookupUID: lookupUID,
	}, nil
}

// serve accepts requests until the context is cancelled. A socket-activated
// activation handles exactly one connection and exits, so an idle host has no
// helper process; the socket unit starts a new activation for the next request.
func (s *helperServer) serve(ctx context.Context, ln net.Listener, oneShot bool) error {
	return sandbox.ServeHelperConnections(ctx, ln, oneShot, cap(s.limiter), s.serveConn)
}

// serveConn 先核验内核 UID，再读取、执行一个请求并写回响应。
func (s *helperServer) serveConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	timeout := s.timeout
	if timeout <= 0 {
		timeout = requestTimeout
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	deadline, _ := rctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		s.logger.Warn("privileged connection deadline could not be set", "err", err)
		return
	}
	interrupt := context.AfterFunc(rctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer interrupt()
	// --- 内核身份门禁：请求正文与自报用户名均不参与连接授权 ----------------------
	peerUID, peerErr := sandbox.HelperPeerUID(conn)
	if peerErr == nil && peerUID != 0 {
		agentUID, lookupErr := s.lookupUID(s.cfg.AgentUser)
		if lookupErr != nil {
			peerErr = lookupErr
		} else if peerUID != agentUID {
			peerErr = errors.New("the peer is not the configured agent")
		}
	}
	if peerErr != nil {
		s.logger.Warn("privileged peer rejected", "uid", peerUID, "err", peerErr)
		if err := sandbox.WriteHelperJSON(conn, helperFailure(problem.Unauthenticated,
			"This connection is not authorized to call the privileged helper.")); err != nil {
			s.logger.Warn("privileged peer rejection could not be written", "err", err)
		}
		return
	}
	if rctx.Err() != nil {
		return
	}
	if s.afterPeerAuth != nil {
		s.afterPeerAuth(rctx)
	}
	reader := bufio.NewReaderSize(conn, 64<<10)
	raw, err := sandbox.ReadHelperDocument(reader)
	defer clear(raw)
	if err != nil {
		// The body is never logged: it can contain a plugin token.
		s.logger.Warn("privileged request could not be decoded", "err", err)
		_ = sandbox.WriteHelperJSON(conn, helperFailure(problem.ValidationFailed,
			"The request is not a valid privileged helper request."))
		return
	}
	req, err := sandbox.DecodePrivilegedHelperRequest(raw)
	if err != nil || reader.Buffered() != 0 {
		_ = sandbox.WriteHelperJSON(conn, helperFailure(problem.ValidationFailed,
			"The connection must carry one valid privileged helper request."))
		return
	}
	// --- 同一 reader 监听：预读第二帧已被拒绝，后续字节/断开取消原执行 ----------
	execution, finish := sandbox.WatchHelperReaderDisconnect(rctx, conn, reader)
	defer finish()
	var resp any
	switch {
	case req.Legacy != nil:
		resp = s.handle(execution, *req.Legacy)
	case req.ConsumerStage != nil || req.ConsumerActivate != nil || req.ConsumerCurrent != nil || req.ConsumerRemove != nil:
		resp = s.handleConsumerCert(execution, req)
	default:
		resp = s.handleGeneration(execution, req)
	}
	if err := sandbox.WriteHelperJSON(conn, resp); err != nil {
		s.logger.Warn("privileged response could not be written",
			"err", err)
	}
}

// handle dispatches one request. A panic is converted into a JSON error so a
// bug cannot take down the activation without a reply.
func (s *helperServer) handle(ctx context.Context, req sandbox.HelperRequest) (resp sandbox.HelperResponse) {
	started := time.Now()
	defer func() {
		if r := recover(); r != nil {
			resp = helperFailure(problem.Internal, "The privileged helper failed to handle the request.")
			s.logger.Error("privileged request panicked", "op", req.Op, "panic", fmt.Sprint(r))
		}
		id := req.ID
		if id == "" {
			id = req.PluginID
		}
		s.logger.Info("privileged request",
			"op", req.Op, "id", id, "ok", resp.OK,
			"duration", time.Since(started).Round(time.Millisecond))
	}()
	switch req.Op {
	case sandbox.HelperOpInstall:
		return s.install(ctx, req)
	case sandbox.HelperOpRemove:
		return s.remove(ctx, req)
	case sandbox.HelperOpPublish:
		return s.publish(ctx, req)
	case sandbox.HelperOpLogs:
		return s.logs(ctx, req)
	case sandbox.HelperOpReload:
		return s.reload(ctx)
	case sandbox.HelperOpPing:
		return sandbox.HelperResponse{OK: true, Version: s.cfg.Version, UID: os.Geteuid()}
	default:
		return helperFailure(problem.ValidationFailed,
			fmt.Sprintf("%q is not a privileged helper operation.", req.Op))
	}
}

// install writes everything one plugin needs and reloads systemd.
func (s *helperServer) install(ctx context.Context, req sandbox.HelperRequest) sandbox.HelperResponse {
	if req.Spec == nil {
		return helperFailure(problem.ValidationFailed,
			"An install request must carry a unit spec.")
	}
	spec := *req.Spec
	if err := s.validateSpec(&spec); err != nil {
		return helperFailure(problem.ValidationFailed, err.Error())
	}
	credential, err := decodeCredential(req.CredentialBase64)
	if err != nil {
		return helperFailure(problem.ValidationFailed, err.Error())
	}
	res, err := s.installer.Install(ctx, spec, credential)
	if err != nil {
		s.logger.Error("privileged install failed", "id", spec.ID, "err", err)
		return helperFailure(problem.Internal,
			fmt.Sprintf("The unit artifacts of plugin %s could not be installed.", spec.ID))
	}
	if err := s.daemonReload(ctx); err != nil {
		s.logger.Error("systemctl daemon-reload failed after install", "id", spec.ID, "err", err)
		return helperFailure(problem.Internal,
			"The unit files were written, but systemd could not reload its unit definitions.")
	}
	var warnings []string
	if warning := s.enableSocket(ctx, spec.ID); warning != "" {
		warnings = append(warnings, warning)
	}
	return sandbox.HelperResponse{OK: true, Install: &res, Warnings: warnings}
}

// remove deletes a version directory and, unless KeepUnit is set, the unit
// artifacts of the plugin. It is idempotent.
func (s *helperServer) remove(ctx context.Context, req sandbox.HelperRequest) sandbox.HelperResponse {
	if err := sandbox.ValidateID(req.ID); err != nil {
		return helperFailure(problem.ValidationFailed, err.Error())
	}
	if req.PurgeData && req.KeepUnit {
		return helperFailure(problem.ValidationFailed, "Persistent data cannot be purged while retaining the plugin unit.")
	}
	paths, err := s.removePaths(req)
	if err != nil {
		return helperFailure(problem.ValidationFailed, err.Error())
	}
	pid, err := s.mainPID(ctx, req.ID)
	switch {
	case err != nil:
		s.logger.Error("systemctl show failed before remove", "id", req.ID, "err", err)
		return helperFailure(problem.Unavailable,
			fmt.Sprintf("The systemd state of plugin %s could not be read; nothing was removed.", req.ID))
	case pid > 0:
		return helperFailure(problem.PreconditionFailed,
			fmt.Sprintf("Plugin %s is still running (main PID %d); its files cannot be removed.", req.ID, pid))
	}
	res := sandbox.RemoveResult{ID: req.ID}
	var warnings []string
	if !req.KeepUnit {
		// Stop and disable the socket before the files disappear: an active
		// socket unit would otherwise keep a loaded listener and an enable
		// symlink pointing at a unit that no longer exists. A failure is not
		// fatal; the files are still removed.
		if warning := s.disableSocket(ctx, req.ID); warning != "" {
			if req.PurgeData {
				return helperFailure(problem.Unavailable, "The plugin socket could not be disabled; its persistent data was retained.")
			}
			warnings = append(warnings, warning)
		}
		removed, rerr := s.installer.Remove(ctx, req.ID)
		if rerr != nil {
			s.logger.Error("privileged remove failed", "id", req.ID, "err", rerr)
			return helperFailure(problem.Internal,
				fmt.Sprintf("The unit artifacts of plugin %s could not be removed.", req.ID))
		}
		res = removed
	} else if group, gerr := sandbox.GroupName(req.ID); gerr == nil {
		res.Group = group
	}
	if len(paths) > 0 {
		removed, rerr := s.removeVersionTrees(req.ID, paths)
		res.Removed = append(res.Removed, removed...)
		if rerr != nil {
			s.logger.Error("privileged version removal failed", "id", req.ID, "err", rerr)
			return helperFailure(problem.Internal,
				fmt.Sprintf("The files of plugin %s could not be removed.", req.ID))
		}
	}
	if req.PurgeData {
		removed, err := sandbox.PurgePluginData(ctx, s.cfg.Trust, req.ID, s.cfg.DataRoot, s.cfg.PrivateDataRoot)
		res.Removed = append(res.Removed, removed...)
		if err != nil {
			s.logger.Error("privileged persistent data removal failed", "id", req.ID, "err", err)
			return helperFailure(problem.Internal, fmt.Sprintf("The persistent data of plugin %s could not be removed.", req.ID))
		}
	}
	if err := s.daemonReload(ctx); err != nil {
		s.logger.Error("systemctl daemon-reload failed after remove", "id", req.ID, "err", err)
		return helperFailure(problem.Internal,
			"The files were removed, but systemd could not reload its unit definitions.")
	}
	return sandbox.HelperResponse{OK: true, Remove: &res, Warnings: warnings}
}

// removeVersionTrees deletes validated <plugins-root>/<id>/<version> trees
// through the trusted plugins handle, so a swapped root or a symlinked
// component can never redirect the recursive delete (PRIV-01).
func (s *helperServer) removeVersionTrees(id string, paths []string) ([]string, error) {
	plugins, err := s.openPluginsRoot()
	if err != nil {
		return nil, err
	}
	defer func() { _ = plugins.Close() }()
	var removed []string
	for _, path := range paths {
		rel, err := filepath.Rel(s.cfg.PluginsRoot, path)
		if err != nil {
			return removed, err
		}
		ok, err := sandbox.RemoveAllIn(plugins, rel)
		if err != nil {
			return removed, fmt.Errorf("removing %s: %w", path, err)
		}
		if ok {
			removed = append(removed, path)
			// Drop the now-empty <plugins-root>/<id> directory. Remove fails
			// when another version or file is still there, which is exactly
			// the case where the parent must be kept.
			_ = plugins.Remove(id)
		}
	}
	return removed, nil
}

// openPluginsRoot opens the plugins root as a trusted handle. Every write
// below the root goes through the returned handle.
func (s *helperServer) openPluginsRoot() (*os.Root, error) {
	r, err := s.cfg.Trust.Open(s.cfg.PluginsRoot)
	if err != nil {
		return nil, fmt.Errorf("sandbox: plugins root %s: %w", s.cfg.PluginsRoot, err)
	}
	return r, nil
}

// reload only tells systemd to re-read its unit files.
func (s *helperServer) reload(ctx context.Context) sandbox.HelperResponse {
	if err := s.daemonReload(ctx); err != nil {
		s.logger.Error("systemctl daemon-reload failed", "err", err)
		return helperFailure(problem.Internal, "systemd could not reload its unit definitions.")
	}
	return sandbox.HelperResponse{OK: true}
}

// publish copies a verified staging tree into the immutable version directory.
// It is the root half of install.Staged.Commit: the controller verifies and
// unpacks the package as qwq, but /var/lib/qwq-plugins belongs to root.
//
// The request may only name a direct .staging-* child of the staging root and
// the exact <plugins-root>/<id>/<version> target. The staging tree is validated
// (no symlinks, devices or unsafe names), copied into a temporary directory
// below the plugin parent, finalized to 0555/0444, fsynced and renamed into
// place. An existing version directory is accepted only when its content
// digest is identical.
func (s *helperServer) publish(ctx context.Context, req sandbox.HelperRequest) sandbox.HelperResponse {
	id, version, versionDir, stagedDir, err := s.checkPublishRequest(req)
	if err != nil {
		return helperFailure(problem.ValidationFailed, err.Error())
	}
	// The plugins root is opened once and every later step is relative to
	// this handle: swapping the root (or <id>) after this point cannot
	// redirect a write (PRIV-01).
	plugins, err := s.openPluginsRoot()
	if err != nil {
		s.logger.Error("the plugins root is not available", "err", err)
		return helperFailure(problem.Unavailable,
			"The plugin root is not available on this host; nothing was published.")
	}
	defer func() { _ = plugins.Close() }()
	if s.afterRootCheck != nil {
		s.afterRootCheck()
	}
	// Validation, comparison and copy all read the same pinned handle
	// (PRIV-02): the staging tree is qwq-owned, so any path re-resolution
	// could be raced into a symlink to a root-only directory.
	owner, err := s.lookupUID(s.cfg.AgentUser)
	if err != nil {
		s.logger.Error("the agent user cannot be resolved", "user", s.cfg.AgentUser, "err", err)
		return helperFailure(problem.Unavailable,
			"The plugin staging owner is not available on this host; nothing was published.")
	}
	src, err := s.openStaged(stagedDir, owner)
	if err != nil {
		if errors.Is(err, errStagingUnavailable) {
			s.logger.Error("the staging root is not available", "err", err)
			return helperFailure(problem.Unavailable,
				"The plugin staging root is not available on this host; nothing was published.")
		}
		return helperFailure(problem.ValidationFailed, err.Error())
	}
	defer func() { _ = src.Close() }()
	if s.afterOpenStaged != nil {
		s.afterOpenStaged()
	}
	stats, err := validateStagedTree(ctx, src, owner)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return helperFailure(problem.Timeout,
				"The plugin version could not be published before the request deadline.")
		}
		return helperFailure(problem.ValidationFailed, err.Error())
	}
	res := sandbox.PublishResult{
		ID: id, Version: version, VersionDir: versionDir,
		Files: stats.Files, Dirs: stats.Dirs,
	}
	if err := checkVersionParent(plugins, id); err != nil {
		return helperFailure(problem.PreconditionFailed, err.Error())
	}
	versionRel := filepath.Join(id, version)
	if fi, statErr := plugins.Lstat(versionRel); statErr == nil {
		if !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 {
			return helperFailure(problem.PreconditionFailed,
				fmt.Sprintf("The version path %s exists but is not a real directory.", versionDir))
		}
		same, derr := sameTree(ctx, src, owner, plugins, versionRel)
		if derr != nil {
			if errors.Is(derr, context.DeadlineExceeded) || errors.Is(derr, context.Canceled) {
				return helperFailure(problem.Timeout,
					"The plugin version could not be published before the request deadline.")
			}
			s.logger.Error("comparing the existing version directory failed",
				"id", id, "version", version, "err", derr)
			return helperFailure(problem.Internal,
				fmt.Sprintf("The existing version directory %s could not be compared.", versionDir))
		}
		if !same {
			return helperFailure(problem.PreconditionFailed,
				fmt.Sprintf("The version directory %s already exists with different content.", versionDir))
		}
		res.Existing = true
		return sandbox.HelperResponse{OK: true, Publish: &res}
	} else if !errors.Is(statErr, fs.ErrNotExist) {
		s.logger.Error("inspecting the version directory failed",
			"id", id, "version", version, "err", statErr)
		return helperFailure(problem.Internal,
			fmt.Sprintf("The version directory of plugin %s could not be inspected.", id))
	}
	if err := publishTree(ctx, src, plugins, id, version, owner); err != nil {
		if errors.Is(err, errVersionDirExists) {
			// Another publish won the rename race. Accept it only when the
			// resulting tree is identical.
			same, derr := sameTree(ctx, src, owner, plugins, versionRel)
			if derr != nil {
				if errors.Is(derr, context.DeadlineExceeded) || errors.Is(derr, context.Canceled) {
					return helperFailure(problem.Timeout,
						"The plugin version could not be published before the request deadline.")
				}
				s.logger.Error("comparing a concurrently published version failed",
					"id", id, "version", version, "err", derr)
				return helperFailure(problem.Internal,
					fmt.Sprintf("The published version directory %s could not be compared.", versionDir))
			}
			if !same {
				return helperFailure(problem.PreconditionFailed,
					fmt.Sprintf("The version directory %s already exists with different content.", versionDir))
			}
			res.Existing = true
			return sandbox.HelperResponse{OK: true, Publish: &res}
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return helperFailure(problem.Timeout,
				"The plugin version could not be published before the request deadline.")
		}
		s.logger.Error("publishing the plugin version failed",
			"id", id, "version", version, "err", err)
		return helperFailure(problem.Internal,
			fmt.Sprintf("The package of plugin %s version %s could not be published.", id, version))
	}
	relabelSELinuxPluginBin(ctx, filepath.Join(versionDir, "bin"), s.logger)
	return sandbox.HelperResponse{OK: true, Publish: &res}
}

// relabelSELinuxPluginBin best-effort sets bin_t on published plugin binaries
// when SELinux is enabled (e.g. Rocky/AlmaLinux 9 Enforcing) so systemd does
// not fail unit startup with 203/EXEC.
func relabelSELinuxPluginBin(ctx context.Context, binDir string, logger *slog.Logger) {
	if _, err := os.Stat("/sys/fs/selinux/enforce"); err != nil {
		return
	}
	if _, err := os.Stat(binDir); err != nil {
		return
	}
	chcon, err := exec.LookPath("chcon")
	if err != nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if out, rerr := exec.CommandContext(cctx, chcon, "-R", "-t", "bin_t", binDir).CombinedOutput(); rerr != nil && logger != nil {
		logger.Warn("selinux chcon bin_t on plugin bin failed", "dir", binDir, "err", rerr, "output", strings.TrimSpace(string(out)))
	}
}

// checkPublishRequest pins both paths to their configured roots and returns the
// validated ids and paths.
func (s *helperServer) checkPublishRequest(req sandbox.HelperRequest) (id, version, versionDir, stagedDir string, err error) {
	id = req.PluginID
	if err := sandbox.ValidateID(id); err != nil {
		return "", "", "", "", err
	}
	version = req.Version
	if version == "" || len(version) > maxVersionLen || !versionPattern.MatchString(version) {
		return "", "", "", "", fmt.Errorf("sandbox: version %q is not a valid version directory name", version)
	}
	versionDir, err = cleanAbsPath("version dir", req.VersionDir)
	if err != nil {
		return "", "", "", "", err
	}
	want := filepath.Join(s.cfg.PluginsRoot, id, version)
	if versionDir != want {
		return "", "", "", "", fmt.Errorf("sandbox: version dir %q is not %q", versionDir, want)
	}
	stagedDir, err = cleanAbsPath("staged dir", req.StagedDir)
	if err != nil {
		return "", "", "", "", err
	}
	rel, rerr := filepath.Rel(s.cfg.StagingRoot, stagedDir)
	if rerr != nil || rel == "." || rel == ".." ||
		strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", "", "", "", fmt.Errorf("sandbox: staged dir %q is outside %s", stagedDir, s.cfg.StagingRoot)
	}
	if strings.ContainsRune(rel, filepath.Separator) {
		return "", "", "", "", fmt.Errorf("sandbox: staged dir %q must be a direct child of %s",
			stagedDir, s.cfg.StagingRoot)
	}
	if !strings.HasPrefix(rel, install.StagingPrefix) {
		return "", "", "", "", fmt.Errorf("sandbox: staged dir %q is not an install staging directory", stagedDir)
	}
	fi, lerr := os.Lstat(stagedDir)
	if lerr != nil {
		return "", "", "", "", fmt.Errorf("sandbox: staged dir %q is not readable: %w", stagedDir, lerr)
	}
	if !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 {
		return "", "", "", "", fmt.Errorf("sandbox: staged dir %q is not a real directory", stagedDir)
	}
	return id, version, versionDir, stagedDir, nil
}

// errStagingUnavailable marks a staging root that is missing or not shaped
// as the layout requires; publish reports it as UNAVAILABLE.
var errStagingUnavailable = errors.New("the staging root is not available")

// openStaged pins the staged tree: the staging root must be a real 0700
// directory owned by the agent user, the staged entry a real directory below
// it, and the returned handle must be the very inode that was inspected.
// Everything publish reads afterwards goes through this handle.
func (s *helperServer) openStaged(stagedDir string, owner int) (*os.Root, error) {
	staging, err := os.OpenRoot(s.cfg.StagingRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", errStagingUnavailable, s.cfg.StagingRoot, err)
	}
	defer func() { _ = staging.Close() }()
	rfi, err := staging.Stat(".")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errStagingUnavailable, err)
	}
	if uid, ok := sandbox.FileOwner(rfi); !ok || uid != owner || rfi.Mode().Perm() != 0o700 {
		return nil, fmt.Errorf("%w: %s must be a 0700 directory owned by uid %d", errStagingUnavailable,
			s.cfg.StagingRoot, owner)
	}
	rel := filepath.Base(stagedDir)
	lfi, err := staging.Lstat(rel)
	if err != nil {
		return nil, fmt.Errorf("sandbox: staged dir %q is not readable: %w", stagedDir, err)
	}
	if !lfi.IsDir() || lfi.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("sandbox: staged dir %q is not a real directory", stagedDir)
	}
	src, err := staging.OpenRoot(rel)
	if err != nil {
		return nil, fmt.Errorf("sandbox: opening staged dir %q: %w", stagedDir, err)
	}
	if fi, err := src.Stat("."); err != nil || !os.SameFile(fi, lfi) {
		_ = src.Close()
		return nil, fmt.Errorf("sandbox: staged dir %q changed while it was being opened", stagedDir)
	}
	return src, nil
}

// openStagedFile opens a regular file below r without blocking: O_NONBLOCK
// keeps a FIFO swapped in after validation from hanging the open, and the
// fstat on the opened descriptor rejects anything that is not a regular,
// single-link file owned by owner (owner < 0 skips the owner check, used for
// the root-owned published tree).
func openStagedFile(r *os.Root, rel string, owner int) (*os.File, fs.FileInfo, error) {
	f, err := r.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	nlink, uid, ok := sandbox.FileLinks(fi)
	switch {
	case !fi.Mode().IsRegular():
		err = fmt.Errorf("sandbox: %q is not a regular file", rel)
	case !ok || nlink != 1:
		err = fmt.Errorf("sandbox: %q has %d hard links; a plugin package file must have exactly one", rel, nlink)
	case owner >= 0 && uid != owner:
		err = fmt.Errorf("sandbox: %q is owned by uid %d, want %d", rel, uid, owner)
	}
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, fi, nil
}

// lookupUID resolves a user name through os/user.
func lookupUID(name string) (int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(u.Uid)
}

// checkVersionParent refuses a plugin directory that is a symlink or a file.
// A missing <plugins-root>/<id> is created by publishTree.
func checkVersionParent(plugins *os.Root, id string) error {
	fi, err := plugins.Lstat(id)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("sandbox: inspecting plugin directory %s: %w", id, err)
	case !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("sandbox: plugin directory %s is not a real directory", id)
	}
	return nil
}

// treeStats counts the entries below one version directory.
type treeStats struct {
	Files int
	Dirs  int
}

// validateStagedTree rejects anything publish must not copy: symlinks, devices,
// FIFOs, sockets, hard-linked or foreign-owned files and path components that
// are empty, dot segments, too long or carry control characters. It walks the
// pinned handle, never a path.
func validateStagedTree(ctx context.Context, src *os.Root, owner int) (treeStats, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var stats treeStats
	err := fs.WalkDir(src.FS(), ".", func(rel string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if err := checkTreePath(rel); err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			return fmt.Errorf("sandbox: %q is a symlink; a plugin package may not contain one", rel)
		case info.IsDir():
			stats.Dirs++
		case info.Mode().IsRegular():
			nlink, uid, ok := sandbox.FileLinks(info)
			if !ok || nlink != 1 {
				return fmt.Errorf("sandbox: %q has %d hard links; a plugin package file must have exactly one", rel, nlink)
			}
			if uid != owner {
				return fmt.Errorf("sandbox: %q is owned by uid %d, want %d", rel, uid, owner)
			}
			stats.Files++
		default:
			return fmt.Errorf("sandbox: %q is not a regular file or directory", rel)
		}
		return nil
	})
	return stats, err
}

// checkTreePath validates one relative path component by component.
func checkTreePath(rel string) error {
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("sandbox: %q contains an empty or dot path component", rel)
		}
		if len(part) > maxTreeNameLen {
			return fmt.Errorf("sandbox: path component %q is longer than %d bytes", part, maxTreeNameLen)
		}
		for _, r := range part {
			if r < 0x20 || r == 0x7f {
				return fmt.Errorf("sandbox: %q contains a control character", rel)
			}
		}
	}
	return nil
}

// sameTree reports whether the pinned staged tree and the published version
// rel below plugins have the same structure, file executable bits and file
// content. Directory permission bits are ignored because the staged tree is
// finalized while it is copied.
func sameTree(ctx context.Context, src *os.Root, owner int, plugins *os.Root, rel string) (bool, error) {
	da, _, err := treeDigest(ctx, src, owner)
	if err != nil {
		return false, err
	}
	version, err := plugins.OpenRoot(rel)
	if err != nil {
		return false, err
	}
	defer func() { _ = version.Close() }()
	db, _, err := treeDigest(ctx, version, -1)
	if err != nil {
		return false, err
	}
	return da == db, nil
}

// treeDigest hashes the tree in lexical order. Every field is NUL separated so
// a file name containing a newline cannot collide with another entry.
func treeDigest(ctx context.Context, r *os.Root, owner int) (string, treeStats, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	h := sha256.New()
	var stats treeStats
	err := fs.WalkDir(r.FS(), ".", func(rel string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			return fmt.Errorf("sandbox: %q is a symlink", rel)
		case info.IsDir():
			stats.Dirs++
			fmt.Fprintf(h, "d\x00%s\n", rel)
		case info.Mode().IsRegular():
			stats.Files++
			exec := byte('0')
			if info.Mode().Perm()&0o111 != 0 {
				exec = '1'
			}
			fmt.Fprintf(h, "f\x00%s\x00%c\x00%d\n", rel, exec, info.Size())
			f, _, oerr := openStagedFile(r, rel, owner)
			if oerr != nil {
				return oerr
			}
			_, cerr := io.Copy(h, f)
			if closeErr := f.Close(); cerr == nil {
				cerr = closeErr
			}
			if cerr != nil {
				return cerr
			}
			h.Write([]byte{0})
		default:
			return fmt.Errorf("sandbox: %q is not a regular file or directory", rel)
		}
		return nil
	})
	if err != nil {
		return "", treeStats{}, err
	}
	return hex.EncodeToString(h.Sum(nil)), stats, nil
}

// errVersionDirExists reports that the rename lost a race with another publish.
var errVersionDirExists = errors.New("publish: the version directory appeared concurrently")

// publishTree copies the pinned staged tree into a temporary directory below
// <plugins>/<id>, finalizes it and renames it to <id>/<version>. Every read is
// relative to src and every write to the trusted plugins handle. A concurrent
// winner of the rename is reported as errVersionDirExists for the caller to
// compare.
func publishTree(ctx context.Context, src *os.Root, plugins *os.Root, id, version string, owner int) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := sandbox.MkdirAllIn(plugins, id, 0o755); err != nil {
		return fmt.Errorf("creating plugin directory %s: %w", id, err)
	}
	// Make a newly created plugin directory durable before it receives the
	// version entry.
	if err := sandbox.SyncIn(plugins, "."); err != nil {
		return err
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := filepath.Join(id, ".publish-"+hex.EncodeToString(rnd[:]))
	if err := plugins.Mkdir(tmp, 0o700); err != nil {
		return fmt.Errorf("creating a temporary version directory: %w", err)
	}
	defer func() {
		if tmp != "" {
			_, _ = sandbox.RemoveAllIn(plugins, tmp)
		}
	}()
	err := fs.WalkDir(src.FS(), ".", func(rel string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if err := checkTreePath(rel); err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("sandbox: %q is a symlink", rel)
		}
		dest := filepath.Join(tmp, rel)
		if info.IsDir() {
			return plugins.MkdirAll(dest, 0o700)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("sandbox: %q is not a regular file", rel)
		}
		if err := plugins.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
			return err
		}
		in, st, err := openStagedFile(src, rel, owner)
		if err != nil {
			return err
		}
		defer func() { _ = in.Close() }()
		return copyPublishedFile(plugins, dest, in, st.Mode())
	})
	if err != nil {
		return err
	}
	if err := finalizePublishedTree(plugins, tmp); err != nil {
		return err
	}
	versionRel := filepath.Join(id, version)
	if err := plugins.Rename(tmp, versionRel); err != nil {
		if _, statErr := plugins.Lstat(versionRel); statErr == nil {
			return fmt.Errorf("%w: %s", errVersionDirExists, versionRel)
		}
		return fmt.Errorf("publishing %s: %w", versionRel, err)
	}
	tmp = ""
	return sandbox.SyncIn(plugins, id)
}

// copyPublishedFile creates dest inside plugins exclusively and copies in to
// it with the published mode, fsynced before close.
func copyPublishedFile(plugins *os.Root, dest string, in io.Reader, mode fs.FileMode) error {
	out, err := plugins.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Chmod(publishedFileMode(mode)); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// finalizePublishedTree makes every directory below rel 0555 and fsyncs it
// deepest first, all through the plugins handle.
func finalizePublishedTree(plugins *os.Root, rel string) error {
	var dirs []string
	err := fs.WalkDir(plugins.FS(), filepath.ToSlash(rel), func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			dirs = append(dirs, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := plugins.Chmod(dirs[i], install.DirMode); err != nil {
			return fmt.Errorf("mode of %s: %w", dirs[i], err)
		}
		if err := sandbox.SyncIn(plugins, dirs[i]); err != nil {
			return err
		}
	}
	return nil
}

// publishedFileMode preserves the executable bit and drops every write bit.
func publishedFileMode(mode fs.FileMode) fs.FileMode {
	if mode&0o111 != 0 {
		return install.ExecMode
	}
	return install.FileMode
}

// pathWithin reports whether path is root or below it.
func pathWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// validateSpec enforces the allowlist on top of the renderer's validation. The
// renderer already rejects injection and out-of-range limits; this method pins
// the paths to the roots this process was configured with.
func (s *helperServer) validateSpec(spec *sandbox.UnitSpec) error {
	if err := sandbox.ValidateID(spec.ID); err != nil {
		return err
	}
	if spec.AgentUser == "" {
		spec.AgentUser = s.cfg.AgentUser
	} else if spec.AgentUser != s.cfg.AgentUser {
		return fmt.Errorf("sandbox: agent_user %q is not allowed; this helper only serves %q",
			spec.AgentUser, s.cfg.AgentUser)
	}
	if spec.RuntimeBase == "" {
		spec.RuntimeBase = s.cfg.RuntimeBase
	} else if filepath.Clean(spec.RuntimeBase) != s.cfg.RuntimeBase {
		return fmt.Errorf("sandbox: runtime_base %q is not the configured runtime base %q",
			spec.RuntimeBase, s.cfg.RuntimeBase)
	}
	if err := s.checkVersionDir(*spec); err != nil {
		return err
	}
	// RenderUnit is pure and validates the entrypoint, the digest, the
	// executable, the limits and every string that reaches a unit file.
	if _, err := sandbox.RenderUnit(*spec); err != nil {
		return err
	}
	return nil
}

// checkVersionDir requires <plugins root>/<id>/<version>, a real directory
// without symlink components escaping the root.
func (s *helperServer) checkVersionDir(spec sandbox.UnitSpec) error {
	dir, err := cleanAbsPath("version dir", spec.VersionDir)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(s.cfg.PluginsRoot, dir)
	if err != nil {
		return fmt.Errorf("sandbox: version dir %q is not below %s", dir, s.cfg.PluginsRoot)
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) != 2 || parts[0] != spec.ID || !versionPattern.MatchString(parts[1]) {
		return fmt.Errorf("sandbox: version dir %q must be %s/<id>/<version>",
			dir, s.cfg.PluginsRoot)
	}
	plugins, err := s.openPluginsRoot()
	if err != nil {
		return err
	}
	defer func() { _ = plugins.Close() }()
	fi, err := plugins.Lstat(rel)
	if err != nil {
		return fmt.Errorf("sandbox: version dir %s is not installed: %w", dir, err)
	}
	if !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("sandbox: version dir %s is not a real directory", dir)
	}
	return nil
}

// removePaths validates the optional version directories of a remove request.
// The only accepted value is the exact <plugins root>/<id>/<version>.
func (s *helperServer) removePaths(req sandbox.HelperRequest) ([]string, error) {
	if len(req.Paths) == 0 {
		return nil, nil
	}
	if req.Version == "" {
		return nil, errors.New("sandbox: version is required when paths are given")
	}
	if len(req.Version) > maxVersionLen || !versionPattern.MatchString(req.Version) {
		return nil, fmt.Errorf("sandbox: version %q is not a valid version directory name", req.Version)
	}
	want := filepath.Join(s.cfg.PluginsRoot, req.ID, req.Version)
	for _, path := range req.Paths {
		clean, err := cleanAbsPath("remove path", path)
		if err != nil {
			return nil, err
		}
		if clean != want {
			return nil, fmt.Errorf("sandbox: remove path %q is not the version directory %q", clean, want)
		}
	}
	return []string{want}, nil
}

// mainPID returns the main process of the plugin's service unit.
func (s *helperServer) mainPID(ctx context.Context, id string) (int, error) {
	service, _, err := sandbox.UnitNames(id)
	if err != nil {
		return 0, err
	}
	out, err := s.runSystemctl(ctx, "show", "-p", "MainPID", service)
	if err != nil {
		return 0, fmt.Errorf("systemctl show %s: %w", service, err)
	}
	return parseMainPID(out)
}

// daemonReload asks systemd to re-read the unit directory.
func (s *helperServer) daemonReload(ctx context.Context) error {
	out, err := s.runSystemctl(ctx, "daemon-reload")
	if err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w: %s", err, out)
	}
	return nil
}

// enableSocket enables and starts the plugin socket. A missing socket unit is
// not fatal: the unit files are installed and an operator can enable it. A
// failure is returned as a warning because the install itself succeeded.
func (s *helperServer) enableSocket(ctx context.Context, id string) string {
	_, socket, err := sandbox.UnitNames(id)
	if err != nil {
		return fmt.Sprintf("The socket unit of plugin %s could not be derived.", id)
	}
	path := filepath.Join(s.cfg.UnitDir, socket)
	if fi, statErr := os.Stat(path); statErr != nil || fi.IsDir() {
		return fmt.Sprintf("The socket unit %s was not installed, so it was not enabled.", socket)
	}
	out, err := s.runSystemctl(ctx, "enable", "--now", socket)
	if err != nil {
		message := strings.TrimSpace(out + " " + err.Error())
		return fmt.Sprintf("The socket unit %s could not be enabled: %s", socket, message)
	}
	return ""
}

// disableSocket stops and disables the plugin socket before its unit file is
// removed. A socket unit that was never installed is skipped: there is nothing
// to disable and `systemctl disable` would fail on an unknown unit.
func (s *helperServer) disableSocket(ctx context.Context, id string) string {
	_, socket, err := sandbox.UnitNames(id)
	if err != nil {
		return ""
	}
	if _, statErr := os.Stat(filepath.Join(s.cfg.UnitDir, socket)); statErr != nil {
		return ""
	}
	out, err := s.runSystemctl(ctx, "disable", "--now", socket)
	if err != nil {
		message := strings.TrimSpace(out + " " + err.Error())
		return fmt.Sprintf("The socket unit %s could not be disabled: %s", socket, message)
	}
	return ""
}

// runSystemctl runs one allowlisted systemctl command. The helper never takes
// a command from a request.
func (s *helperServer) runSystemctl(ctx context.Context, args ...string) (string, error) {
	if err := checkSystemctlArgs(args); err != nil {
		return "", err
	}
	return s.runner.Run(ctx, "systemctl", args...)
}

// checkSystemctlArgs is the allowlist of systemctl arguments. Unit names must
// be concrete qwq-plugin@<id> units so a request cannot address another unit.
func checkSystemctlArgs(args []string) error {
	if len(args) == 0 {
		return errors.New("sandbox: empty systemctl command")
	}
	switch args[0] {
	case "daemon-reload":
		if len(args) != 1 {
			return fmt.Errorf("sandbox: systemctl daemon-reload takes no arguments")
		}
		return nil
	case "show":
		if len(args) != 4 || args[1] != "-p" || args[2] != "MainPID" {
			return fmt.Errorf("sandbox: systemctl show is only allowed as show -p MainPID <unit>")
		}
		return checkPluginUnit(args[3], ".service")
	case "enable", "disable":
		if len(args) != 3 || args[1] != "--now" {
			return fmt.Errorf("sandbox: systemctl %s is only allowed as %s --now <socket>", args[0], args[0])
		}
		return checkPluginUnit(args[2], ".socket")
	default:
		return fmt.Errorf("sandbox: systemctl %q is not allowed", args[0])
	}
}

// checkPluginUnit accepts only qwq-plugin@<valid id><suffix>.
func checkPluginUnit(unit, suffix string) error {
	if err := sandbox.CheckUnitName(unit); err != nil {
		return err
	}
	if !strings.HasPrefix(unit, "qwq-plugin@") || !strings.HasSuffix(unit, suffix) {
		return fmt.Errorf("sandbox: %q is not a qwq plugin %s unit", unit, suffix)
	}
	id := strings.TrimSuffix(strings.TrimPrefix(unit, "qwq-plugin@"), suffix)
	if err := sandbox.ValidateID(id); err != nil {
		return fmt.Errorf("sandbox: %q is not a qwq plugin unit: %w", unit, err)
	}
	return nil
}

// groupRunner restricts the external commands sandbox.Installer may run. The
// installer only needs the shadow tools; a bug that tries anything else fails
// here instead of executing it as root.
type groupRunner struct {
	base sandbox.Runner
}

func (r groupRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	switch name {
	case "groupadd":
		if len(args) != 3 || args[0] != "--system" || args[1] != "--force" {
			return "", fmt.Errorf("sandbox: groupadd is only allowed as groupadd --system --force <group>")
		}
		if err := checkPluginGroup(args[2]); err != nil {
			return "", err
		}
	case "groupdel":
		if len(args) != 1 {
			return "", fmt.Errorf("sandbox: groupdel is only allowed as groupdel <group>")
		}
		if err := checkPluginGroup(args[0]); err != nil {
			return "", err
		}
	case "getent":
		if len(args) != 2 || args[0] != "group" {
			return "", fmt.Errorf("sandbox: getent is only allowed as getent group <group>")
		}
		if err := checkPluginGroup(args[1]); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("sandbox: the privileged helper never runs %q", name)
	}
	return r.base.Run(ctx, name, args...)
}

// checkPluginGroup accepts only qwq-p-<valid id>.
func checkPluginGroup(name string) error {
	if !strings.HasPrefix(name, "qwq-p-") {
		return fmt.Errorf("sandbox: %q is not a qwq plugin group", name)
	}
	return sandbox.ValidateID(strings.TrimPrefix(name, "qwq-p-"))
}

// decodeCredential decodes the optional base64 credential. The token is
// validated here as well as by sandbox.Installer so a bad token is reported as
// a request error instead of a failed install.
func decodeCredential(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, nil
	}
	if len(encoded) > maxCredentialBase64 {
		return nil, errors.New("sandbox: credential_base64 is larger than the helper accepts")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("sandbox: credential_base64 is not valid base64")
	}
	if len(raw) < sandbox.MinTokenLen || len(raw) > sandbox.MaxTokenLen {
		return nil, fmt.Errorf("sandbox: credential is %d bytes, want %d..%d",
			len(raw), sandbox.MinTokenLen, sandbox.MaxTokenLen)
	}
	for _, b := range raw {
		if b < 0x21 || b > 0x7e {
			return nil, errors.New("sandbox: credential must be printable ASCII without spaces")
		}
	}
	return raw, nil
}

// helperFailure builds a refused response.
func helperFailure(code problem.Code, detail string) sandbox.HelperResponse {
	return sandbox.HelperResponse{Code: string(code), Error: detail}
}

// parseMainPID extracts MainPID from `systemctl show -p MainPID`.
func parseMainPID(out string) (int, error) {
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || key != "MainPID" {
			continue
		}
		pid, err := strconv.Atoi(value)
		if err != nil || pid < 0 {
			return 0, fmt.Errorf("systemctl show returned MainPID=%q", value)
		}
		return pid, nil
	}
	return 0, errors.New("systemctl show returned no MainPID property")
}

// cleanAbsPath validates an absolute, clean, single-line path.
func cleanAbsPath(field, path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("sandbox: %s is empty", field)
	}
	if strings.ContainsAny(path, "\x00\n\r") {
		return "", fmt.Errorf("sandbox: %s contains a control character", field)
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("sandbox: %s %q is not absolute", field, path)
	}
	if filepath.Clean(path) != path {
		return "", fmt.Errorf("sandbox: %s %q is not a clean path", field, path)
	}
	if path == string(filepath.Separator) {
		return "", fmt.Errorf("sandbox: %s must not be the root directory", field)
	}
	return path, nil
}

// loggerOr returns logger or a discard logger.
func loggerOr(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return logger
}
