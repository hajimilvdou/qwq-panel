// SPDX-License-Identifier: AGPL-3.0-only

// Command plugin is the minimal P2-T1 plugin. It serves a gRPC service on the
// listening file descriptor passed by systemd socket activation and reports to
// the agent over the per-plugin host socket. It deliberately does not use
// go-plugin's Serve(), because Serve() always creates its own listener.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	grpc_health_v1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/qwq-panel/qwq/spikes/p2t1/internal/echopb"
	"github.com/qwq-panel/qwq/spikes/p2t1/internal/peercred"
)

func main() {
	var (
		id         = flag.String("id", "", "plugin instance id (systemd %i)")
		listenFD   = flag.Int("listen-fd", 3, "inherited listening socket file descriptor")
		hostSocket = flag.String("host-socket", "/run/qwq-spike/link/host.sock", "agent host-service socket")
		agentUnit  = flag.String("agent-unit", "qwq-spike-agent.service", "systemd unit of the agent")
	)
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})).
		With("plugin", *id, "pid", os.Getpid())
	if *id == "" {
		log.Error("missing --id")
		os.Exit(2)
	}

	started := time.Now()
	p := &plugin{
		id:         *id,
		agentUnit:  *agentUnit,
		hostSocket: *hostSocket,
		started:    started,
		log:        log,
	}
	if err := p.loadCredential(); err != nil {
		log.Warn("credential unavailable", "err", err)
	}
	if err := p.loadAgentIdentity(); err != nil {
		log.Error("cannot establish the expected agent identity", "err", err, "host_socket", *hostSocket)
		os.Exit(1)
	}

	ln, err := listenerFromFD(*listenFD)
	if err != nil {
		log.Error("cannot adopt inherited listener", "err", err, "fd", *listenFD)
		os.Exit(1)
	}
	log.Info("serving on inherited listener",
		"addr", ln.Addr().String(),
		"LISTEN_FDS", os.Getenv("LISTEN_FDS"),
		"LISTEN_FDNAMES", os.Getenv("LISTEN_FDNAMES"))

	srv := grpc.NewServer(grpc.Creds(peercred.TransportCredentials{}))
	healthSrv := health.NewServer()
	healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	healthSrv.SetServingStatus("plugin", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(srv, healthSrv)
	p.health = healthSrv
	echopb.RegisterEchoServer(srv, p)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.reportLoop(ctx)
	go p.keepaliveMetrics(ctx)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigs
		log.Info("signal received, stopping", "signal", sig.String())
		healthSrv.Shutdown()
		srv.GracefulStop()
		cancel()
	}()

	if err := srv.Serve(ln); err != nil {
		log.Error("grpc serve failed", "err", err)
	}
	log.Info("stopped")
}

// listenerFromFD wraps a systemd socket activation fd into a net.Listener.
func listenerFromFD(fd int) (net.Listener, error) {
	f := os.NewFile(uintptr(fd), "systemd-listen-fd")
	if f == nil {
		return nil, fmt.Errorf("fd %d is not open", fd)
	}
	ln, err := net.FileListener(f)
	_ = f.Close()
	if err != nil {
		return nil, err
	}
	return peercred.CredListener{Listener: ln}, nil
}

type plugin struct {
	id         string
	agentUnit  string
	hostSocket string
	started    time.Time
	log        *slog.Logger
	health     *health.Server

	credentialSHA string
	credentialLen int

	agentUID uint32
	agentGID uint32

	lastReport atomicReport
}

type atomicReport struct {
	mu       sync.Mutex
	ok       bool
	reason   string
	gen      string
	agentPID int32
}

func (a *atomicReport) set(ok bool, reason, gen string, agentPID int32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ok, a.reason, a.gen, a.agentPID = ok, reason, gen, agentPID
}

func (a *atomicReport) get() (bool, string, string, int32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ok, a.reason, a.gen, a.agentPID
}

func (p *plugin) loadCredential() error {
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if dir == "" {
		return errors.New("CREDENTIALS_DIRECTORY is not set")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "spike-token"))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	p.credentialSHA = hex.EncodeToString(sum[:8])
	p.credentialLen = len(raw)
	return nil
}

// loadAgentIdentity derives the expected agent uid/gid from the owner of the
// host socket. Only the agent can create it: it lives in a 0700 directory the
// plugin can only reach through its private bind mount.
func (p *plugin) loadAgentIdentity() error {
	var lastErr error
	for i := 0; i < 60; i++ {
		fi, err := os.Stat(p.hostSocket)
		if err == nil {
			st, ok := fi.Sys().(*syscall.Stat_t)
			if !ok {
				return errors.New("host socket has no stat_t")
			}
			if st.Uid == 0 {
				return errors.New("host socket is owned by root")
			}
			p.agentUID, p.agentGID = st.Uid, st.Gid
			return nil
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	return lastErr
}

// Echo reports the plugin identity and the peer credentials observed for the
// calling agent. The agent is authenticated by uid only: under
// ProtectProc=invisible a plugin cannot map the agent pid to a unit, and the
// agent uid is the kernel-guaranteed fact the ADR requires.
func (p *plugin) Echo(ctx context.Context, req *echopb.EchoRequest) (*echopb.EchoResponse, error) {
	cred, ok := peercred.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no peer credentials on connection")
	}
	proc, procErr := peercred.ReadProc(int(cred.PID))
	resp := &echopb.EchoResponse{
		Message:          req.Message,
		Nonce:            req.Nonce,
		PluginID:         p.id,
		Pid:              os.Getpid(),
		UID:              uint32(os.Getuid()),
		StartedAt:        p.started.UnixNano(),
		PeerPID:          cred.PID,
		PeerUID:          cred.UID,
		PeerUnit:         proc.Unit,
		PIDFD:            cred.PidfdOK,
		AgentUID:         p.agentUID,
		CredentialSHA256: p.credentialSHA,
		CredentialBytes:  p.credentialLen,
	}
	if procErr != nil {
		resp.PeerUnitErr = procErr.Error()
		p.log.Warn("cannot read agent /proc identity", "err", procErr, "pid", cred.PID)
	}
	if p.agentUID == 0 {
		return nil, status.Error(codes.Unavailable, "agent identity not established from host socket")
	}
	if cred.UID != p.agentUID {
		return nil, status.Errorf(codes.PermissionDenied,
			"peer uid %d is not the agent uid %d", cred.UID, p.agentUID)
	}
	if p.health != nil {
		p.health.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	}
	okReport, reason, gen, agentPID := p.lastReport.get()
	resp.HostReportOK, resp.HostReportReason, resp.HostGeneration, resp.HostAgentPID = okReport, reason, gen, agentPID
	return resp, nil
}

// Probe exercises a path from inside the plugin sandbox. Spike-only test hook.
func (p *plugin) Probe(_ context.Context, req *echopb.ProbeRequest) (*echopb.ProbeResponse, error) {
	resp := &echopb.ProbeResponse{Path: req.Path}
	st, err := os.Lstat(req.Path)
	if err != nil {
		resp.StatErr = err.Error()
	} else {
		resp.IsSocket = st.Mode()&os.ModeSocket != 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", req.Path)
	if err != nil {
		resp.DialErr = err.Error()
		return resp, nil
	}
	resp.DialOK = true
	_ = conn.Close()
	return resp, nil
}

// reportLoop keeps reporting to the agent. It reconnects after an agent
// restart, which is what proves the reverse channel is independent of the
// agent process lifetime.
func (p *plugin) reportLoop(ctx context.Context) {
	attempt := 0
	for {
		if ctx.Err() != nil {
			return
		}
		attempt++
		gen, agentPID, err := p.reportOnce(ctx, attempt)
		if err != nil {
			p.lastReport.set(false, err.Error(), gen, agentPID)
			p.log.Warn("host report failed", "attempt", attempt, "err", err.Error())
			select {
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
			}
			continue
		}
		p.lastReport.set(true, "", gen, agentPID)
		p.log.Info("host report accepted", "attempt", attempt, "generation", gen, "agent_pid", agentPID)
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// reportOnce dials the host socket, verifies the agent's kernel identity and
// then calls Host.Report.
func (p *plugin) reportOnce(ctx context.Context, attempt int) (string, int32, error) {
	fi, err := os.Stat(p.hostSocket)
	if err != nil {
		return "", 0, fmt.Errorf("stat host socket: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", 0, errors.New("host socket has no stat_t")
	}
	expectedUID := st.Uid

	d := peercred.NewDialer(p.hostSocket)
	conn, err := grpc.NewClient("passthrough:///host",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(d.DialContext),
		grpc.WithDefaultCallOptions(grpc.CallContentSubtype(echopb.JSONSubtype)))
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = conn.Close() }()

	callCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	resp, err := echopb.NewHostClient(conn).Report(callCtx, &echopb.HostReportRequest{
		PluginID:  p.id,
		PluginPID: os.Getpid(),
		PluginUID: uint32(os.Getuid()),
		StartedAt: p.started.UnixNano(),
		Attempt:   attempt,
	})
	if err != nil {
		return "", 0, fmt.Errorf("report rpc: %w", err)
	}

	cred, ok := d.Cred()
	if !ok {
		return "", 0, errors.New("no peer credentials captured on host connection")
	}
	// Required check: the kernel says the peer is the agent uid. SO_PEERCRED
	// reports the peer's *primary* gid, which is not the socket's group, so the
	// gid is only logged. Reading the agent's cgroup is best effort, because
	// ProtectProc=invisible hides other users' processes from the sandbox.
	if cred.UID != expectedUID {
		return "", 0, fmt.Errorf("host socket peer uid %d does not match the agent uid %d",
			cred.UID, expectedUID)
	}
	peerUnit, unitErr := "", ""
	if proc, err := peercred.ReadProc(int(cred.PID)); err == nil {
		peerUnit = proc.Unit
		if proc.Unit != p.agentUnit {
			p.log.Warn("host peer unit mismatch", "unit", proc.Unit, "want", p.agentUnit)
		}
	} else {
		unitErr = err.Error()
	}
	if !resp.Accepted {
		return "", 0, fmt.Errorf("agent rejected report: %s", resp.Reason)
	}
	p.log.Info("host peer verified",
		"agent_pid", cred.PID, "agent_uid", cred.UID, "agent_unit", peerUnit,
		"agent_unit_err", unitErr, "pidfd", cred.PidfdOK, "generation", resp.Generation)
	return resp.Generation, cred.PID, nil
}

// keepaliveMetrics logs the plugin RSS every 30 seconds so the report has
// steady-state numbers.
func (p *plugin) keepaliveMetrics(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			var ru unix.Rusage
			_ = unix.Getrusage(unix.RUSAGE_SELF, &ru)
			p.log.Info("plugin alive", "maxrss_kib", ru.Maxrss, "uptime_s", int(time.Since(p.started).Seconds()))
		}
	}
}
