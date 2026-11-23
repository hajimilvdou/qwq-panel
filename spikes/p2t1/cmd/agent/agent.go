// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	grpc_health_v1 "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/qwq-panel/qwq/spikes/p2t1/internal/echopb"
	"github.com/qwq-panel/qwq/spikes/p2t1/internal/peercred"
)

type agent struct {
	ids          []string
	hostDir      string
	stateDir     string
	pluginSocket string
	pluginUnit   string
	socketUnit   string
	agentUnit    string
	linkDir      string
	runProbe     bool
	log          *slog.Logger

	mu       sync.Mutex
	mainPIDs map[string]int
	gens     map[string]string
	echoes   map[string]*echopb.EchoClient
	clients  []*plugin.Client
	servers  []*grpc.Server
	lns      []net.Listener
}

func (a *agent) unit(id string) string { return fmt.Sprintf(a.pluginUnit, id) }
func (a *agent) socketUnitName(id string) string {
	return fmt.Sprintf(a.socketUnit, id)
}
func (a *agent) socketPath(id string) string { return fmt.Sprintf(a.pluginSocket, id) }
func (a *agent) hostSocket(id string) string {
	return filepath.Join(a.hostDir, id, "host.sock")
}

// startHostServers listens on one host-service socket per plugin and serves the
// host gRPC API there. The directory is created by the installer with the
// per-plugin group and the setgid bit, so the socket inherits that group and
// only this plugin (plus the agent) can reach it.
func (a *agent) startHostServers(_ context.Context) error {
	a.echoes = map[string]*echopb.EchoClient{}
	a.gens = map[string]string{}
	for _, id := range a.ids {
		dir := filepath.Join(a.hostDir, id)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create host dir %s: %w", dir, err)
		}
		sock := a.hostSocket(id)
		_ = os.Remove(sock)
		ln, err := net.Listen("unix", sock)
		if err != nil {
			return fmt.Errorf("listen host socket %s: %w", sock, err)
		}
		// Keep the group inherited from the setgid directory, allow that group
		// to connect and nobody else.
		if err := unix.Chmod(sock, 0o660); err != nil {
			return fmt.Errorf("chmod host socket %s: %w", sock, err)
		}
		if fi, err := os.Stat(sock); err == nil {
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				a.log.Info("host socket ready", "plugin", id, "socket", sock,
					"mode", fi.Mode().Perm().String(), "uid", st.Uid, "gid", st.Gid,
					"dir_mode", dirMode(dir))
			}
		}

		srv := grpc.NewServer(grpc.Creds(peercred.TransportCredentials{}))
		echopb.RegisterHostServer(srv, &hostServer{agent: a, pluginID: id})
		a.lns = append(a.lns, ln)
		a.servers = append(a.servers, srv)
		go func() {
			if err := srv.Serve(peercred.CredListener{Listener: ln}); err != nil {
				a.log.Warn("host server stopped", "err", err)
			}
		}()
		a.log.Info("host service listening", "plugin", id, "socket", sock)
	}
	return nil
}

// attach connects to a plugin through go-plugin's ReattachConfig and records
// the generation derived from systemd and the kernel.
func (a *agent) attach(ctx context.Context, id string) (*PluginState, error) {
	sock := a.socketPath(id)
	st := &PluginState{
		PluginID:   id,
		Unit:       a.unit(id),
		Socket:     sock,
		HostSocket: a.hostSocket(id),
		AgentPID:   os.Getpid(),
		AgentUID:   os.Getuid(),
		AgentUnit:  a.agentUnit,
		AttachedAt: time.Now().UTC().Format(time.RFC3339Nano),
		LinkPath:   filepath.Join(a.linkDir, "host.sock"),
	}
	t0 := time.Now()

	// Socket activation: starting the socket unit is all the agent may do.
	if err := a.systemctl("start", a.socketUnitName(id)); err != nil {
		st.Error = "start socket unit: " + err.Error()
		return st, errors.New(st.Error)
	}
	st.SocketUnitStartedMS = time.Since(t0).Milliseconds()

	// The first connect triggers the service start.
	dialer := peercred.NewDialer(sock)
	cc, err := grpc.NewClient("passthrough:///plugin",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer.DialContext),
		grpc.WithDefaultCallOptions(grpc.CallContentSubtype(echopb.JSONSubtype)))
	if err != nil {
		st.Error = "grpc client: " + err.Error()
		return st, errors.New(st.Error)
	}
	defer func() { _ = cc.Close() }()

	health := grpc_health_v1.NewHealthClient(cc)
	deadline := time.Now().Add(attachTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		st.HealthAttempts++
		cctx, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
		_, err := health.Check(cctx, &grpc_health_v1.HealthCheckRequest{Service: "plugin"})
		cancel()
		if err == nil {
			lastErr = nil
			break
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	st.ColdStartMS = time.Since(t0).Milliseconds()
	if lastErr != nil {
		st.Error = "plugin not ready: " + lastErr.Error()
		return st, errors.New(st.Error)
	}
	st.FirstRPCMs = time.Since(t0).Milliseconds()

	mainPID, err := a.showMainPID(id)
	if err != nil {
		st.Error = "read MainPID: " + err.Error()
		return st, errors.New(st.Error)
	}
	st.MainPID = mainPID

	cred, ok := dialer.Cred()
	if !ok {
		st.Error = "no peer credentials captured from plugin socket"
		return st, errors.New(st.Error)
	}
	st.PeerPID, st.PeerUID = cred.PID, cred.UID
	st.Pidfd, st.PidfdErr = cred.PidfdOK, cred.PidfdErr

	proc, err := peercred.ReadProc(mainPID)
	if err != nil {
		st.Error = "read plugin /proc identity: " + err.Error()
		return st, errors.New(st.Error)
	}
	st.PluginUID = proc.UID
	st.PluginCgroup = proc.Cgroup
	st.PluginUnit = proc.Unit
	st.PluginStartTime = proc.StartTime
	st.MainPIDMatch = int(cred.PID) == mainPID
	// With socket activation the listening socket belongs to systemd, so the
	// client side of SO_PEERCRED reports pid 1, not the plugin. The plugin's
	// kernel identity is therefore proven on the host channel below.
	st.PluginSocketPeerIsSystemd = cred.PID == 1 && cred.UID == 0
	st.UnitMatch = proc.Unit == a.unit(id)
	if st.Pidfd {
		st.PidfdAlive = cred.Alive() == nil
	}
	gen, gerr := generation(a.unit(id), mainPID, proc.StartTime)
	if gerr != nil {
		st.Error = gerr.Error()
		return st, gerr
	}
	st.Generation = gen
	a.mu.Lock()
	a.mainPIDs[id] = mainPID
	a.gens[id] = gen
	a.mu.Unlock()

	st.Environment = a.showProperty(id, "Environment")
	st.LoadCredential = a.showProperty(id, "LoadCredential")

	// From here on the production path is go-plugin's ReattachConfig.
	reattach := &plugin.ReattachConfig{
		Protocol:        plugin.ProtocolGRPC,
		ProtocolVersion: 1,
		Addr:            &net.UnixAddr{Name: sock, Net: "unix"},
		Pid:             mainPID,
	}
	st.ReattachPid = reattach.Pid
	gpDialer := peercred.NewDialer(sock)
	client := plugin.NewClient(&plugin.ClientConfig{
		Logger: hclog.New(&hclog.LoggerOptions{
			Name:   "go-plugin",
			Level:  hclog.Info,
			Output: os.Stderr,
		}),
		HandshakeConfig: plugin.HandshakeConfig{
			ProtocolVersion:  1,
			MagicCookieKey:   "QWQ_SPIKE",
			MagicCookieValue: "p2t1",
		},
		Plugins:          map[string]plugin.Plugin{"echo": &echoPlugin{}},
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		Reattach:         reattach,
		GRPCDialOptions:  []grpc.DialOption{grpc.WithContextDialer(gpDialer.DialContext)},
	})
	a.mu.Lock()
	a.clients = append(a.clients, client)
	a.mu.Unlock()

	type clientResult struct {
		cp  plugin.ClientProtocol
		err error
	}
	ch := make(chan clientResult, 1)
	go func() {
		cp, err := client.Client()
		ch <- clientResult{cp: cp, err: err}
	}()
	var cp plugin.ClientProtocol
	select {
	case r := <-ch:
		if r.err != nil {
			st.Error = "go-plugin reattach: " + r.err.Error()
			return st, errors.New(st.Error)
		}
		cp = r.cp
	case <-time.After(10 * time.Second):
		st.Error = "go-plugin reattach timed out"
		return st, errors.New(st.Error)
	}
	raw, err := cp.Dispense("echo")
	if err != nil {
		st.Error = "dispense: " + err.Error()
		return st, errors.New(st.Error)
	}
	echo, ok := raw.(*echopb.EchoClient)
	if !ok {
		st.Error = "unexpected plugin type"
		return st, errors.New(st.Error)
	}
	gpCred, gpOK := gpDialer.Cred()
	if gpOK {
		st.GoPluginPeerPID, st.GoPluginPeerUID = gpCred.PID, gpCred.UID
		if gpProc, err := peercred.ReadProc(int(gpCred.PID)); err == nil {
			st.GoPluginPeerUnit = gpProc.Unit
		}
	}

	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := echo.Echo(callCtx, &echopb.EchoRequest{
		Message: "ping from agent",
		Nonce:   fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano()),
	})
	st.EchoCallMS = time.Since(t0).Milliseconds()
	if err != nil {
		st.EchoErr = err.Error()
		st.Error = "echo rpc: " + err.Error()
		return st, errors.New(st.Error)
	}
	st.Echo = resp
	st.AgentPeerVerified = resp.PeerPID == int32(os.Getpid()) && resp.PeerUID == uint32(os.Getuid()) &&
		resp.AgentUID == uint32(os.Getuid())
	st.AgentPeerUnitVisible = resp.PeerUnit != ""

	// The plugin's kernel identity comes from the host channel: the plugin
	// connects to us, so SO_PEERCRED on that accepted connection is the plugin
	// process. Wait for its first accepted report and require pid == MainPID.
	st.HostVerified = a.awaitHostReport(ctx, id, mainPID, st)

	a.mu.Lock()
	a.echoes[id] = echo
	a.mu.Unlock()
	a.log.Info("plugin attached",
		"plugin", id, "generation", gen, "main_pid", mainPID,
		"plugin_socket_peer_pid", st.PeerPID, "plugin_socket_peer_is_systemd", st.PluginSocketPeerIsSystemd,
		"unit_match", st.UnitMatch, "host_verified", st.HostVerified, "host_peer_pid", st.HostPeerPID,
		"pidfd", st.Pidfd, "cold_start_ms", st.ColdStartMS, "echo_ms", st.EchoCallMS)
	return st, nil
}

// awaitHostReport waits for the first accepted host report from the plugin and
// records the kernel-attested identity it carries.
func (a *agent) awaitHostReport(ctx context.Context, id string, mainPID int, st *PluginState) bool {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return false
		}
		hs, err := readHostState(a.stateDir, id)
		if err == nil && hs.Accepted && hs.MainPID == mainPID {
			st.HostPeerPID, st.HostPeerUID, st.HostPeerUnit = hs.PeerPID, hs.PeerUID, hs.PeerUnit
			st.HostPeerCgroup = hs.PeerCgroup
			st.HostMainPIDMatch = hs.PeerPID == int32(mainPID)
			st.HostGeneration = hs.Generation
			st.HostReportCount = hs.Count
			return st.HostMainPIDMatch
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// probeCrossPlugin asks each plugin to attempt connections that must fail.
func (a *agent) probeCrossPlugin(ctx context.Context) error {
	a.mu.Lock()
	echoes := make(map[string]*echopb.EchoClient, len(a.echoes))
	for k, v := range a.echoes {
		echoes[k] = v
	}
	a.mu.Unlock()

	var firstErr error
	for _, id := range a.ids {
		echo := echoes[id]
		if echo == nil {
			continue
		}
		type target struct {
			name     string
			path     string
			wantDial bool
		}
		targets := []target{
			{"own-host-bind-mount", filepath.Join(a.linkDir, "host.sock"), true},
			{"own-host-real-path", a.hostSocket(id), false},
			{"own-plugin-socket", a.socketPath(id), false},
		}
		for _, other := range a.ids {
			if other == id {
				continue
			}
			targets = append(targets,
				target{"other-plugin-socket:" + other, a.socketPath(other), false},
				target{"other-host-socket:" + other, a.hostSocket(other), false},
			)
		}
		st, err := readState(a.stateDir, id)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, t := range targets {
			callCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			resp, err := echo.Probe(callCtx, &echopb.ProbeRequest{Path: t.path})
			cancel()
			pr := ProbeResult{Name: t.name, Path: t.path, WantDial: t.wantDial}
			if err != nil {
				pr.RPCErr = err.Error()
				pr.Pass = false
			} else {
				pr.StatErr = resp.StatErr
				pr.IsSocket = resp.IsSocket
				pr.DialOK = resp.DialOK
				pr.DialErr = resp.DialErr
				pr.Pass = resp.DialOK == t.wantDial
			}
			if !pr.Pass && firstErr == nil {
				firstErr = fmt.Errorf("probe %s on %s did not match expectation", t.name, id)
			}
			st.Probes = append(st.Probes, pr)
			a.log.Info("probe", "plugin", id, "name", t.name, "path", t.path,
				"want_dial", t.wantDial, "dial_ok", pr.DialOK, "dial_err", pr.DialErr,
				"stat_err", pr.StatErr, "pass", pr.Pass)
		}
		if err := writeState(a.stateDir, id, st); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// currentMainPID always asks systemd. A cached value would go stale if the
// plugin is restarted out of band (for example by an operator or by the socket
// unit after a crash), and a stale MainPID makes the agent reject the plugin's
// own host reports.
func (a *agent) currentMainPID(id string) (int, error) {
	pid, err := a.showMainPID(id)
	if err != nil {
		return 0, err
	}
	a.mu.Lock()
	a.mainPIDs[id] = pid
	a.mu.Unlock()
	return pid, nil
}

func (a *agent) showMainPID(id string) (int, error) {
	out, err := a.showPropertyErr(id, "MainPID")
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return 0, fmt.Errorf("parse MainPID %q: %w", out, err)
	}
	return pid, nil
}

func (a *agent) showProperty(id, prop string) string {
	out, err := a.showPropertyErr(id, prop)
	if err != nil {
		return "error: " + err.Error()
	}
	return out
}

func (a *agent) showPropertyErr(id, prop string) (string, error) {
	out, err := exec.Command("systemctl", "show", "--value", "-p", prop, a.unit(id)).Output()
	return strings.TrimSpace(string(out)), err
}

func (a *agent) systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (a *agent) close() {
	for _, srv := range a.servers {
		srv.GracefulStop()
	}
	for _, ln := range a.lns {
		_ = ln.Close()
	}
	// Close the client connections only; plugin processes are stopped through
	// systemd, never through go-plugin's Client.Kill (which would SIGKILL them).
	for _, c := range a.clients {
		if cp, err := c.Client(); err == nil {
			_ = cp.Close()
		}
	}
}

// dirMode renders the permission bits of a directory for the log.
func dirMode(dir string) string {
	fi, err := os.Stat(dir)
	if err != nil {
		return "missing"
	}
	return fi.Mode().Perm().String()
}

func sha256Sum(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
