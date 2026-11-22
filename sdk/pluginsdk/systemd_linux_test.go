// SPDX-License-Identifier: Apache-2.0

//go:build linux

package pluginsdk

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// transportTestEnv prepares the activation environment and the two Unix
// sockets the transport needs. The activation descriptor is a duplicate of a
// real listening socket, so the test exercises net.FileListener instead of a
// fake.
type transportTestEnv struct {
	dir        string
	socket     string
	hostSocket string
	listener   net.Listener
	file       *os.File
}

func newTransportTestEnv(t *testing.T) *transportTestEnv {
	t.Helper()
	// Unix socket paths are limited to 108 bytes; t.TempDir embeds the test
	// name, so the directory lives directly under /tmp.
	dir, err := os.MkdirTemp("", "qwq-sdk-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	socket := filepath.Join(dir, "plugin.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen %s: %v", socket, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	file, err := ln.(*net.UnixListener).File()
	if err != nil {
		t.Fatalf("duplicate the listener: %v", err)
	}
	t.Cleanup(func() { _ = file.Close() })

	hostSocket := filepath.Join(dir, "host.sock")
	host, err := net.Listen("unix", hostSocket)
	if err != nil {
		t.Fatalf("listen %s: %v", hostSocket, err)
	}
	t.Cleanup(func() { _ = host.Close() })
	go func() {
		for {
			conn, err := host.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	return &transportTestEnv{dir: dir, socket: socket, hostSocket: hostSocket, listener: ln, file: file}
}

func (e *transportTestEnv) activation(t *testing.T) {
	t.Helper()
	t.Setenv("LISTEN_FDS", "1")
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
}

func (e *transportTestEnv) options() SystemdOptions {
	return SystemdOptions{
		PluginID:       "test.plugin",
		HostSocket:     e.hostSocket,
		ListenFD:       int(e.file.Fd()),
		HostSocketWait: 2 * time.Second,
		ShutdownGrace:  time.Second,
		Logger:         slog.New(slog.DiscardHandler),
	}
}

func transportServeOptions() Options {
	return Options{
		Plugin:   newTestPlugin(),
		Manifest: fixtureManifest(0, defaultOps, defaultCaps),
	}
}

// startTransport runs ServeSystemd in the background and returns the result
// channel plus a connected client.
func startTransport(t *testing.T, env *transportTestEnv) (*grpc.ClientConn, <-chan error, context.CancelFunc) {
	t.Helper()
	env.activation(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- ServeSystemd(ctx, env.options(), transportServeOptions())
	}()
	conn, err := waitForTransport(t, env.socket)
	if err != nil {
		cancel()
		select {
		case serr := <-errCh:
			t.Fatalf("ServeSystemd: %v (client: %v)", serr, err)
		case <-time.After(5 * time.Second):
			t.Fatalf("client: %v", err)
		}
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, errCh, cancel
}

// waitForTransport dials the plugin socket until the gRPC health service
// answers or the deadline expires.
func waitForTransport(t *testing.T, socket string) (*grpc.ClientConn, error) {
	t.Helper()
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(5 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		_, last = grpc_health_v1.NewHealthClient(conn).Check(ctx, &grpc_health_v1.HealthCheckRequest{})
		cancel()
		if last == nil {
			return conn, nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	_ = conn.Close()
	return nil, fmt.Errorf("the plugin did not answer: %w", last)
}

func TestServeSystemdServesInheritedListener(t *testing.T) {
	env := newTransportTestEnv(t)
	conn, errCh, cancel := startTransport(t, env)
	ctx := t.Context()

	for _, service := range []string{"", DefaultHealthService} {
		resp, err := grpc_health_v1.NewHealthClient(conn).Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: service})
		if err != nil {
			t.Fatalf("health %q: %v", service, err)
		}
		if resp.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
			t.Errorf("health %q = %s, want SERVING", service, resp.GetStatus())
		}
	}
	desc, err := platformv1.NewPluginServiceClient(conn).GetDescriptor(ctx, &platformv1.GetDescriptorRequest{})
	if err != nil {
		t.Fatalf("GetDescriptor: %v", err)
	}
	if desc.GetDescriptor_().GetPluginId() != "test.plugin" {
		t.Errorf("descriptor id = %q, want test.plugin", desc.GetDescriptor_().GetPluginId())
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ServeSystemd after cancel: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeSystemd did not stop after the context was canceled")
	}
}

func TestServeSystemdRejectsBadActivation(t *testing.T) {
	// A regular file is a valid descriptor but not a listening socket.
	plain, err := os.CreateTemp("", "qwq-sdk-fd-*")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	defer func() { _ = plain.Close() }()

	cases := []struct {
		name       string
		listenFDs  string
		listenPID  string
		fd         int
		wantSubstr string
	}{
		{name: "missing LISTEN_FDS", listenFDs: "", listenPID: "self", wantSubstr: "LISTEN_FDS"},
		{name: "wrong count", listenFDs: "2", listenPID: "self", wantSubstr: "exactly one"},
		{name: "missing LISTEN_PID", listenFDs: "1", listenPID: "", wantSubstr: "LISTEN_PID"},
		{name: "wrong pid", listenFDs: "1", listenPID: "other", wantSubstr: "does not match this process"},
		{name: "fd below start", listenFDs: "1", listenPID: "self", fd: 2, wantSubstr: "below the socket-activation start"},
		{name: "regular file", listenFDs: "1", listenPID: "self", fd: int(plain.Fd()), wantSubstr: "not a listening socket"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newTransportTestEnv(t)
			if tc.listenFDs == "" {
				// t.Setenv cannot unset a variable; the test process inherits
				// the parent environment, which normally has no LISTEN_FDS.
				old, had := os.LookupEnv("LISTEN_FDS")
				if err := os.Unsetenv("LISTEN_FDS"); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if had {
						_ = os.Setenv("LISTEN_FDS", old)
					}
				})
			} else {
				t.Setenv("LISTEN_FDS", tc.listenFDs)
			}
			switch tc.listenPID {
			case "":
				old, had := os.LookupEnv("LISTEN_PID")
				if err := os.Unsetenv("LISTEN_PID"); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if had {
						_ = os.Setenv("LISTEN_PID", old)
					}
				})
			case "self":
				t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
			default:
				t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()+1))
			}
			fd := tc.fd
			if fd == 0 {
				fd = int(env.file.Fd())
			}
			err := ServeSystemd(context.Background(), SystemdOptions{
				HostSocket:     env.hostSocket,
				ListenFD:       fd,
				HostSocketWait: 50 * time.Millisecond,
				ShutdownGrace:  time.Second,
				Logger:         slog.New(slog.DiscardHandler),
			}, transportServeOptions())
			if err == nil || !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("ServeSystemd = %v, want an error containing %q", err, tc.wantSubstr)
			}
		})
	}
}

func TestServeSystemdRequiresHostSocket(t *testing.T) {
	env := newTransportTestEnv(t)
	env.activation(t)
	missing := filepath.Join(env.dir, "missing.sock")
	started := time.Now()
	err := ServeSystemd(context.Background(), SystemdOptions{
		HostSocket:     missing,
		ListenFD:       int(env.file.Fd()),
		HostSocketWait: 100 * time.Millisecond,
		ShutdownGrace:  time.Second,
		Logger:         slog.New(slog.DiscardHandler),
	}, transportServeOptions())
	if err == nil || !strings.Contains(err.Error(), "did not appear") {
		t.Fatalf("ServeSystemd = %v, want the missing host socket error", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("the host socket wait took %s, want the configured 100ms", elapsed)
	}
}

func TestServeSystemdRequiresPlugin(t *testing.T) {
	env := newTransportTestEnv(t)
	env.activation(t)
	err := ServeSystemd(context.Background(), SystemdOptions{
		HostSocket: env.hostSocket,
		ListenFD:   int(env.file.Fd()),
	}, Options{})
	if err == nil || !strings.Contains(err.Error(), "Plugin is required") {
		t.Fatalf("ServeSystemd without a plugin = %v, want the Serve validation error", err)
	}
}

// TestServeSystemdChildFD3 proves the real systemd contract: the child process
// receives a listening socket as descriptor 3 and LISTEN_FDS=1. The child sets
// LISTEN_PID itself because the parent cannot know the child pid before exec.
func TestServeSystemdChildFD3(t *testing.T) {
	env := newTransportTestEnv(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestServeSystemdHelperProcess$", "-test.v")
	cmd.Env = append(withoutEnv(os.Environ(), "LISTEN_FDS", "LISTEN_PID"),
		"QWQ_TEST_SYSTEMD_HELPER=1",
		"LISTEN_FDS=1",
		"LISTEN_FDNAMES=plugin",
		"QWQ_HOST_SOCKET="+env.hostSocket,
	)
	cmd.ExtraFiles = []*os.File{env.file}
	var logs strings.Builder
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the helper: %v", err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})

	conn, err := waitForTransport(t, env.socket)
	if err != nil {
		t.Fatalf("the child did not serve: %v\n%s", err, logs.String())
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if resp, err := grpc_health_v1.NewHealthClient(conn).Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: ""}); err != nil {
		t.Fatalf("health: %v\n%s", err, logs.String())
	} else if resp.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatalf("health = %s, want SERVING\n%s", resp.GetStatus(), logs.String())
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM: %v", err)
	}
	waited = true
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the helper exited with %v\n%s", err, logs.String())
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("the helper did not exit on SIGTERM\n%s", logs.String())
	}
}

// withoutEnv returns env without the named variables. The child of the fd-3
// test sets LISTEN_PID itself, so an inherited value would be wrong.
func withoutEnv(env []string, names ...string) []string {
	out := make([]string, 0, len(env))
	for _, entry := range env {
		drop := false
		for _, name := range names {
			if strings.HasPrefix(entry, name+"=") {
				drop = true
				break
			}
		}
		if !drop {
			out = append(out, entry)
		}
	}
	return out
}

// TestServeSystemdHelperProcess is the child half of
// TestServeSystemdChildFD3. It is skipped unless the parent set the marker.
func TestServeSystemdHelperProcess(t *testing.T) {
	if os.Getenv("QWQ_TEST_SYSTEMD_HELPER") != "1" {
		t.Skip("only runs as the child process of TestServeSystemdChildFD3")
	}
	if err := os.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid())); err != nil {
		t.Fatalf("set LISTEN_PID: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := ServeSystemd(ctx, SystemdOptions{
		PluginID:      "test.plugin",
		ShutdownGrace: time.Second,
		Logger:        slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})),
	}, transportServeOptions()); err != nil {
		t.Fatalf("child ServeSystemd: %v", err)
	}
}
