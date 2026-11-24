// SPDX-License-Identifier: AGPL-3.0-only

package firewall

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/qwq-panel/qwq/internal/capability/local"
	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/sandbox"
)

type guardExecutor struct{ sshOutput []byte }

func (e guardExecutor) Execute(_ context.Context, tool local.Tool, _ []string, _ []byte) (local.Result, error) {
	if tool == local.Systemctl {
		return local.Result{Output: []byte("Id=ssh.socket\nMainPID=0\nActiveState=active\nListen=[::]:2023 (Stream)\n")}, nil
	}
	return local.Result{Output: append([]byte(nil), e.sshOutput...)}, nil
}

type runtimeGuardExecutor struct{}

func (runtimeGuardExecutor) Execute(_ context.Context, tool local.Tool, _ []string, _ []byte) (local.Result, error) {
	if tool == local.Systemctl {
		return local.Result{Output: []byte("MainPID=501\nId=ssh.service\nActiveState=active\n\nListen=[::]:22 (Stream)\nListen=0.0.0.0:2233 (Stream)\nId=ssh.socket\nMainPID=0\nActiveState=active\n")}, nil
	}
	return local.Result{Output: []byte("LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:((\"sshd\",pid=501,fd=3))\nLISTEN 0 128 0.0.0.0:9999 0.0.0.0:* users:((\"sshd\",pid=999,fd=4))\n")}, nil
}

type inactiveSocketExecutor struct{}

func (inactiveSocketExecutor) Execute(_ context.Context, tool local.Tool, _ []string, _ []byte) (local.Result, error) {
	if tool == local.Systemctl {
		return local.Result{Output: []byte("Id=ssh.service\nMainPID=501\nActiveState=active\n\nId=ssh.socket\nMainPID=0\nActiveState=inactive\nListen=0.0.0.0:9999 (Stream)\n")}, nil
	}
	return local.Result{Output: []byte("LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:((\"sshd\",pid=501,fd=3))\nLISTEN 0 128 0.0.0.0:9999 0.0.0.0:* users:((\"sshd\",pid=999,fd=4))\n")}, nil
}

func TestInactiveSocketAndForgedProcessAreNotLiveSSH(t *testing.T) {
	ports, err := (SystemGuard{Executor: inactiveSocketExecutor{}}).RuntimeSSHPorts(t.Context())
	if err != nil || len(ports) != 1 || ports[0] != 2222 {
		t.Fatal("inactive socket or forged process counted as an active SSH listener")
	}
}

func TestRuntimeSSHPortsBindProcessIdentity(t *testing.T) {
	g := SystemGuard{Executor: runtimeGuardExecutor{}}
	ports, err := g.RuntimeSSHPorts(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var old, current, socket bool
	for _, port := range ports {
		if port == 22 {
			old = true
		}
		if port == 2222 {
			current = true
		}
		if port == 2233 {
			socket = true
		}
		if port == 9999 {
			t.Fatal("a forged process name became a preserved port")
		}
	}
	if !old || !current || !socket {
		t.Fatal("configured socket or actual daemon listener was omitted")
	}
}

func TestSystemGuardManagementPortsAndMultilineConfig(t *testing.T) {
	cfg := config.Config{HTTP: config.HTTP{Listen: "0.0.0.0:8443", PublicOrigins: []string{"https://panel.example.invalid", "https://panel.example.invalid:9443"}}}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	guard := SystemGuard{Config: &fakeState{raw: raw}, Executor: guardExecutor{sshOutput: []byte("port 2022\nport 22\npasswordauthentication yes\n")}}
	ports, err := guard.PreservedPorts(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []uint32{22, 443, 2022, 2023, 8443, 9443} {
		if !slices.Contains(ports, want) {
			t.Fatalf("required management port %d missing from %v", want, ports)
		}
	}
	// Loopback bootstrap listen must not punch a hole on public firewall while keeping PublicOrigins + SSH.
	loopCfg := config.Config{HTTP: config.HTTP{Listen: "127.0.0.1:8443", PublicOrigins: []string{"https://panel.example.invalid"}}}
	loopRaw, _ := json.Marshal(loopCfg)
	loopGuard := SystemGuard{Config: &fakeState{raw: loopRaw}, Executor: guardExecutor{sshOutput: []byte("port 22\n")}}
	loopPreserved, err := loopGuard.PreservedPorts(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(loopPreserved, 8443) {
		t.Fatalf("loopback panel port 8443 must not be opened on public firewall: %v", loopPreserved)
	}
	if !slices.Contains(loopPreserved, 22) || !slices.Contains(loopPreserved, 443) {
		t.Fatalf("expected SSH 22 and origin 443 preserved: %v", loopPreserved)
	}
	// Authoritative panel-port.json overrides static qwq.json port and respects loopback listen_host.
	tmpRoot := t.TempDir()
	hintDir := filepath.Join(tmpRoot, "var", "lib", "qwq-capability")
	if err := os.MkdirAll(hintDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hintDir, "panel-port.json"), []byte(`{"port":45001,"listen_host":"0.0.0.0","updated_at":"2026-11-24T00:00:00Z"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	authGuard := SystemGuard{
		Config:   &fakeState{raw: raw},
		Executor: guardExecutor{sshOutput: []byte("port 22\n")},
		RootPath: tmpRoot,
		Trust:    sandbox.TrustPolicy{UID: os.Geteuid()},
	}
	authPorts, err := authGuard.PreservedPorts(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(authPorts, 45001) || slices.Contains(authPorts, 8443) {
		t.Fatalf("panel-port.json should replace static 8443 with 45001, got %v", authPorts)
	}
	if err := os.WriteFile(filepath.Join(hintDir, "panel-port.json"), []byte(`{"port":45001,"listen_host":"127.0.0.1","updated_at":"2026-11-24T00:00:00Z"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	authLoopPorts, err := authGuard.PreservedPorts(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(authLoopPorts, 45001) || slices.Contains(authLoopPorts, 8443) {
		t.Fatalf("loopback panel-port.json must not expose panel port publicly, got %v", authLoopPorts)
	}
	for _, listen := range []string{"127.0.0.1:0", "127.0.0.1:65536", "invalid"} {
		if _, err := ManagementPorts(config.HTTP{Listen: listen}); err == nil {
			t.Fatal("invalid listener accepted")
		}
	}
	if _, err := ManagementPorts(config.HTTP{Listen: "127.0.0.1:8443", PublicOrigins: []string{"https://user:password@example.invalid"}}); err == nil {
		t.Fatal("credentials in an origin accepted")
	}
}
