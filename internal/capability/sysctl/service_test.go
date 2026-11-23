// SPDX-License-Identifier: AGPL-3.0-only

package sysctl

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/sandbox"
)

func TestSysctlAllowlistRejectsGlobalBrutalAndArbitraryKeys(t *testing.T) {
	dir := t.TempDir()
	var cmds [][]string
	svc := &Service{
		ManagedPath: filepath.Join(dir, "99-qwq-tcpfit.conf"),
		RunCmd: func(_ context.Context, _ string, args []string) ([]byte, error) {
			cmds = append(cmds, append([]string(nil), args...))
			return nil, nil
		},
	}

	// 1. Global tcp_congestion_control=brutal must be refused.
	brutalBody, _ := json.Marshal(applyParams{Values: map[string]string{
		"net.ipv4.tcp_congestion_control": "brutal",
	}})
	resp, err := svc.Run(t.Context(), sandbox.CapabilityRequest{Op: "sysctl.apply", ID: "proxy.advanced", ParamsJSON: brutalBody})
	if err != nil || resp.OK || resp.Code != "VALIDATION_FAILED" {
		t.Fatalf("expected global brutal to fail validation, got resp=%+v err=%v", resp, err)
	}

	// 2. Non-allowlisted kernel key must be refused.
	badKeyBody, _ := json.Marshal(applyParams{Values: map[string]string{
		"kernel.core_pattern": "|/bin/sh",
	}})
	resp, err = svc.Run(t.Context(), sandbox.CapabilityRequest{Op: "sysctl.apply", ID: "proxy.advanced", ParamsJSON: badKeyBody})
	if err != nil || resp.OK || resp.Code != "VALIDATION_FAILED" {
		t.Fatalf("expected non-allowlisted key to fail validation, got resp=%+v err=%v", resp, err)
	}

	// 3. Valid BBR + forwarding tuning succeeds atomically.
	okBody, _ := json.Marshal(applyParams{Values: map[string]string{
		"net.core.default_qdisc":          "fq",
		"net.ipv4.tcp_congestion_control": "bbr",
		"net.ipv4.ip_forward":             "1",
		"net.ipv6.conf.all.forwarding":    "1",
		"net.netfilter.nf_conntrack_max":  "262144",
	}})
	resp, err = svc.Run(t.Context(), sandbox.CapabilityRequest{Op: "sysctl.apply", ID: "proxy.advanced", ParamsJSON: okBody})
	if err != nil || !resp.OK {
		t.Fatalf("expected valid sysctl apply to succeed, got resp=%+v err=%v", resp, err)
	}
	raw, err := os.ReadFile(svc.ManagedPath)
	if err != nil || !strings.Contains(string(raw), "net.ipv4.tcp_congestion_control = bbr") {
		t.Fatalf("unexpected written sysctl file: err=%v body=%s", err, raw)
	}
	if len(cmds) != 1 || cmds[0][0] != "-p" {
		t.Fatalf("expected sysctl -p invocation, got %+v", cmds)
	}

	// 4. Rollback deletes managed file and restores allowlisted baseline.
	rbBody, _ := json.Marshal(rollbackParams{Baseline: map[string]string{
		"net.ipv4.tcp_congestion_control": "cubic",
		"kernel.core_pattern":             "ignored",
	}})
	resp, err = svc.Run(t.Context(), sandbox.CapabilityRequest{Op: "sysctl.rollback", ID: "proxy.advanced", ParamsJSON: rbBody})
	if err != nil || !resp.OK {
		t.Fatalf("expected rollback to succeed, got resp=%+v err=%v", resp, err)
	}
	if _, err := os.Stat(svc.ManagedPath); !os.IsNotExist(err) {
		t.Fatalf("expected managed sysctl file to be removed, stat err=%v", err)
	}
}

func TestSysctlIOErrorClassificationAndRestoreOnApplyFailure(t *testing.T) {
	// 1. OS I/O failure must return UNAVAILABLE, not VALIDATION_FAILED.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	badSvc := &Service{
		ManagedPath: filepath.Join(blocker, "nested", "99-qwq-tcpfit.conf"),
		RunCmd: func(_ context.Context, _ string, _ []string) ([]byte, error) {
			return nil, nil
		},
	}
	validBody, _ := json.Marshal(applyParams{Values: map[string]string{
		"net.ipv4.tcp_congestion_control": "bbr",
	}})
	resp, err := badSvc.Run(t.Context(), sandbox.CapabilityRequest{Op: "sysctl.apply", ID: "proxy.advanced", ParamsJSON: validBody})
	if err != nil || resp.OK || resp.Code != "UNAVAILABLE" {
		t.Fatalf("expected UNAVAILABLE on OS I/O error, got resp=%+v err=%v", resp, err)
	}

	// 2. Creates missing parent directory and removes new file when sysctl -p fails with no prior file.
	nestedPath := filepath.Join(t.TempDir(), "sysctl.d", "99-qwq-tcpfit.conf")
	failApply := true
	svc := &Service{
		ManagedPath: nestedPath,
		RunCmd: func(_ context.Context, _ string, _ []string) ([]byte, error) {
			if failApply {
				return []byte("sysctl: setting key failed"), errors.New("exit status 1")
			}
			return nil, nil
		},
	}
	resp, err = svc.Run(t.Context(), sandbox.CapabilityRequest{Op: "sysctl.apply", ID: "proxy.advanced", ParamsJSON: validBody})
	if err != nil || resp.OK || resp.Code != "UNAVAILABLE" {
		t.Fatalf("expected UNAVAILABLE when sysctl -p fails, got resp=%+v err=%v", resp, err)
	}
	if _, statErr := os.Stat(nestedPath); !os.IsNotExist(statErr) {
		t.Fatalf("expected newly created file to be removed after sysctl -p failure, stat err=%v", statErr)
	}

	// 3. Restores previous managed file content when subsequent sysctl -p fails.
	failApply = false
	firstBody, _ := json.Marshal(applyParams{Values: map[string]string{
		"net.ipv4.tcp_congestion_control": "cubic",
	}})
	resp, err = svc.Run(t.Context(), sandbox.CapabilityRequest{Op: "sysctl.apply", ID: "proxy.advanced", ParamsJSON: firstBody})
	if err != nil || !resp.OK {
		t.Fatalf("initial apply failed: resp=%+v err=%v", resp, err)
	}
	beforeRaw, err := os.ReadFile(nestedPath)
	if err != nil {
		t.Fatal(err)
	}

	failApply = true
	resp, err = svc.Run(t.Context(), sandbox.CapabilityRequest{Op: "sysctl.apply", ID: "proxy.advanced", ParamsJSON: validBody})
	if err != nil || resp.OK || resp.Code != "UNAVAILABLE" {
		t.Fatalf("expected UNAVAILABLE on second failed apply, got resp=%+v err=%v", resp, err)
	}
	afterRaw, err := os.ReadFile(nestedPath)
	if err != nil || string(afterRaw) != string(beforeRaw) {
		t.Fatalf("previous sysctl file not restored: got=%q want=%q err=%v", string(afterRaw), string(beforeRaw), err)
	}
}
