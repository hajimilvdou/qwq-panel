// SPDX-License-Identifier: AGPL-3.0-only

// Package sysctl provides an allowlisted privileged kernel tuning capability
// for qwq-capability (verbs: sysctl.apply, sysctl.rollback).
// It strictly forbids setting global tcp_congestion_control=brutal (which would
// throttle all non-setsockopt connections to ~1 Mbps) and forbids any security-
// sensitive kernel keys outside the explicit allowlist.
package sysctl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/qwq-panel/qwq/internal/sandbox"
)

const DefaultManagedSysctlPath = "/etc/sysctl.d/99-qwq-tcpfit.conf"

// AllowedSysctlValidators strictly allowlists network-tuning sysctl keys and
// their safe value domains. Global tcp_congestion_control=brutal is explicitly
// refused; per-socket TCP Brutal must only be enabled via TCP_BRUTAL_PARAMS.
var AllowedSysctlValidators = map[string]func(string) error{
	"net.core.default_qdisc": func(v string) error {
		switch v {
		case "fq", "fq_codel", "cake", "pfifo_fast":
			return nil
		default:
			return fmt.Errorf("disallowed qdisc %q", v)
		}
	},
	"net.ipv4.tcp_congestion_control": func(v string) error {
		if v == "brutal" {
			return errors.New("refusing global tcp_congestion_control=brutal (must only be enabled per-socket via TCP_BRUTAL_PARAMS)")
		}
		switch v {
		case "bbr", "cubic", "reno":
			return nil
		default:
			return fmt.Errorf("disallowed congestion control %q", v)
		}
	},
	"net.core.rmem_max":                  validateIntRange(262144, 134217728),
	"net.core.wmem_max":                  validateIntRange(262144, 134217728),
	"net.ipv4.tcp_rmem":                  validateTripleInt(4096, 134217728),
	"net.ipv4.tcp_wmem":                  validateTripleInt(4096, 134217728),
	"net.ipv4.tcp_mtu_probing":           validateIntRange(0, 2),
	"net.ipv4.tcp_slow_start_after_idle": validateIntRange(0, 1),
	"net.ipv4.tcp_notsent_lowat":         validateIntRange(16384, 4194304),
	"net.ipv4.ip_forward":                validateIntRange(0, 1),
	"net.ipv6.conf.all.forwarding":       validateIntRange(0, 1),
	"net.netfilter.nf_conntrack_max":     validateIntRange(16384, 2097152),
}

// CommandRunner executes sysctl commands (injectable for deterministic unit tests).
type CommandRunner func(ctx context.Context, name string, args []string) ([]byte, error)

// Service handles sysctl.apply and sysctl.rollback capability requests.
type Service struct {
	ManagedPath string
	SysctlPath  string
	RunCmd      CommandRunner
	mu          sync.Mutex
}

// NewService constructs the default privileged sysctl capability service.
func NewService() *Service {
	return &Service{
		ManagedPath: DefaultManagedSysctlPath,
		SysctlPath:  "/sbin/sysctl",
	}
}

type applyParams struct {
	Values map[string]string `json:"values"`
}

type rollbackParams struct {
	Baseline map[string]string `json:"baseline,omitempty"`
}

// validationError distinguishes input validation failures from OS / sysctl I/O errors.
type validationError struct {
	err error
}

func (e validationError) Error() string { return e.err.Error() }
func (e validationError) Unwrap() error { return e.err }

// Run dispatches sysctl.apply and sysctl.rollback capability verbs.
func (s *Service) Run(ctx context.Context, req sandbox.CapabilityRequest) (sandbox.CapabilityResponse, error) {
	if sandbox.ValidateCapabilityRequest(req) != nil || len(req.Secret) != 0 {
		return sandbox.CapabilityResponse{Code: "VALIDATION_FAILED", Error: "invalid sysctl capability request"}, nil
	}
	params := req.ParamsJSON
	if len(params) == 0 {
		params = []byte("{}")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	switch req.Op {
	case "sysctl.apply":
		var p applyParams
		if sandbox.DecodeHelperDocument(params, &p) != nil {
			return sandbox.CapabilityResponse{Code: "VALIDATION_FAILED", Error: "invalid sysctl.apply parameters"}, nil
		}
		if err := s.ApplyManagedSysctl(ctx, p.Values); err != nil {
			code := "UNAVAILABLE"
			var ve validationError
			if errors.As(err, &ve) {
				code = "VALIDATION_FAILED"
			}
			return sandbox.CapabilityResponse{Code: code, Error: err.Error()}, nil
		}
		raw, _ := json.Marshal(map[string]any{"applied": true, "path": s.managedPath()})
		return sandbox.CapabilityResponse{OK: true, ResultJSON: raw}, nil

	case "sysctl.rollback":
		var p rollbackParams
		if sandbox.DecodeHelperDocument(params, &p) != nil {
			return sandbox.CapabilityResponse{Code: "VALIDATION_FAILED", Error: "invalid sysctl.rollback parameters"}, nil
		}
		if err := s.RollbackManagedSysctl(ctx, p.Baseline); err != nil {
			return sandbox.CapabilityResponse{Code: "UNAVAILABLE", Error: err.Error()}, nil
		}
		raw, _ := json.Marshal(map[string]any{"rolled_back": true})
		return sandbox.CapabilityResponse{OK: true, ResultJSON: raw}, nil

	default:
		return sandbox.CapabilityResponse{Code: "UNIMPLEMENTED", Error: "unsupported sysctl verb"}, nil
	}
}

func (s *Service) managedPath() string {
	if s.ManagedPath != "" {
		return s.ManagedPath
	}
	return DefaultManagedSysctlPath
}

func (s *Service) sysctlBin() string {
	if s.SysctlPath != "" {
		return s.SysctlPath
	}
	return "/sbin/sysctl"
}

func (s *Service) exec(ctx context.Context, args []string) ([]byte, error) {
	if s.RunCmd != nil {
		return s.RunCmd(ctx, s.sysctlBin(), args)
	}
	return exec.CommandContext(ctx, s.sysctlBin(), args...).CombinedOutput()
}

// ValidateSysctlMap verifies every key/value pair against the strict allowlist.
func ValidateSysctlMap(kv map[string]string) ([]string, error) {
	if len(kv) == 0 || len(kv) > 32 {
		return nil, validationError{err: errors.New("sysctl: invalid parameter count")}
	}
	keys := make([]string, 0, len(kv))
	for k, v := range kv {
		validator, ok := AllowedSysctlValidators[k]
		if !ok {
			return nil, validationError{err: fmt.Errorf("sysctl: key %q is not in host capability allowlist", k)}
		}
		cleanVal := strings.TrimSpace(v)
		if strings.ContainsAny(cleanVal, "\r\n;#") {
			return nil, validationError{err: fmt.Errorf("sysctl: invalid characters in value for %q", k)}
		}
		if err := validator(cleanVal); err != nil {
			return nil, validationError{err: fmt.Errorf("sysctl %s: %w", k, err)}
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}

// ApplyManagedSysctl validates all key/value pairs, atomically replaces the
// managed sysctl.d drop-in via CreateTemp+Sync+Rename, and applies it. If
// `sysctl -p` fails, any previous drop-in is restored (or the newly written
// file is removed when none existed).
func (s *Service) ApplyManagedSysctl(ctx context.Context, kv map[string]string) error {
	keys, err := ValidateSysctlMap(kv)
	if err != nil {
		return err
	}

	var sb strings.Builder
	sb.WriteString("# Managed by qwq-capability (system.sysctl.tune). Do not edit manually.\n")
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteString(" = ")
		sb.WriteString(strings.TrimSpace(kv[k]))
		sb.WriteByte('\n')
	}

	target := s.managedPath()
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("sysctl: mkdir %s: %w", dir, err)
	}

	prevBytes, prevErr := os.ReadFile(target)
	hadPrev := prevErr == nil
	if prevErr != nil && !errors.Is(prevErr, os.ErrNotExist) {
		return fmt.Errorf("sysctl: read previous managed file: %w", prevErr)
	}

	if err := writeSysctlAtomic(dir, target, []byte(sb.String())); err != nil {
		return err
	}

	out, err := s.exec(ctx, []string{"-p", target})
	if err != nil {
		if hadPrev {
			_ = writeSysctlAtomic(dir, target, prevBytes)
		} else {
			_ = os.Remove(target)
		}
		return fmt.Errorf("sysctl -p failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func writeSysctlAtomic(dir, target string, data []byte) error {
	tmp, err := os.CreateTemp(dir, ".99-qwq-tcpfit.*.tmp")
	if err != nil {
		return fmt.Errorf("sysctl: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, target); err != nil {
		return fmt.Errorf("sysctl: atomic rename: %w", err)
	}
	return nil
}

// RollbackManagedSysctl removes the managed drop-in and restores allowlisted baseline values.
func (s *Service) RollbackManagedSysctl(ctx context.Context, baseline map[string]string) error {
	_ = os.Remove(s.managedPath())
	if len(baseline) == 0 {
		return nil
	}
	keys := make([]string, 0, len(baseline))
	for k := range baseline {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		validator, ok := AllowedSysctlValidators[k]
		if !ok {
			continue
		}
		cleanVal := strings.TrimSpace(baseline[k])
		if strings.ContainsAny(cleanVal, "\r\n;#") || validator(cleanVal) != nil {
			continue
		}
		_, _ = s.exec(ctx, []string{"-w", k + "=" + cleanVal})
	}
	return nil
}

// ApplyManagedSysctl applies validated network sysctl tuning using the default service.
func ApplyManagedSysctl(kv map[string]string) error {
	return NewService().ApplyManagedSysctl(context.Background(), kv)
}

// RollbackManagedSysctl rolls back managed network sysctl tuning using the default service.
func RollbackManagedSysctl(baseline map[string]string) error {
	return NewService().RollbackManagedSysctl(context.Background(), baseline)
}

func validateIntRange(minVal, maxVal int64) func(string) error {
	return func(s string) error {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n < minVal || n > maxVal {
			return fmt.Errorf("value %q outside [%d, %d]", s, minVal, maxVal)
		}
		return nil
	}
}

func validateTripleInt(minVal, maxVal int64) func(string) error {
	return func(s string) error {
		fields := strings.Fields(s)
		if len(fields) != 3 {
			return errors.New("expected 3 space-separated integers")
		}
		var prev int64
		for i, f := range fields {
			n, err := strconv.ParseInt(f, 10, 64)
			if err != nil || n < minVal || n > maxVal || (i > 0 && n < prev) {
				return fmt.Errorf("invalid triple %q", s)
			}
			prev = n
		}
		return nil
	}
}
