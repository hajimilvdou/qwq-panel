// SPDX-License-Identifier: AGPL-3.0-only

package sshd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/qwq-panel/qwq/internal/capability/local"
	"github.com/qwq-panel/qwq/internal/sandbox"
)

// FileRepository 的路径是 root 启动配置；请求只能提供受控 SSH 字段。
type FileRepository struct {
	ConfigDir string
	TempDir   string
	Executor  local.Executor
	Trust     sandbox.TrustPolicy
	cached    map[string][]byte
}

func (r FileRepository) Read(ctx context.Context, match Match) (Snapshot, error) {
	if r.Executor == nil || !validMatch(match) {
		return Snapshot{}, errors.New("sshd: invalid repository configuration")
	}
	graph, err := r.graph(nil, false)
	if err != nil {
		return Snapshot{}, err
	}
	actual, err := r.native(ctx, local.Sshd, filepath.Join(r.ConfigDir, "sshd_config"), false, match)
	if err != nil {
		return Snapshot{}, err
	}
	defer clear(actual.Output)
	var snapshot Snapshot
	err = r.withCandidate(graph, func(path string) error {
		flattened, err := r.native(ctx, local.SshdTrace, path, true, match)
		if err != nil {
			return err
		}
		defer clear(flattened.Output)
		defer clear(flattened.Diagnostics)
		// 以真实主配置为权威，展开语义不等价时拒绝写入及来源猜测。
		if !sameEffective(actual.Output, flattened.Output) {
			return errors.New("sshd: Include expansion differs from native effective config")
		}
		snapshot, err = graph.snapshot(actual.Output, flattened.Diagnostics, path)
		return err
	})
	return snapshot, err
}

func (r FileRepository) Candidate(ctx context.Context, before Snapshot, raw []byte, match Match) (Snapshot, error) {
	if before.graph == nil || !before.Writable || len(raw) > 64<<10 || !validMatch(match) {
		return Snapshot{}, errors.New("sshd: invalid candidate snapshot")
	}
	if raw != nil {
		if _, err := parseDropIn(raw); err != nil {
			return Snapshot{}, err
		}
	}
	clone := r
	clone.cached = before.graph.files
	graph, err := clone.graph(raw, true)
	if err != nil {
		return Snapshot{}, err
	}
	var snapshot Snapshot
	err = r.withCandidate(graph, func(path string) error {
		checked, err := r.Executor.Execute(ctx, local.Sshd, []string{"-t", "-f", path}, nil)
		clear(checked.Output)
		clear(checked.Diagnostics)
		if err != nil || checked.ExitCode != 0 {
			return errors.New("sshd: native candidate validation failed")
		}
		result, err := r.native(ctx, local.SshdTrace, path, true, match)
		if err != nil {
			return err
		}
		defer clear(result.Output)
		defer clear(result.Diagnostics)
		actual, err := r.native(ctx, local.Sshd, path, false, match)
		if err != nil {
			return err
		}
		defer clear(actual.Output)
		if !sameEffective(actual.Output, result.Output) {
			return errors.New("sshd: trace changed effective config")
		}
		snapshot, err = graph.snapshot(actual.Output, result.Diagnostics, path)
		return err
	})
	return snapshot, err
}

// -ddd 自身会改变 LogLevel；只排除此诊断开关，其余字段必须逐字等价。
func sameEffective(a, b []byte) bool {
	filter := func(raw []byte) []byte {
		var out []byte
		for _, line := range bytes.Split(raw, []byte{'\n'}) {
			if bytes.HasPrefix(line, []byte("loglevel ")) {
				continue
			}
			out = append(out, line...)
			out = append(out, '\n')
		}
		return out
	}
	return bytes.Equal(filter(a), filter(b))
}

func (r FileRepository) Commit(raw []byte) error {
	if raw != nil {
		if _, err := parseDropIn(raw); err != nil {
			return err
		}
	}
	state := local.FileState{Directory: filepath.Join(r.ConfigDir, "sshd_config.d"), Name: "00-qwq.conf", Trust: r.Trust, Mode: 0644}
	return state.Commit(raw)
}

func (r FileRepository) native(ctx context.Context, tool local.Tool, path string, trace bool, match Match) (local.Result, error) {
	args := []string{"-T", "-f", path}
	if trace {
		args = append(args, "-ddd")
	}
	if match.User != "" || match.Address != "" {
		var conditions []string
		if match.User != "" {
			conditions = append(conditions, "user="+match.User)
		}
		if match.Address != "" {
			conditions = append(conditions, "addr="+match.Address, "host="+match.Address)
		}
		args = append(args, "-C", strings.Join(conditions, ","))
	}
	result, err := r.Executor.Execute(ctx, tool, args, nil)
	if err != nil || result.ExitCode != 0 {
		clear(result.Output)
		clear(result.Diagnostics)
		return local.Result{}, errors.New("sshd: native effective config is unavailable")
	}
	return result, nil
}

// withCandidate 只在可信运行目录创建随机私有配置，完成后按句柄清理。
func (r FileRepository) withCandidate(graph *configGraph, run func(string) error) error {
	root, err := r.Trust.Open(r.TempDir)
	if err != nil {
		return err
	}
	defer root.Close()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	name := "sshd-candidate-" + hex.EncodeToString(nonce[:])
	if err := root.Mkdir(name, 0700); err != nil {
		return err
	}
	defer func() { _ = root.RemoveAll(name) }()
	relative := filepath.Join(name, "sshd_config")
	file, err := root.OpenFile(relative, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(graph.flat.String()); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return run(filepath.Join(r.TempDir, relative))
}

func (g *configGraph) snapshot(output, diagnostics []byte, candidatePath string) (Snapshot, error) {
	settings, err := annotatedSettings(output, diagnostics, candidatePath, g.lines)
	if err != nil {
		return Snapshot{}, err
	}
	var ports []uint32
	for _, setting := range settings {
		if setting.Key != "port" {
			continue
		}
		port, err := strconv.ParseUint(setting.Value, 10, 16)
		if err != nil || port == 0 {
			return Snapshot{}, errors.New("sshd: invalid native port")
		}
		ports = append(ports, uint32(port))
	}
	if len(ports) == 0 {
		return Snapshot{}, errors.New("sshd: missing native SSH port")
	}
	content, exists := g.files[ownedDropIn]
	return Snapshot{Revision: g.revision(false), ExternalRevision: g.revision(true), Content: slices.Clone(content), Exists: exists, Writable: g.covered, Ports: uniquePorts(ports), Settings: settings, graph: g}, nil
}
