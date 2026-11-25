// SPDX-License-Identifier: AGPL-3.0-only

// Package xraybin 定位包内已核验核心，只接受固定参数与私有候选文件。
package xraybin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/sdk/coreapi"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// PinnedDigest 来自 X0 三方核验的 v26.11.9 发布二进制（linux/amd64）；升级必须重新完成供应链门禁。
const (
	PinnedDigest      = "e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d"
	PinnedDigestARM64 = "c2d1e66a130556d32089adcf38202fcb6f9027e41fb456cc2cda9a5fabdc093a"
)

// PinnedDigestFor 返回受信任官方目标架构（linux/amd64、linux/arm64）对应的锁定 Xray 核心摘要。
func PinnedDigestFor(target string) (string, bool) {
	switch target {
	case "linux/amd64":
		return PinnedDigest, true
	case "linux/arm64":
		return PinnedDigestARM64, true
	default:
		return "", false
	}
}

var (
	ErrBinary    = errors.New("xraybin: packaged binary is not trusted")
	ErrCandidate = errors.New("xraybin: candidate is not private")
	ErrPreflight = errors.New("xraybin: native preflight failed")
)

// Binary 的路径只能由安装目录和签名清单推导，调用方不能从配置提供程序路径。
type Binary struct{ path, root string }

// Locate 只从当前驱动的绝对可执行路径定位 bin/xray，忽略工作目录及 PATH。
func Locate() (*Binary, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, ErrBinary
	}
	target := "linux/" + runtime.GOARCH
	digest, ok := PinnedDigestFor(target)
	if !ok {
		return nil, ErrBinary
	}
	return locateForTarget(executable, target, digest, sandbox.TrustPolicy{})
}

func locate(executable, digest string, trust sandbox.TrustPolicy) (*Binary, error) {
	return locateForTarget(executable, "linux/amd64", digest, trust)
}

func locateForTarget(executable, target, digest string, trust sandbox.TrustPolicy) (*Binary, error) {
	if !filepath.IsAbs(executable) || filepath.Base(executable) != "plugin" || filepath.Base(filepath.Dir(executable)) != "bin" {
		return nil, ErrBinary
	}
	root := filepath.Dir(filepath.Dir(executable))
	r, err := trust.Open(root)
	if err != nil {
		return nil, ErrBinary
	}
	defer r.Close()
	for _, name := range []string{".", "bin"} {
		info, err := r.Lstat(name)
		if err != nil {
			return nil, ErrBinary
		}
		owner, ok := sandbox.FileOwner(info)
		if !ok || owner != trust.UID || !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 || info.Mode().Perm()&0o222 != 0 {
			return nil, ErrBinary
		}
	}
	plugin, err := openRegular(r, "bin/plugin", trust.UID, 128<<20, true)
	if err != nil {
		return nil, ErrBinary
	}
	_ = plugin.Close()
	f, err := openRegular(r, "manifest.json", trust.UID, manifest.MaxSize, false)
	if err != nil {
		return nil, ErrBinary
	}
	raw, err := io.ReadAll(io.LimitReader(f, manifest.MaxSize+1))
	_ = f.Close()
	if err != nil || len(raw) > manifest.MaxSize {
		return nil, ErrBinary
	}
	m, err := manifest.Parse(raw)
	if err != nil || (m.ID != "core.xray" && m.ID != "proxy.advanced") || m.Entrypoint != "bin/plugin" || m.Target != target || m.Files["bin/xray"] != "sha256:"+digest {
		return nil, ErrBinary
	}
	f, err = openRegular(r, "bin/xray", trust.UID, 128<<20, true)
	if err != nil {
		return nil, ErrBinary
	}
	defer f.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(f, (128<<20)+1))
	if err != nil || size > 128<<20 || hex.EncodeToString(hash.Sum(nil)) != digest {
		return nil, ErrBinary
	}
	return &Binary{path: filepath.Join(root, "bin", "xray"), root: root}, nil
}

func openRegular(root *os.Root, name string, uid int, limit int64, executable bool) (*os.File, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return nil, ErrBinary
	}
	owner, ok := sandbox.FileOwner(before)
	if !ok || owner != uid || !before.Mode().IsRegular() || before.Mode().Perm()&0o222 != 0 || before.Size() > limit || executable && before.Mode().Perm()&0o111 == 0 {
		return nil, ErrBinary
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, ErrBinary
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		_ = f.Close()
		return nil, ErrBinary
	}
	return f, nil
}

// Command 生成启动或预检命令。环境只包含核心所需项，不把宿主 token 传给子进程。
func (b *Binary) Command(ctx context.Context, candidate string, preflight bool) (*exec.Cmd, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if b == nil || b.path == "" || !privateCandidate(candidate) {
		return nil, ErrCandidate
	}
	args := []string{"run"}
	if preflight {
		args = append(args, "-test")
	}
	args = append(args, "-config", candidate)
	command := exec.CommandContext(ctx, b.path, args...)
	command.Dir = b.root
	command.Env = []string{"LANG=C", "LC_ALL=C", "XRAY_LOCATION_ASSET=" + filepath.Join(b.root, "bin")}
	command.WaitDelay = time.Second
	return command, nil
}

func privateCandidate(name string) bool {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name || filepath.Ext(name) != ".json" || strings.ContainsAny(name, "\x00\r\n") {
		return false
	}
	dir, err := os.Lstat(filepath.Dir(name))
	if err != nil || !dir.IsDir() || dir.Mode()&fs.ModeSymlink != 0 || dir.Mode().Perm()&0o077 != 0 {
		return false
	}
	owner, ok := sandbox.FileOwner(dir)
	if !ok || owner != os.Geteuid() {
		return false
	}
	info, err := os.Lstat(name)
	if err != nil {
		return false
	}
	owner, ok = sandbox.FileOwner(info)
	return ok && owner == os.Geteuid() && info.Mode().IsRegular() && info.Mode().Perm() == 0o600 && info.Size() <= coreapi.MaxSize
}

// Preflight 同时限制时间及输出。上游错误会回显私钥，捕获内容永不进入日志或 API。
func (b *Binary) Preflight(ctx context.Context, candidate string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command, err := b.Command(ctx, candidate, true)
	if err != nil {
		return err
	}
	stdout, stderr := &boundedOutput{data: make([]byte, 0, 8192)}, &boundedOutput{data: make([]byte, 0, 8192)}
	defer func() { clear(stdout.data); clear(stderr.data) }()
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrPreflight
	}
	if stdout.overflow || stderr.overflow {
		return ErrPreflight
	}
	return nil
}

// boundedOutput 继续排空超限输出，防止子进程因满管道阻塞；每个流最多保存 8 KiB。
type boundedOutput struct {
	data     []byte
	overflow bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	remaining := 8192 - len(b.data)
	if len(p) > remaining {
		b.overflow = true
	}
	b.data = append(b.data, p[:min(len(p), remaining)]...)
	return len(p), nil
}
