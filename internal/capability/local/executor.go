// SPDX-License-Identifier: AGPL-3.0-only

// Package local 提供能力 helper 共享的有界工具执行与可信文件状态。
package local

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/sandbox"
)

// Tool 是封闭的工具枚举；请求不能指定程序路径或通过 PATH 替换程序。
type Tool string

const (
	Nft         Tool = "nft"
	Sshd        Tool = "sshd"
	SshdTrace   Tool = "sshd-trace"
	Systemctl   Tool = "systemctl"
	Journalctl  Tool = "journalctl"
	Chpasswd    Tool = "chpasswd"
	SocketStats Tool = "ss"
)

const maxToolOutput = 512 << 10

// Result 的输出只供能力实现解析，不能写入日志。
type Result struct {
	Output []byte
	// Diagnostics 仅在显式 SshdTrace 中返回，仍有硬上限且不能记录日志。
	Diagnostics []byte
	ExitCode    int
}

func (Result) String() string   { return "local.Result{[REDACTED]}" }
func (Result) GoString() string { return "local.Result{[REDACTED]}" }

// Executor 是 fake executor 与实际受控程序之间的唯一接缝。参数由能力实现构造。
type Executor interface {
	Execute(context.Context, Tool, []string, []byte) (Result, error)
}

// ExecTools 不使用 shell，限制 deadline、stdout/stderr 和子进程退出等待。
type ExecTools struct{}

func (ExecTools) Execute(ctx context.Context, tool Tool, args []string, input []byte) (Result, error) {
	program, err := toolPath(tool)
	if err != nil {
		return Result{}, err
	}
	root, err := sandbox.OpenTrustedRoot(filepath.Dir(program))
	if err != nil {
		return Result{}, errors.New("capability: tool directory is not trusted")
	}
	info, err := root.Lstat(filepath.Base(program))
	root.Close()
	if err != nil || !info.Mode().IsRegular() || !ownedFile(info, 0) || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 {
		return Result{}, errors.New("capability: tool binary is not trusted")
	}
	if tool == SshdTrace {
		return runToolCaptured(ctx, program, args, input, true)
	}
	return runTool(ctx, program, args, input)
}

func toolPath(tool Tool) (string, error) {
	switch tool {
	case Nft:
		return "/usr/sbin/nft", nil
	case Sshd, SshdTrace:
		return "/usr/sbin/sshd", nil
	case Systemctl:
		return "/usr/bin/systemctl", nil
	case Journalctl:
		return "/usr/bin/journalctl", nil
	case Chpasswd:
		return "/usr/sbin/chpasswd", nil
	case SocketStats:
		return "/usr/bin/ss", nil
	default:
		return "", errors.New("capability: tool is not allowed")
	}
}

func runTool(ctx context.Context, program string, args []string, input []byte) (Result, error) {
	return runToolCaptured(ctx, program, args, input, false)
}

func runToolCaptured(ctx context.Context, program string, args []string, input []byte, capture bool) (Result, error) {
	if ctx == nil {
		return Result{}, errors.New("capability: context is required")
	}
	toolCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := toolCtx.Err(); err != nil {
		return Result{}, err
	}
	stdout := &boundedOutput{limit: maxToolOutput, cancel: cancel}
	stderr := &boundedOutput{limit: 8 << 10, cancel: cancel}
	if capture {
		stderr.limit = 128 << 10
	}
	command := exec.CommandContext(toolCtx, program, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin", "LC_ALL=C", "LANG=C"}
	command.WaitDelay = 250 * time.Millisecond
	command.Stdout, command.Stderr = stdout, stderr
	command.Stdin = bytes.NewReader(input)
	err := command.Run()
	defer clear(stderr.buffer.Bytes())
	if stdout.exceeded || stderr.exceeded {
		clear(stdout.buffer.Bytes())
		return Result{}, errors.New("capability: tool output exceeded the limit")
	}
	if err := ctx.Err(); err != nil {
		clear(stdout.buffer.Bytes())
		return Result{}, err
	}
	if err := toolCtx.Err(); err != nil {
		clear(stdout.buffer.Bytes())
		return Result{}, err
	}
	result := Result{Output: append([]byte(nil), stdout.buffer.Bytes()...)}
	if capture {
		result.Diagnostics = append([]byte(nil), stderr.buffer.Bytes()...)
	}
	clear(stdout.buffer.Bytes())
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			clear(result.Output)
			clear(result.Diagnostics)
			return Result{}, errors.New("capability: tool could not execute")
		}
		result.ExitCode = exit.ExitCode()
	}
	return result, nil
}

type boundedOutput struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	limit    int
	exceeded bool
	cancel   context.CancelFunc
}

func (b *boundedOutput) Write(raw []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buffer.Len()+len(raw) > b.limit {
		b.exceeded = true
		b.cancel()
		return len(raw), nil
	}
	return b.buffer.Write(raw)
}

// State 保存一个固定的能力资源。Lock 必须跨 helper 进程生效。
type State interface {
	Lock(context.Context) (func(), error)
	Read() ([]byte, bool, error)
	Commit([]byte) error
}

// FileState 的路径只来自 root 控制的启动配置，不能来自插件参数。
type FileState struct {
	Directory     string
	Name          string
	LockDirectory string
	LockName      string
	Trust         sandbox.TrustPolicy
	// Mode 非零时要求精确权限；默认 0644，事务与私有状态使用 0600。
	Mode fs.FileMode
}

func validName(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name && !bytes.ContainsAny([]byte(name), "/\\\x00")
}
