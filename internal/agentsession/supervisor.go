// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// External CLI Process Supervisor & Isolation Boundary (ADR-0028).
//
// Security & 1C1G guarantees:
//   - Strict environment allowlist: NEVER inherits host HOME, XDG_*, CODEX_HOME,
//     OPENCODE_CONFIG_DIR, DSH_HOME, CLAUDE_CONFIG_DIR, or host secret vars.
//   - Ephemeral 0700 isolated per-process HOME/XDG/TMPDIR created per turn and
//     removed on Close so an external CLI cannot read host configs or OAuth files.
//   - Unix process-group isolation (Setpgid: true) + explicit stderr pipe so
//     Close() sends SIGTERM -> grace -> SIGKILL to the ENTIRE process group and
//     never blocks indefinitely on descendants holding stderr open.
//   - Bounded concurrency semaphore (default 1 active OS CLI process on 1C1G).

const (
	defaultChildGracePeriod = 1500 * time.Millisecond
	hardReapTimeout         = 2 * time.Second
	maxStderrCaptureBytes   = 64 << 10
	maxExternalTurnEvents   = 1000
)

// allowedBaseEnvKeys strictly excludes host HOME / XDG / CLI config dirs so a
// child CLI process can never discover or read host credentials or databases.
var allowedBaseEnvKeys = map[string]struct{}{
	"PATH":        {},
	"LANG":        {},
	"LC_ALL":      {},
	"LC_CTYPE":    {},
	"TERM":        {},
	"TZ":          {},
	"NO_COLOR":    {},
	"HTTP_PROXY":  {},
	"HTTPS_PROXY": {},
	"NO_PROXY":    {},
	"http_proxy":  {},
	"https_proxy": {},
	"no_proxy":    {},
}

// forbiddenEnvSubstrings blocks accidental plaintext credential forwarding via
// user-supplied env entries.
var forbiddenEnvSubstrings = []string{
	"QWQ_MASTER",
	"QWQ_SESSION_SECRET",
	"QWQ_COOKIE",
	"PASSWORD",
	"PRIVATE_KEY",
}

// SanitizedEnv constructs a minimal, scrubbed environment for a child CLI.
// It never copies host HOME, XDG_*, or host CLI credential directories.
func SanitizedEnv(extra []string) ([]string, error) {
	out := make([]string, 0, len(allowedBaseEnvKeys)+len(extra))
	for _, kv := range os.Environ() {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if _, allow := allowedBaseEnvKeys[k]; allow {
			out = append(out, kv)
		}
	}
	for _, kv := range extra {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || strings.TrimSpace(k) == "" {
			return nil, problem.New(problem.ValidationFailed, "External CLI env entry must be KEY=VALUE.")
		}
		upper := strings.ToUpper(k)
		for _, bad := range forbiddenEnvSubstrings {
			if strings.Contains(upper, bad) {
				return nil, problem.New(problem.PermissionDenied,
					"External CLI env must not carry host secret variable %q.", k)
			}
		}
		out = append(out, kv)
	}
	// Deduplicate keeping the last value per key so explicit per-core persistent
	// auth overrides take precedence deterministically over default temp dirs.
	idxByKey := make(map[string]int, len(out))
	dedup := make([]string, 0, len(out))
	for _, kv := range out {
		k, _, _ := strings.Cut(kv, "=")
		if pos, exists := idxByKey[k]; exists {
			dedup[pos] = kv
		} else {
			idxByKey[k] = len(dedup)
			dedup = append(dedup, kv)
		}
	}
	return dedup, nil
}

// globalCLISem enforces the 1C1G concurrency ceiling (at most 1 active OS CLI
// child process by default unless a launcher overrides MaxConcurrent).
var globalCLISem = make(chan struct{}, 1)

// ChildProcess wraps one supervised external agent process with stdin/stdout
// pipes, bounded stderr capture, isolated temp home, and process-group cleanup.
type ChildProcess struct {
	cmd          *exec.Cmd
	stdin        io.WriteCloser
	stdout       io.ReadCloser
	stderrR      io.ReadCloser
	stderr       *boundedBuffer
	isolatedHome string
	releaseSem   func()
	doneCh       chan struct{}
	waitErr      error
	closeOnce    sync.Once
}

// ProcessLauncher abstracts starting an external CLI so unit tests can inject
// deterministic in-memory pipe doubles while production spawns isolated OS
// subprocesses.
type ProcessLauncher interface {
	Start(ctx context.Context, path string, args, env []string, workDir string) (*ChildProcess, error)
}

// OSProcessLauncher spawns real OS subprocesses with isolated 0700 home dirs,
// scrubbed environments, process-group reaping, and optional UID/GID drop.
type OSProcessLauncher struct {
	GracePeriod time.Duration
	RunAsUID    *uint32
	RunAsGID    *uint32
	// DisableConcurrencyGate lets unit tests run multiple tiny shell helpers
	// in parallel; production leaves this false (global 1-slot 1C1G gate).
	DisableConcurrencyGate bool
}

// Start launches the configured executable with clean pipes, isolated 0700
// HOME/XDG/TMPDIR, scrubbed env, and Unix process-group isolation.
func (l OSProcessLauncher) Start(ctx context.Context, path string, args, env []string, workDir string) (*ChildProcess, error) {
	if strings.TrimSpace(path) == "" {
		return nil, problem.New(problem.Unavailable, "External agent binary path is empty.")
	}
	resolved, err := exec.LookPath(path)
	if err != nil {
		return nil, problem.New(problem.Unavailable, "External agent binary %q is not installed on this host.", path)
	}

	releaseSem := func() {}
	if !l.DisableConcurrencyGate {
		select {
		case globalCLISem <- struct{}{}:
			var once sync.Once
			releaseSem = func() { once.Do(func() { <-globalCLISem }) }
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			return nil, problem.New(problem.Unavailable,
				"Another external CLI agent turn is already running on this host; wait for it to finish or use the native core.")
		}
	}

	isolatedHome, err := createIsolatedCLIHome()
	if err != nil {
		releaseSem()
		return nil, problem.New(problem.Internal, "Failed to create isolated CLI home directory.")
	}
	cleanupOnErr := func() {
		_ = os.RemoveAll(isolatedHome)
		releaseSem()
	}
	if err := chownIsolatedHome(isolatedHome, l.RunAsUID, l.RunAsGID); err != nil {
		cleanupOnErr()
		return nil, problem.New(problem.Internal, "Failed to assign isolated CLI home ownership.")
	}

	isolatedEnv := []string{
		"HOME=" + isolatedHome,
		"XDG_CONFIG_HOME=" + filepath.Join(isolatedHome, "config"),
		"XDG_DATA_HOME=" + filepath.Join(isolatedHome, "data"),
		"XDG_CACHE_HOME=" + filepath.Join(isolatedHome, "cache"),
		"TMPDIR=" + filepath.Join(isolatedHome, "tmp"),
		"CODEX_HOME=" + filepath.Join(isolatedHome, "config", "codex"),
		"OPENCODE_CONFIG_DIR=" + filepath.Join(isolatedHome, "config", "opencode"),
		"DSH_HOME=" + filepath.Join(isolatedHome, "config", "dsh"),
		"CLAUDE_CONFIG_DIR=" + filepath.Join(isolatedHome, "config", "claude"),
	}
	combinedExtra := make([]string, 0, len(isolatedEnv)+len(env))
	combinedExtra = append(combinedExtra, isolatedEnv...)
	combinedExtra = append(combinedExtra, env...)

	safeEnv, err := SanitizedEnv(combinedExtra)
	if err != nil {
		cleanupOnErr()
		return nil, err
	}

	cmd := exec.Command(resolved, args...)
	cmd.Env = safeEnv
	if workDir != "" {
		cmd.Dir = workDir
	} else {
		cmd.Dir = filepath.Join(isolatedHome, "workspace")
	}
	configureChildProcess(cmd, l.RunAsUID, l.RunAsGID)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		cleanupOnErr()
		return nil, problem.Wrap(err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		cleanupOnErr()
		return nil, problem.Wrap(err)
	}
	cmd.Stdout = stdoutW
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		_ = stdoutR.Close()
		_ = stdoutW.Close()
		cleanupOnErr()
		return nil, problem.Wrap(err)
	}
	cmd.Stderr = stderrW

	if err := cmd.Start(); err != nil {
		_ = stdoutR.Close()
		_ = stdoutW.Close()
		_ = stderrR.Close()
		_ = stderrW.Close()
		cleanupOnErr()
		return nil, problem.New(problem.Unavailable, "Failed to start external agent process: %v", err)
	}
	// Parent closes write ends immediately so EOF is observed when all children exit,
	// without cmd.Wait() racing to close stdoutR while unread output is still buffered.
	_ = stdoutW.Close()
	_ = stderrW.Close()

	stderrBuf := &boundedBuffer{limit: maxStderrCaptureBytes}
	go func() {
		_, _ = io.Copy(stderrBuf, stderrR)
		_ = stderrR.Close()
	}()

	cp := &ChildProcess{
		cmd:          cmd,
		stdin:        stdin,
		stdout:       stdoutR,
		stderrR:      stderrR,
		stderr:       stderrBuf,
		isolatedHome: isolatedHome,
		releaseSem:   releaseSem,
		doneCh:       make(chan struct{}),
	}
	go func() {
		cp.waitErr = cmd.Wait()
		close(cp.doneCh)
	}()

	// Propagate context cancellation directly to the entire process group.
	go func() {
		select {
		case <-ctx.Done():
			_ = cp.Close(l.GracePeriod)
		case <-cp.doneCh:
		}
	}()

	return cp, nil
}

func createIsolatedCLIHome() (string, error) {
	base, err := os.MkdirTemp("", "qwq-cli-home-*")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(base, 0o700); err != nil {
		_ = os.RemoveAll(base)
		return "", err
	}
	for _, sub := range []string{
		"workspace",
		"tmp",
		"data",
		"cache",
		filepath.Join("config", "codex"),
		filepath.Join("config", "opencode"),
		filepath.Join("config", "dsh"),
		filepath.Join("config", "claude"),
	} {
		if err := os.MkdirAll(filepath.Join(base, sub), 0o700); err != nil {
			_ = os.RemoveAll(base)
			return "", err
		}
	}
	return base, nil
}

// NewPipeProcess wraps an in-memory pipe pair for deterministic tests.
func NewPipeProcess(stdin io.WriteCloser, stdout io.ReadCloser) *ChildProcess {
	doneCh := make(chan struct{})
	close(doneCh)
	return &ChildProcess{
		stdin:      stdin,
		stdout:     stdout,
		stderr:     &boundedBuffer{limit: maxStderrCaptureBytes},
		releaseSem: func() {},
		doneCh:     doneCh,
	}
}

func (p *ChildProcess) Stdin() io.WriteCloser { return p.stdin }
func (p *ChildProcess) Stdout() io.ReadCloser { return p.stdout }
func (p *ChildProcess) StderrText() string    { return p.stderr.String() }
func (p *ChildProcess) IsolatedHome() string  { return p.isolatedHome }
func (p *ChildProcess) PID() int {
	if p.cmd != nil && p.cmd.Process != nil {
		return p.cmd.Process.Pid
	}
	return 0
}

// Close terminates the child AND its entire process group (SIGTERM -> grace ->
// SIGKILL), closes inherited pipe readers so Wait never stalls, waits bounded,
// removes the isolated temp home, and releases the concurrency slot.
func (p *ChildProcess) Close(grace time.Duration) error {
	if grace <= 0 {
		grace = defaultChildGracePeriod
	}
	var waitErr error
	p.closeOnce.Do(func() {
		defer func() {
			if p.isolatedHome != "" {
				_ = os.RemoveAll(p.isolatedHome)
			}
			if p.releaseSem != nil {
				p.releaseSem()
			}
		}()

		if p.stdin != nil {
			_ = p.stdin.Close()
		}
		if p.cmd == nil || p.cmd.Process == nil {
			select {
			case <-p.doneCh:
				waitErr = p.waitErr
			default:
			}
			return
		}

		pid := p.cmd.Process.Pid
		// Phase 1: polite SIGTERM to the whole process group.
		_ = signalProcessGroup(pid, false)

		select {
		case <-p.doneCh:
			waitErr = p.waitErr
		case <-time.After(grace):
			// Phase 2: SIGKILL the entire process group and break pipe holds.
			_ = signalProcessGroup(pid, true)
			_ = p.cmd.Process.Kill()
			if p.stderrR != nil {
				_ = p.stderrR.Close()
			}
			if p.stdout != nil {
				_ = p.stdout.Close()
			}
			select {
			case <-p.doneCh:
				waitErr = p.waitErr
			case <-time.After(hardReapTimeout):
				waitErr = errors.New("child process group reap timed out")
			}
		}

		// Ensure no stray descendants survive even if the main PID exited early,
		// waiting bounded until the process group is fully gone before releasing
		// the concurrency slot or removing isolatedHome.
		reapProcessGroup(pid, hardReapTimeout)
		if p.stderrR != nil {
			_ = p.stderrR.Close()
		}
		if p.stdout != nil {
			_ = p.stdout.Close()
		}
	})
	if errors.Is(waitErr, os.ErrProcessDone) {
		return nil
	}
	return waitErr
}

const defaultProviderSentinel = "__default__"

// ResolveCLIProviderIDWithDefault resolves the AI provider ID for an external
// CLI session: explicit "oauth" returns "" (never overrides OAuth login); an
// explicit provider_id wins; otherwise falls back to the host's default AI
// provider via defaultProviderFn (matching NativeCore's default fallback).
func ResolveCLIProviderIDWithDefault(
	ctx context.Context,
	authMode, explicitProviderID string,
	defaultProviderFn func(context.Context) (string, error),
) string {
	if strings.EqualFold(strings.TrimSpace(authMode), "oauth") {
		return ""
	}
	if p := strings.TrimSpace(explicitProviderID); p != "" {
		return p
	}
	if defaultProviderFn != nil {
		if defID, err := defaultProviderFn(ctx); err == nil {
			return strings.TrimSpace(defID)
		}
	}
	return ""
}

func isProviderCompatibleWithCore(core CoreName, epKind string) bool {
	kind := strings.TrimSpace(epKind)
	if kind == "" {
		kind = ProviderKindOpenAI
	}
	switch core {
	case CoreClaudeCode:
		return kind == ProviderKindAnthropic
	case CoreCodex, CoreDSH:
		return kind != ProviderKindAnthropic
	default:
		return true
	}
}

func defaultProviderIDLookupForCore(providers ProviderResolver, core CoreName) func(context.Context) (string, error) {
	if providers == nil {
		return nil
	}
	return func(ctx context.Context) (string, error) {
		ep, found, err := providers.ResolveProvider(ctx, "")
		if err != nil {
			return "", err
		}
		clear(ep.Key)
		if !found || !isProviderCompatibleWithCore(core, ep.Kind) {
			return "", nil
		}
		if strings.TrimSpace(ep.ID) != "" {
			return strings.TrimSpace(ep.ID), nil
		}
		if strings.TrimSpace(ep.BaseURL) != "" {
			return defaultProviderSentinel, nil
		}
		return "", nil
	}
}

// resolveCLIAuthEnvForSession resolves either global AI provider credentials
// (explicit or default fallback when no local OAuth login is active in auto
// mode) or persistent isolated OAuth credentials for an external CLI core.
func resolveCLIAuthEnvForSession(
	ctx context.Context,
	providers ProviderResolver,
	auth *CLIAuthManager,
	core CoreName,
	authMode, explicitProviderID, sessionID string,
) (extraEnv []string, ep ProviderEndpoint, found bool, cleanup func(), err error) {
	noop := func() {}
	mode := strings.ToLower(strings.TrimSpace(authMode))
	explicit := strings.TrimSpace(explicitProviderID)

	// In auto mode (auth_mode=="" && provider_id==""), respect an active
	// persistent official OAuth login before falling back to the default provider.
	if mode == "" && explicit == "" && auth != nil {
		if oauthEnv := auth.PersistentEnvFor(core); len(oauthEnv) > 0 {
			return oauthEnv, ProviderEndpoint{}, false, noop, nil
		}
	}

	resolvedID := ResolveCLIProviderIDWithDefault(ctx, mode, explicit, defaultProviderIDLookupForCore(providers, core))
	if resolvedID != "" {
		pEnv, pEp, pFound, pCleanup, pErr := ResolveProviderForCLI(ctx, providers, resolvedID, core)
		if pErr != nil {
			return nil, ProviderEndpoint{}, false, noop, pErr
		}
		if !pFound {
			if explicit != "" {
				return nil, ProviderEndpoint{}, false, noop, problem.New(problem.Unavailable,
					"The AI provider config.provider_id names no longer exists; pick another one or ask an administrator.")
			}
			if mode == "provider" {
				return nil, ProviderEndpoint{}, false, noop, problem.New(problem.Unavailable,
					"No compatible global AI provider is configured for this external CLI core.")
			}
		} else {
			if sessionID != "" && auth != nil {
				if stEnv := auth.SessionStateEnvFor(core, sessionID); len(stEnv) > 0 {
					pEnv = append(stEnv, pEnv...)
				}
			}
			return pEnv, pEp, true, pCleanup, nil
		}
	}
	if mode == "provider" {
		return nil, ProviderEndpoint{}, false, noop, problem.New(problem.Unavailable,
			"No compatible global AI provider is configured for this external CLI core.")
	}
	if auth != nil {
		return auth.PersistentEnvFor(core), ProviderEndpoint{}, false, noop, nil
	}
	return nil, ProviderEndpoint{}, false, noop, nil
}

// ResolveProviderEnv safely resolves a global AIProvider's API key into child
// CLI environment variables when a session explicitly configures provider_id.
// The plaintext key never touches config_json, logs or errors, and cleanup
// scrubs the temporary slice on return.
func ResolveProviderEnv(ctx context.Context, providers ProviderResolver, providerID string, core CoreName) ([]string, func(), error) {
	env, _, _, cleanup, err := ResolveProviderForCLI(ctx, providers, providerID, core)
	return env, cleanup, err
}

// ResolveProviderForCLI resolves provider_id into child CLI environment
// variables AND returns the resolved ProviderEndpoint metadata (model,
// reasoning_effort, max_context_tokens, kind) so adapters inherit provider
// defaults seamlessly.
func ResolveProviderForCLI(ctx context.Context, providers ProviderResolver, providerID string, core CoreName) ([]string, ProviderEndpoint, bool, func(), error) {
	noop := func() {}
	if providers == nil || providerID == "" {
		return nil, ProviderEndpoint{}, false, noop, nil
	}
	lookupID := providerID
	if lookupID == defaultProviderSentinel {
		lookupID = ""
	}
	ep, found, err := providers.ResolveProvider(ctx, lookupID)
	if err != nil {
		return nil, ProviderEndpoint{}, false, noop, problem.From(err)
	}
	if !found {
		return nil, ProviderEndpoint{}, false, noop, nil
	}
	cleanup := func() { clear(ep.Key) }
	var env []string
	switch {
	case core == CoreDSH:
		if len(ep.Key) > 0 {
			env = append(env, "DEEPSEEK_API_KEY="+string(ep.Key))
		}
		if ep.BaseURL != "" {
			env = append(env, "DEEPSEEK_BASE_URL="+ep.BaseURL)
		}
	case core == CoreClaudeCode || (core == CoreOpencode && ep.Kind == ProviderKindAnthropic):
		if len(ep.Key) > 0 {
			env = append(env, "ANTHROPIC_API_KEY="+string(ep.Key))
		}
		if ep.BaseURL != "" {
			base := ep.BaseURL
			if core == CoreClaudeCode {
				base = normalizeAnthropicCLIBaseURL(base)
			}
			env = append(env, "ANTHROPIC_BASE_URL="+base)
		}
	default:
		if len(ep.Key) > 0 {
			env = append(env, "OPENAI_API_KEY="+string(ep.Key))
		}
		if ep.BaseURL != "" {
			env = append(env, "OPENAI_BASE_URL="+ep.BaseURL)
		}
	}
	return env, ep, true, cleanup, nil
}

// boundedBuffer retains at most limit bytes so verbose stderr never OOMs 1C1G.
type boundedBuffer struct {
	mu    sync.Mutex
	limit int
	buf   []byte
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	rem := b.limit - len(b.buf)
	if rem > 0 {
		if len(p) > rem {
			b.buf = append(b.buf, p[:rem]...)
		} else {
			b.buf = append(b.buf, p...)
		}
	}
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}
