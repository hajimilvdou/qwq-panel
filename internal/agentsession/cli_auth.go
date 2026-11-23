// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// Persistent isolated credential homes & interactive device/OAuth login manager
// for external CLI agent cores (codex, claude-code, opencode).
//
// Security boundaries preserved:
//   - Credentials live exclusively under <DataDir>/agent-homes/<core> (mode 0700),
//     strictly isolated from host /root or other users' HOME directories.
//   - Every login subprocess runs with SanitizedEnv + process-group reaping and
//     a bounded 5-minute deadline.
//   - Plaintext tokens are never echoed in API responses, audit records, or logs.

const (
	cliLoginTimeout    = 5 * time.Minute
	maxLoginTailLines  = 16
	maxLoginTokenBytes = 64 << 10
	claudeSetupTokFile = ".setup-token"
)

// CoreAuthStatus describes installation and official login status for one
// external CLI core (GET /api/v1/agent/cores/auth).
type CoreAuthStatus struct {
	Core        CoreName        `json:"core"`
	DisplayName string          `json:"display_name"`
	Binary      string          `json:"binary"`
	Installed   bool            `json:"installed"`
	InstallHint string          `json:"install_hint"`
	LoggedIn    bool            `json:"logged_in"`
	AuthMethod  string          `json:"auth_method"` // oauth | token | none
	UpdatedAt   string          `json:"updated_at,omitempty"`
	ActiveLogin *CLILoginStatus `json:"active_login,omitempty"`
}

// CLILoginStatus captures an in-flight or recently completed official login
// attempt started from the panel UI.
type CLILoginStatus struct {
	State           string   `json:"state"` // pending | succeeded | failed | cancelled | expired
	VerificationURL string   `json:"verification_url,omitempty"`
	UserCode        string   `json:"user_code,omitempty"`
	Message         string   `json:"message,omitempty"`
	OutputTail      []string `json:"output_tail,omitempty"`
	StartedAt       string   `json:"started_at,omitempty"`
	UpdatedAt       string   `json:"updated_at,omitempty"`
}

// CLILoginInput carries POST /api/v1/agent/cores/{core}/login.
type CLILoginInput struct {
	// Mode selects "device" (launch official interactive/device-code OAuth CLI)
	// or "token" (import pasted OAuth setup token / auth JSON).
	Mode  string `json:"mode"`
	Token string `json:"token,omitempty"`
}

type coreAuthSpec struct {
	core        CoreName
	displayName string
	binary      string
	installHint string
	loginArgs   []string
	credFiles   []string // relative to core auth root
}

var externalAuthSpecs = []coreAuthSpec{
	{
		core:        CoreCodex,
		displayName: "OpenAI Codex CLI",
		binary:      "codex",
		installHint: "npm i -g @openai/codex",
		loginArgs:   []string{"login", "--device-auth"},
		credFiles:   []string{filepath.Join("config", "codex", "auth.json")},
	},
	{
		core:        CoreClaudeCode,
		displayName: "Claude Code (Anthropic)",
		binary:      "claude",
		installHint: "npm i -g @anthropic-ai/claude-code",
		loginArgs:   []string{"auth", "login"},
		credFiles: []string{
			filepath.Join("config", "claude", ".credentials.json"),
			filepath.Join("config", "claude", "credentials.json"),
			filepath.Join("config", "claude", claudeSetupTokFile),
		},
	},
	{
		core:        CoreOpencode,
		displayName: "OpenCode",
		binary:      "opencode",
		installHint: "curl -fsSL https://opencode.ai/install | bash",
		loginArgs:   []string{"auth", "login"},
		credFiles: []string{
			filepath.Join("data", "opencode", "auth.json"),
			filepath.Join("config", "opencode", "auth.json"),
		},
	},
}

func authSpecFor(core CoreName) (coreAuthSpec, bool) {
	for _, s := range externalAuthSpecs {
		if s.core == core {
			return s, true
		}
	}
	return coreAuthSpec{}, false
}

// CLIAuthManager tracks persistent per-core credential homes and active
// device-code login flows.
type CLIAuthManager struct {
	rootDir string

	mu     sync.Mutex
	active map[CoreName]*cliLoginRun
}

type cliLoginRun struct {
	mu     sync.Mutex
	status CLILoginStatus
	cancel context.CancelFunc
	done   chan struct{}
}

// NewCLIAuthManager builds a manager rooted at <dataDir>/agent-homes.
// When dataDir is empty (unit tests), a safe disabled manager is returned.
func NewCLIAuthManager(dataDir string) *CLIAuthManager {
	root := ""
	if strings.TrimSpace(dataDir) != "" {
		root = filepath.Join(dataDir, "agent-homes")
	}
	return &CLIAuthManager{
		rootDir: root,
		active:  make(map[CoreName]*cliLoginRun),
	}
}

// RootDir returns the persistent agent-homes directory (empty when unconfigured).
func (m *CLIAuthManager) RootDir() string {
	if m == nil {
		return ""
	}
	return m.rootDir
}

// CoreHomeDir returns the persistent 0700 directory for core, creating it on demand.
func (m *CLIAuthManager) CoreHomeDir(core CoreName) (string, error) {
	if m == nil || m.rootDir == "" {
		return "", problem.New(problem.Unavailable, "Persistent agent home directory is not configured on this host.")
	}
	if _, ok := authSpecFor(core); !ok {
		return "", problem.New(problem.NotFound, "Unsupported external CLI core %q.", core)
	}
	dir := filepath.Join(m.rootDir, string(core))
	for _, sub := range []string{
		"",
		"data",
		filepath.Join("data", "opencode"),
		"cache",
		filepath.Join("config", "codex"),
		filepath.Join("config", "claude"),
		filepath.Join("config", "opencode"),
	} {
		target := filepath.Join(dir, sub)
		if err := os.MkdirAll(target, 0o700); err != nil {
			return "", problem.New(problem.Internal, "Failed to initialize persistent auth directory.")
		}
		_ = os.Chmod(target, 0o700)
	}
	return dir, nil
}

// PersistentEnvFor returns environment overrides pointing core to its
// persistent credential directory (if logged in) plus any imported OAuth setup
// token. It returns nil when no persistent credentials exist.
func (m *CLIAuthManager) PersistentEnvFor(core CoreName) []string {
	if m == nil || m.rootDir == "" {
		return nil
	}
	spec, ok := authSpecFor(core)
	if !ok {
		return nil
	}
	homeDir := filepath.Join(m.rootDir, string(core))
	loggedIn, _, _ := inspectCoreCreds(homeDir, spec)
	if !loggedIn {
		return nil
	}
	env := coreAuthEnv(homeDir, core)
	if core == CoreClaudeCode {
		tokPath := filepath.Join(homeDir, "config", "claude", claudeSetupTokFile)
		if raw, err := os.ReadFile(tokPath); err == nil {
			if tok := strings.TrimSpace(string(raw)); tok != "" {
				env = append(env, "CLAUDE_CODE_OAUTH_TOKEN="+tok)
			}
		}
	}
	return env
}

func coreAuthEnv(homeDir string, core CoreName) []string {
	switch core {
	case CoreCodex:
		return []string{
			"CODEX_HOME=" + filepath.Join(homeDir, "config", "codex"),
			"XDG_CONFIG_HOME=" + filepath.Join(homeDir, "config"),
			"XDG_DATA_HOME=" + filepath.Join(homeDir, "data"),
		}
	case CoreClaudeCode:
		return []string{
			"CLAUDE_CONFIG_DIR=" + filepath.Join(homeDir, "config", "claude"),
			"XDG_CONFIG_HOME=" + filepath.Join(homeDir, "config"),
			"XDG_DATA_HOME=" + filepath.Join(homeDir, "data"),
		}
	case CoreOpencode:
		return []string{
			"OPENCODE_CONFIG_DIR=" + filepath.Join(homeDir, "config", "opencode"),
			"XDG_CONFIG_HOME=" + filepath.Join(homeDir, "config"),
			"XDG_DATA_HOME=" + filepath.Join(homeDir, "data"),
		}
	default:
		return nil
	}
}

func inspectCoreCreds(homeDir string, spec coreAuthSpec) (loggedIn bool, method string, updatedAt string) {
	if homeDir == "" {
		return false, "none", ""
	}
	for _, rel := range spec.credFiles {
		p := filepath.Join(homeDir, rel)
		st, err := os.Stat(p)
		if err != nil || st.IsDir() || st.Size() == 0 {
			continue
		}
		m := "oauth"
		if filepath.Base(rel) == claudeSetupTokFile {
			m = "token"
		}
		return true, m, st.ModTime().UTC().Format(time.RFC3339)
	}
	return false, "none", ""
}

// StatusList returns installation and login status for every supported CLI core.
func (m *CLIAuthManager) StatusList() []CoreAuthStatus {
	out := make([]CoreAuthStatus, 0, len(externalAuthSpecs))
	for _, spec := range externalAuthSpecs {
		out = append(out, m.Status(spec.core))
	}
	return out
}

// Status returns installation and login status for one core.
func (m *CLIAuthManager) Status(core CoreName) CoreAuthStatus {
	spec, ok := authSpecFor(core)
	if !ok {
		return CoreAuthStatus{Core: core, AuthMethod: "none"}
	}
	installed, _ := probeBinary(spec.binary)
	homeDir := ""
	if m != nil && m.rootDir != "" {
		homeDir = filepath.Join(m.rootDir, string(core))
	}
	loggedIn, method, updatedAt := inspectCoreCreds(homeDir, spec)
	st := CoreAuthStatus{
		Core:        spec.core,
		DisplayName: spec.displayName,
		Binary:      spec.binary,
		Installed:   installed,
		InstallHint: spec.installHint,
		LoggedIn:    loggedIn,
		AuthMethod:  method,
		UpdatedAt:   updatedAt,
	}
	if m != nil {
		m.mu.Lock()
		run := m.active[core]
		m.mu.Unlock()
		if run != nil {
			run.mu.Lock()
			cp := run.status
			cp.OutputTail = append([]string(nil), run.status.OutputTail...)
			run.mu.Unlock()
			st.ActiveLogin = &cp
		}
	}
	return st
}

// StartLogin initiates either official interactive/device-code login or direct
// OAuth/setup-token import for the specified external CLI core.
func (m *CLIAuthManager) StartLogin(ctx context.Context, core CoreName, in CLILoginInput) (CoreAuthStatus, error) {
	spec, ok := authSpecFor(core)
	if !ok {
		return CoreAuthStatus{}, problem.New(problem.NotFound, "Unsupported external CLI core %q.", core)
	}
	mode := strings.ToLower(strings.TrimSpace(in.Mode))
	if mode == "" {
		mode = "device"
	}
	switch mode {
	case "token":
		return m.importToken(core, spec, in.Token)
	case "device":
		return m.startDeviceLogin(core, spec)
	default:
		return CoreAuthStatus{}, problem.Validation(problem.Violation{
			Pointer: "/mode", Code: "INVALID", Message: "mode must be device or token.",
		})
	}
}

func (m *CLIAuthManager) importToken(core CoreName, spec coreAuthSpec, raw string) (CoreAuthStatus, error) {
	tok := strings.TrimSpace(raw)
	if tok == "" {
		return CoreAuthStatus{}, problem.Validation(problem.Violation{
			Pointer: "/token", Code: "REQUIRED", Message: "A token or auth JSON payload is required.",
		})
	}
	if len(tok) > maxLoginTokenBytes {
		return CoreAuthStatus{}, problem.Validation(problem.Violation{
			Pointer: "/token", Code: "too_long", Message: "Token payload exceeds 64 KiB.",
		})
	}
	homeDir, err := m.CoreHomeDir(core)
	if err != nil {
		return CoreAuthStatus{}, err
	}
	// Cancel any in-flight device login for this core.
	m.cancelActive(core, "cancelled")

	var target string
	var payload []byte
	trimmedJSON := json.Valid([]byte(tok)) && strings.HasPrefix(tok, "{")
	switch core {
	case CoreCodex:
		target = filepath.Join(homeDir, "config", "codex", "auth.json")
		if trimmedJSON {
			payload = []byte(tok + "\n")
		} else {
			payload, _ = json.MarshalIndent(map[string]string{"OPENAI_API_KEY": tok}, "", "  ")
			payload = append(payload, '\n')
		}
	case CoreClaudeCode:
		if trimmedJSON {
			target = filepath.Join(homeDir, "config", "claude", ".credentials.json")
			payload = []byte(tok + "\n")
		} else {
			target = filepath.Join(homeDir, "config", "claude", claudeSetupTokFile)
			payload = []byte(tok + "\n")
		}
	case CoreOpencode:
		target = filepath.Join(homeDir, "data", "opencode", "auth.json")
		if trimmedJSON {
			payload = []byte(tok + "\n")
		} else {
			payload, _ = json.MarshalIndent(map[string]any{"default": map[string]string{"type": "api", "key": tok}}, "", "  ")
			payload = append(payload, '\n')
		}
	}
	if err := writeSecretFileAtomic(target, payload); err != nil {
		return CoreAuthStatus{}, problem.New(problem.Internal, "Failed to persist credentials for %s.", core)
	}
	return m.Status(core), nil
}

func (m *CLIAuthManager) startDeviceLogin(core CoreName, spec coreAuthSpec) (CoreAuthStatus, error) {
	resolved, err := exec.LookPath(spec.binary)
	if err != nil {
		return CoreAuthStatus{}, problem.New(problem.Unavailable,
			"%s binary (%s) is not installed on this host. Install via `%s`.", spec.displayName, spec.binary, spec.installHint)
	}
	homeDir, err := m.CoreHomeDir(core)
	if err != nil {
		return CoreAuthStatus{}, err
	}
	m.cancelActive(core, "cancelled")

	tmpDir, err := os.MkdirTemp("", "qwq-cli-login-*")
	if err != nil {
		return CoreAuthStatus{}, problem.New(problem.Internal, "Failed to create login temp directory.")
	}
	_ = os.Chmod(tmpDir, 0o700)

	extraEnv := append([]string{
		"HOME=" + homeDir,
		"TMPDIR=" + tmpDir,
		"BROWSER=echo",
		"NO_BROWSER=1",
		"NO_COLOR=1",
	}, coreAuthEnv(homeDir, core)...)
	safeEnv, err := SanitizedEnv(extraEnv)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return CoreAuthStatus{}, err
	}

	loginCtx, cancel := context.WithTimeout(context.Background(), cliLoginTimeout)
	cmd := exec.Command(resolved, spec.loginArgs...)
	cmd.Env = safeEnv
	cmd.Dir = tmpDir
	configureChildProcess(cmd, nil, nil)

	pr, pw, err := os.Pipe()
	if err != nil {
		cancel()
		_ = os.RemoveAll(tmpDir)
		return CoreAuthStatus{}, problem.Wrap(err)
	}
	cmd.Stdout = pw
	cmd.Stderr = pw

	if err := cmd.Start(); err != nil {
		cancel()
		_ = pr.Close()
		_ = pw.Close()
		_ = os.RemoveAll(tmpDir)
		return CoreAuthStatus{}, problem.New(problem.Unavailable, "Failed to start %s login: %v", spec.binary, err)
	}
	_ = pw.Close()

	now := time.Now().UTC().Format(time.RFC3339)
	run := &cliLoginRun{
		status: CLILoginStatus{
			State:     "pending",
			Message:   fmt.Sprintf("已启动 %s 官方登录流程，正在等待授权链接或设备码…", spec.displayName),
			StartedAt: now,
			UpdatedAt: now,
		},
		cancel: cancel,
		done:   make(chan struct{}),
	}
	m.mu.Lock()
	m.active[core] = run
	m.mu.Unlock()

	go m.watchLoginProcess(loginCtx, run, cmd, pr, tmpDir, homeDir, spec)
	return m.Status(core), nil
}

var (
	ansiEscapeRe = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)
	loginURLRe   = regexp.MustCompile(`https://[^\s"'<>()]+`)
	deviceCodeRe = regexp.MustCompile(`\b([A-Z0-9]{4,5}-[A-Z0-9]{4,5})\b`)
	secretLeakRe = regexp.MustCompile(`\b(sk-[A-Za-z0-9_-]{12,}|eyJ[A-Za-z0-9._-]{20,})\b`)
)

func sanitizeLoginLine(line string) string {
	clean := ansiEscapeRe.ReplaceAllString(line, "")
	clean = strings.TrimSpace(clean)
	clean = secretLeakRe.ReplaceAllString(clean, "[REDACTED]")
	if len(clean) > 240 {
		clean = clean[:240] + "…"
	}
	return clean
}

func (m *CLIAuthManager) watchLoginProcess(
	ctx context.Context,
	run *cliLoginRun,
	cmd *exec.Cmd,
	out io.ReadCloser,
	tmpDir, homeDir string,
	spec coreAuthSpec,
) {
	defer func() {
		_ = out.Close()
		_ = os.RemoveAll(tmpDir)
		close(run.done)
	}()

	waitCh := make(chan error, 1)
	reaped := make(chan struct{})
	go func() {
		waitCh <- cmd.Wait()
		close(reaped)
	}()

	go func() {
		select {
		case <-ctx.Done():
			if cmd.Process != nil {
				_ = signalProcessGroup(cmd.Process.Pid, false)
				select {
				case <-reaped:
					return
				case <-time.After(500 * time.Millisecond):
				}
				_ = signalProcessGroup(cmd.Process.Pid, true)
			}
		case <-reaped:
		}
	}()

	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 0, 16<<10), 256<<10)
	for sc.Scan() {
		line := sanitizeLoginLine(sc.Text())
		if line == "" {
			continue
		}
		run.mu.Lock()
		if u := loginURLRe.FindString(line); u != "" && !strings.Contains(u, "127.0.0.1") && !strings.Contains(u, "localhost") {
			run.status.VerificationURL = strings.TrimRight(u, ".,;:")
		}
		if mCode := deviceCodeRe.FindStringSubmatch(line); len(mCode) > 1 {
			run.status.UserCode = mCode[1]
		}
		run.status.OutputTail = append(run.status.OutputTail, line)
		if len(run.status.OutputTail) > maxLoginTailLines {
			run.status.OutputTail = run.status.OutputTail[len(run.status.OutputTail)-maxLoginTailLines:]
		}
		if run.status.VerificationURL != "" && run.status.UserCode != "" {
			run.status.Message = "请点击下方授权链接并输入设备码完成官方登录"
		} else if run.status.VerificationURL != "" {
			run.status.Message = "请点击下方授权链接完成官方登录"
		}
		run.status.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		run.mu.Unlock()
	}

	waitErr := <-waitCh
	loggedIn, _, _ := inspectCoreCreds(homeDir, spec)

	run.mu.Lock()
	defer run.mu.Unlock()
	run.status.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if run.status.State == "cancelled" {
		return
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		run.status.State = "expired"
		run.status.Message = "登录超时（超过 5 分钟），请重新发起或使用粘贴 Token 模式。"
		return
	}
	if loggedIn || waitErr == nil {
		run.status.State = "succeeded"
		run.status.Message = fmt.Sprintf("%s 官方登录已完成。", spec.displayName)
		return
	}
	run.status.State = "failed"
	run.status.Message = fmt.Sprintf("%s 登录进程未完成；若无头服务器无法自动回调，可改用「粘贴 Setup Token / Auth JSON」方式导入凭据。", spec.displayName)
}

// Logout cancels any active login flow and deletes persisted credentials for core.
func (m *CLIAuthManager) Logout(core CoreName) (CoreAuthStatus, error) {
	spec, ok := authSpecFor(core)
	if !ok {
		return CoreAuthStatus{}, problem.New(problem.NotFound, "Unsupported external CLI core %q.", core)
	}
	m.cancelActive(core, "cancelled")
	if m != nil && m.rootDir != "" {
		homeDir := filepath.Join(m.rootDir, string(core))
		for _, rel := range spec.credFiles {
			_ = os.Remove(filepath.Join(homeDir, rel))
		}
	}
	m.mu.Lock()
	delete(m.active, core)
	m.mu.Unlock()
	return m.Status(core), nil
}

// Close cancels all active login flows during service shutdown.
func (m *CLIAuthManager) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	cores := make([]CoreName, 0, len(m.active))
	for c := range m.active {
		cores = append(cores, c)
	}
	m.mu.Unlock()
	for _, c := range cores {
		m.cancelActive(c, "cancelled")
	}
}

func (m *CLIAuthManager) cancelActive(core CoreName, finalState string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	run := m.active[core]
	m.mu.Unlock()
	if run == nil {
		return
	}
	run.mu.Lock()
	if run.status.State == "pending" {
		run.status.State = finalState
		run.status.Message = "已取消登录"
		run.status.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	run.mu.Unlock()
	run.cancel()
	select {
	case <-run.done:
	case <-time.After(2 * time.Second):
	}
}

func writeSecretFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".cred-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}
