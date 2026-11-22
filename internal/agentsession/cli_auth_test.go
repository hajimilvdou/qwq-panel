// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

func TestCLIAuthManagerTokenImportAndLogout(t *testing.T) {
	dir := t.TempDir()
	mgr := NewCLIAuthManager(dir)
	defer mgr.Close()

	// Initially none of the external CLI cores have persisted credentials.
	list := mgr.StatusList()
	if len(list) != 3 {
		t.Fatalf("StatusList len = %d, want 3", len(list))
	}
	for _, st := range list {
		if st.LoggedIn || st.AuthMethod != "none" {
			t.Fatalf("unexpected initial auth status for %s: %+v", st.Core, st)
		}
	}

	// 1. Import Claude Code setup token -> persists 0600 file and exports CLAUDE_CODE_OAUTH_TOKEN.
	st, err := mgr.StartLogin(context.Background(), CoreClaudeCode, CLILoginInput{
		Mode:  "token",
		Token: "sk-ant-oat01-demo-token-123456",
	})
	if err != nil {
		t.Fatalf("StartLogin claude token: %v", err)
	}
	if !st.LoggedIn || st.AuthMethod != "token" {
		t.Fatalf("claude status after token import = %+v", st)
	}
	env := mgr.PersistentEnvFor(CoreClaudeCode)
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "CLAUDE_CONFIG_DIR="+filepath.Join(dir, "agent-homes", "claude-code", "config", "claude")) {
		t.Fatalf("missing CLAUDE_CONFIG_DIR in %v", env)
	}
	if !strings.Contains(joined, "CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-demo-token-123456") {
		t.Fatalf("missing CLAUDE_CODE_OAUTH_TOKEN in %v", env)
	}

	// 2. Import Codex auth JSON -> persists 0600 auth.json under CODEX_HOME.
	st, err = mgr.StartLogin(context.Background(), CoreCodex, CLILoginInput{
		Mode:  "token",
		Token: `{"tokens":{"access_token":"demo"}}`,
	})
	if err != nil {
		t.Fatalf("StartLogin codex json: %v", err)
	}
	if !st.LoggedIn || st.AuthMethod != "oauth" {
		t.Fatalf("codex status after json import = %+v", st)
	}
	codexAuthPath := filepath.Join(dir, "agent-homes", "codex", "config", "codex", "auth.json")
	fi, err := os.Stat(codexAuthPath)
	if err != nil {
		t.Fatalf("codex auth.json missing: %v", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("codex auth.json mode = %#o, want 0600", fi.Mode().Perm())
	}

	// 3. Logout removes credentials cleanly.
	st, err = mgr.Logout(CoreCodex)
	if err != nil {
		t.Fatalf("Logout codex: %v", err)
	}
	if st.LoggedIn || st.AuthMethod != "none" {
		t.Fatalf("codex status after logout = %+v", st)
	}
	if env := mgr.PersistentEnvFor(CoreCodex); len(env) != 0 {
		t.Fatalf("PersistentEnvFor after logout = %v, want empty", env)
	}
}

func TestFetchModelsAndProviderCapabilities(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/models" && r.Header.Get("x-api-key") == "sk-ant-key":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"id":"claude-sonnet-4-5"},{"id":"claude-opus-4-1"},{"id":"claude-sonnet-4-5"}]}`))
		case r.URL.Path == "/openai/models" && r.Header.Get("Authorization") == "Bearer sk-openai-key":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"id":"gpt-5"},{"id":"o3-mini"}]}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	keyDir := t.TempDir()
	env := newTestHost(t, func(o *Options) {
		keys, err := secrets.LoadKeyRing(keyDir)
		if err != nil {
			t.Fatalf("LoadKeyRing: %v", err)
		}
		st, err := secrets.New(secrets.Options{DB: o.DB, Keys: keys})
		if err != nil {
			t.Fatalf("secrets.New: %v", err)
		}
		o.Secrets = st
		o.HTTPClient = srv.Client()
	})
	ctx := context.Background()
	admin := actor.Actor{Kind: actor.Human, ID: "usr_admin"}

	// Ad-hoc OpenAI model fetch (before saving provider).
	res, err := env.svc.FetchProviderModels(ctx, FetchModelsInput{
		Kind:    ProviderKindOpenAI,
		BaseURL: srv.URL + "/openai",
		APIKey:  "sk-openai-key",
	})
	if err != nil || !res.OK {
		t.Fatalf("FetchProviderModels openai = %+v, err=%v", res, err)
	}
	if strings.Join(res.Models, ",") != "gpt-5,o3-mini" {
		t.Fatalf("openai models = %v", res.Models)
	}

	// Create Anthropic-compatible provider with models, effort, and max context.
	var created *AIProvider
	if err := env.db.Update(ctx, func(tx *storage.Tx) error {
		var cerr error
		created, cerr = env.svc.CreateProvider(ctx, tx, CreateProviderInput{
			Actor:            admin,
			Name:             "Claude Relay",
			Kind:             ProviderKindAnthropic,
			BaseURL:          srv.URL,
			Model:            "claude-sonnet-4-5",
			Models:           []string{"claude-sonnet-4-5", "claude-opus-4-1"},
			ReasoningEffort:  "high",
			MaxContextTokens: 200000,
			IsDefault:        true,
		})
		return cerr
	}); err != nil {
		t.Fatalf("CreateProvider anthropic: %v", err)
	}
	if _, err := env.svc.SetProviderAPIKey(ctx, admin, created.ID, "sk-ant-key"); err != nil {
		t.Fatalf("SetProviderAPIKey: %v", err)
	}

	// Fetch models via saved provider_id (reuses encrypted key).
	res, err = env.svc.FetchProviderModels(ctx, FetchModelsInput{ProviderID: created.ID})
	if err != nil || !res.OK {
		t.Fatalf("FetchProviderModels saved anthropic = %+v, err=%v", res, err)
	}
	if strings.Join(res.Models, ",") != "claude-opus-4-1,claude-sonnet-4-5" {
		t.Fatalf("anthropic models = %v", res.Models)
	}

	// ResolveProviderForCLI bridges ANTHROPIC_API_KEY + ANTHROPIC_AUTH_TOKEN + ANTHROPIC_BASE_URL.
	cliEnv, ep, found, cleanup, err := ResolveProviderForCLI(ctx, env.svc, created.ID, CoreClaudeCode)
	if err != nil || !found {
		t.Fatalf("ResolveProviderForCLI = found:%v err:%v", found, err)
	}
	defer cleanup()
	if ep.ReasoningEffort != "high" || ep.MaxContextTokens != 200000 || ep.Model != "claude-sonnet-4-5" {
		t.Fatalf("resolved endpoint metadata mismatch: %+v", ep)
	}
	joined := strings.Join(cliEnv, "\n")
	for _, want := range []string{"ANTHROPIC_API_KEY=sk-ant-key", "ANTHROPIC_AUTH_TOKEN=sk-ant-key", "ANTHROPIC_BASE_URL=" + srv.URL} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in %v", want, cliEnv)
		}
	}

	// Update session config live (effort, model, max_context_tokens, plan_mode).
	sess, err := env.svc.Create(ctx, admin, CreateRequest{Title: "Ops", Core: CoreNative})
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	patch, _ := json.Marshal(map[string]any{
		"model":              "claude-opus-4-1",
		"reasoning_effort":   "xhigh",
		"max_context_tokens": 500000,
		"plan_mode":          true,
	})
	updated, err := env.svc.Update(ctx, admin, sess.ID, UpdateRequest{
		Config:           patch,
		ExpectedRevision: sess.Revision,
	})
	if err != nil {
		t.Fatalf("Update session config: %v", err)
	}
	var gotCfg map[string]any
	if err := json.Unmarshal(updated.Config, &gotCfg); err != nil {
		t.Fatalf("unmarshal updated config: %v", err)
	}
	if gotCfg["model"] != "claude-opus-4-1" || gotCfg["reasoning_effort"] != "xhigh" || gotCfg["plan_mode"] != true {
		t.Fatalf("updated config = %v", gotCfg)
	}
}

func TestWorkspaceSeparationAndOfficialRegistry(t *testing.T) {
	dir := t.TempDir()
	cliAuth := NewCLIAuthManager(dir)
	defer cliAuth.Close()
	ws := NewWorkspaceManager(dir, cliAuth)
	reg := NewRegistryManager(ws, nil)

	// 1. Path traversal must be rejected.
	if _, err := ws.WriteFile(WorkspaceWriteInput{
		Area:    WorkspaceAreaSkills,
		Path:    "../prompts/claude-code/CLAUDE.md",
		Content: "evil",
	}); err == nil {
		t.Fatal("path traversal was accepted")
	}

	// 2. Per-core custom prompts stay strictly separated and mirror to each CLI home.
	if _, err := ws.WriteFile(WorkspaceWriteInput{
		Area:    WorkspaceAreaPrompts,
		Path:    "claude-code/CLAUDE.md",
		Content: "Claude only rule",
	}); err != nil {
		t.Fatalf("write CLAUDE.md: %v", err)
	}
	if _, err := ws.WriteFile(WorkspaceWriteInput{
		Area:    WorkspaceAreaPrompts,
		Path:    "codex/AGENTS.md",
		Content: "Codex only rule",
	}); err != nil {
		t.Fatalf("write codex AGENTS.md: %v", err)
	}
	if got := ws.ReadPromptForCore(CoreClaudeCode); got != "Claude only rule" {
		t.Fatalf("claude prompt = %q", got)
	}
	if got := ws.ReadPromptForCore(CoreCodex); got != "Codex only rule" {
		t.Fatalf("codex prompt = %q", got)
	}
	if got := ws.ReadPromptForCore(CoreNative); got != "" {
		t.Fatalf("native prompt leaked: %q", got)
	}
	// Verify mirrored into isolated CLI home.
	mirroredClaude, err := os.ReadFile(filepath.Join(dir, "agent-homes", "claude-code", "config", "claude", "CLAUDE.md"))
	if err != nil || string(mirroredClaude) != "Claude only rule" {
		t.Fatalf("mirrored CLAUDE.md = %q, err=%v", string(mirroredClaude), err)
	}

	// 3. Official registry search returns Anthropic Skills, OpenAI Skills, and MCP Official Servers.
	search := reg.Search(context.Background(), RegistryQuery{Kind: "all"})
	if len(search.Sources) != 3 || len(search.Items) < 15 {
		t.Fatalf("unexpected curated registry: sources=%d items=%d", len(search.Sources), len(search.Items))
	}

	// 4. Install an official MCP server -> written cleanly into mcp/servers.json.
	mcpRes, err := reg.Install(context.Background(), "mcp-official:fetch")
	if err != nil || !mcpRes.Installed {
		t.Fatalf("install official MCP: res=%+v err=%v", mcpRes, err)
	}
	servers, err := ws.ListMCPServers()
	if err != nil || len(servers) != 1 || servers[0].ID != "fetch" || !servers[0].Enabled {
		t.Fatalf("ListMCPServers = %+v, err=%v", servers, err)
	}

	// 5. Drag-and-drop base64 skill upload -> visible in LoadCustomSkillsPrompt.
	if _, err := ws.WriteFile(WorkspaceWriteInput{
		Area:          WorkspaceAreaSkills,
		Path:          "my-ops-skill/SKILL.md",
		ContentBase64: "IyBNeSBPcHMgU2tpbGwK", // "# My Ops Skill\n"
	}); err != nil {
		t.Fatalf("base64 upload skill: %v", err)
	}
	if !ws.SkillInstalled("my-ops-skill") {
		t.Fatal("uploaded skill not detected")
	}
	if !strings.Contains(ws.LoadCustomSkillsPrompt(), "# My Ops Skill") {
		t.Fatalf("LoadCustomSkillsPrompt missing uploaded skill: %q", ws.LoadCustomSkillsPrompt())
	}
}
