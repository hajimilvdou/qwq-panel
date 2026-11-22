// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/agentsession"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/operations"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// ======================== 原生 Agent 与全套内置插件 + 第三方适配器实机联调测试 ========================

func TestNativeAgentRealBuiltinCatalogAndThirdPartyCores(t *testing.T) {
	ctx := t.Context()

	// 1. 启动真实 Controller 并加载仓库全部 8 款内置官方插件的真实 manifest.json + schemas
	opts := testOptions(t)
	fakeClient := &fakePluginClient{
		invokeResp: &platformv1.InvokeResponse{
			PayloadJson: []byte(`{"total_nodes":3,"online_nodes":3,"anomalies":[]}`),
		},
	}
	opts.PluginRuntime = &PluginRuntime{
		dispatcher: &pluginDispatcher{clients: &fakeClients{client: fakeClient}},
	}
	c, err := New(ctx, opts)
	if err != nil {
		t.Fatalf("controller.New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	e := &agentEnv{t: t, c: c}
	admin := e.createUser("native-ai-admin", identity.RoleAdmin)

	pluginDirs := []string{
		"server.probe",
		"ai.relay",
		"proxy.advanced",
		"security.basic",
		"core.xray",
		"domain.dns",
		"tls.certificates",
		"monitor",
		"web.ingress",
		"containers.docker",
		"notify.hub",
	}
	for _, dirName := range pluginDirs {
		pdir := filepath.Join("..", "..", "plugins", "builtin", dirName)
		raw, err := os.ReadFile(filepath.Join(pdir, "manifest.json"))
		if err != nil {
			t.Fatalf("read manifest %s: %v", dirName, err)
		}
		m, err := manifest.Parse(raw)
		if err != nil {
			t.Fatalf("parse manifest %s: %v", dirName, err)
		}
		if err := c.Catalog().SetPlugin(m, func(rel string) ([]byte, error) {
			return os.ReadFile(filepath.Join(pdir, filepath.FromSlash(rel)))
		}); err != nil {
			t.Fatalf("catalog.SetPlugin(%s): %v", dirName, err)
		}
	}

	// 2. 验证 AgentToolCatalog 发现全部 8 款内置插件操作，且每个操作都携带合法 JSON Schema
	tools := AgentToolCatalog{
		Catalog:    c.Catalog(),
		HostAction: c.Operations().HasHostAction,
	}.Actions(ctx)
	byAction := make(map[string]agentsession.ToolSpec, len(tools))
	for _, tool := range tools {
		byAction[tool.Action] = tool
		if len(tool.Parameters) == 0 || !json.Valid(tool.Parameters) {
			t.Fatalf("tool %s has invalid JSON schema: %q", tool.Action, tool.Parameters)
		}
	}
	for _, mustHave := range []string{
		"server.probe/probe.ai.digest",
		"server.probe/probe.settings.update",
		"ai.relay/relay.overview",
		"proxy.advanced/proxy.overview",
		"proxy.advanced/users.set_limits",
		"proxy.advanced/chains.list",
		"proxy.advanced/brutal.status",
		"proxy.advanced/tuning.plan",
		"core.xray/core.export_client",
		"security.basic/security.firewall.status",
		"domain.dns/providers.list",
		"tls.certificates/certificates.list",
		"web.ingress/ingress.ai.digest",
		"web.ingress/ingress.site.upsert",
		"containers.docker/docker.ai.digest",
		"containers.docker/docker.container.limits",
		"notify.hub/notify.ai.digest",
		"notify.hub/notify.dispatch",
	} {
		if _, ok := byAction[mustHave]; !ok {
			t.Fatalf("native agent catalog missing expected plugin tool %q (total tools=%d)", mustHave, len(tools))
		}
	}
	t.Logf("AgentToolCatalog verified: %d total tools across all 11 built-in plugins", len(tools))

	// 3. 启动真实 NewAgentSessions 并核查原生与全部第三方适配器 Core 注册及当前大开发机实机环境探测状态
	svc, err := c.NewAgentSessions(ctx)
	if err != nil {
		t.Fatalf("NewAgentSessions: %v", err)
	}
	t.Cleanup(svc.Close)

	descriptors := svc.CoreDescriptors(ctx)
	descMap := make(map[agentsession.CoreName]agentsession.CoreDescriptor, len(descriptors))
	for _, d := range descriptors {
		descMap[d.Name] = d
		t.Logf("AgentCore live probe: name=%s protocol=%s binary=%q available=%v reason=%q mcp=%v approval=%v stream=%v",
			d.Name, d.Protocol, d.Binary, d.Available, d.Reason,
			d.Capabilities.MCPHostTools, d.Capabilities.BidirectionalApproval, d.Capabilities.Streaming)
	}
	if !descMap[agentsession.CoreNative].Available {
		t.Fatalf("native core must be available, got %+v", descMap[agentsession.CoreNative])
	}
	for _, wantCore := range []agentsession.CoreName{
		agentsession.CoreClaudeCode,
		agentsession.CoreCodex,
		agentsession.CoreOpencode,
		agentsession.CoreDSH,
		agentsession.CoreACP,
	} {
		if _, ok := descMap[wantCore]; !ok {
			t.Fatalf("expected third-party core %q to be registered in CoreDescriptors()", wantCore)
		}
	}

	// 4. 验证生产 AgentRunner -> operations.Run 真实工具调用链（读操作放行，写操作严格进人工审批）
	owner := actor.Actor{Kind: actor.Human, ID: admin.ID, SessionID: "sess_e2e_1"}
	runner := &AgentRunner{
		Ops:     c.Operations(),
		Catalog: c.Catalog(),
		NodeID:  "local",
	}
	readRes, err := runner.RunTool(ctx, agentsession.ToolCall{
		CallID:         "call_probe_digest_1",
		SessionID:      "ags_e2e_probe",
		Seq:            1,
		Actor:          owner,
		PermissionMode: operations.PermissionSafe,
		Action:         "server.probe/probe.ai.digest",
		Args:           json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("AgentRunner read error: %v", err)
	}
	if readRes.Status != agentsession.ToolSucceeded {
		t.Fatalf("native AgentRunner invoke server.probe/probe.ai.digest failed: %+v", readRes)
	}
	if !strings.Contains(string(readRes.Result), `"online_nodes":3`) {
		t.Fatalf("unexpected probe digest result: %s", readRes.Result)
	}

	writeRes, err := runner.RunTool(ctx, agentsession.ToolCall{
		CallID:         "call_probe_write_1",
		SessionID:      "ags_e2e_probe",
		Seq:            2,
		Actor:          owner,
		PermissionMode: operations.PermissionSafe,
		Action:         "server.probe/probe.settings.update",
		Args:           json.RawMessage(`{"site_title":"AI Updated Probe"}`),
	})
	if err != nil {
		t.Fatalf("AgentRunner write error: %v", err)
	}
	if writeRes.Status != agentsession.ToolAwaitingApproval || writeRes.ApprovalID == "" {
		t.Fatalf("expected AWAITING_APPROVAL for server.probe write in safe mode, got %+v", writeRes)
	}

	// 5. 驱动真实 EnhancedNativeCore 完成 OpenAI 兼容模型 -> 真实 AgentRunner(server.probe) -> 最终中文答复完整回环
	var modelCalls atomic.Int32
	var seenProbeTool atomic.Bool
	modelSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody struct {
			Tools []struct {
				Function struct {
					Name        string `json:"name"`
					Description string `json:"description"`
				} `json:"function"`
			} `json:"tools"`
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&reqBody)
		probeFuncName := ""
		for _, tl := range reqBody.Tools {
			if strings.Contains(tl.Function.Name, "probe_ai_digest") || strings.Contains(tl.Function.Name, "probe.ai.digest") {
				probeFuncName = tl.Function.Name
				seenProbeTool.Store(true)
				break
			}
		}
		n := modelCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			if probeFuncName == "" {
				t.Errorf("model request #1 did not expose server.probe/probe.ai.digest in %d tools", len(reqBody.Tools))
				probeFuncName = "server_probe__probe_ai_digest"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "chatcmpl_e2e_1",
				"choices": []map[string]any{{
					"index": 0,
					"message": map[string]any{
						"role": "assistant",
						"tool_calls": []map[string]any{{
							"id":   "tc_probe_1",
							"type": "function",
							"function": map[string]any{
								"name":      probeFuncName,
								"arguments": `{}`,
							},
						}},
					},
					"finish_reason": "tool_calls",
				}},
				"usage": map[string]int{"prompt_tokens": 120, "completion_tokens": 18},
			})
			return
		}
		// 确认第 2 轮把真实插件返回结果喂回了模型
		gotToolPayload := false
		for _, m := range reqBody.Messages {
			if m.Role == "tool" && strings.Contains(m.Content, `"online_nodes":3`) {
				gotToolPayload = true
				break
			}
		}
		if !gotToolPayload {
			t.Errorf("model request #2 did not receive server.probe tool output in messages")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "chatcmpl_e2e_2",
			"choices": []map[string]any{{
				"index": 0,
				"message": map[string]any{
					"role":    "assistant",
					"content": "探针巡检完成：当前 3 台节点全部在线，无异常。",
				},
				"finish_reason": "stop",
			}},
			"usage": map[string]int{"prompt_tokens": 180, "completion_tokens": 24},
		})
	}))
	defer modelSrv.Close()

	nativeCore := agentsession.NewEnhancedNativeCore(agentsession.NativeOptions{
		Client: modelSrv.Client(),
	}, agentsession.NewSkillRegistry())
	cfgJSON, _ := json.Marshal(map[string]any{
		"base_url": modelSrv.URL,
		"model":    "qwq-e2e-test-model",
	})
	var callSeq atomic.Int32
	var finalReply string
	var gotToolEvent bool
	err = nativeCore.Run(ctx, agentsession.Turn{
		SessionID:      "ags_e2e_native_loop",
		PermissionMode: operations.PermissionSafe,
		Messages: []agentsession.Message{{
			Seq:     1,
			Role:    agentsession.RoleUser,
			Content: "帮我巡检一下探针节点状态",
		}},
		Tools:  tools,
		Config: cfgJSON,
		Runner: agentsession.RunnerFunc(func(rctx context.Context, call agentsession.ToolCall) (agentsession.ToolResult, error) {
			call.Actor = owner
			call.SessionID = "ags_e2e_native_loop"
			call.PermissionMode = operations.PermissionSafe
			return runner.RunTool(rctx, call)
		}),
		NextCallID: func() string {
			return "call_loop_" + string(rune('0'+callSeq.Add(1)))
		},
	}, func(ev agentsession.Event) error {
		switch ev.Type {
		case agentsession.EventToolResult:
			if ev.Status == string(agentsession.ToolSucceeded) && strings.Contains(string(ev.Result), `"online_nodes":3`) {
				gotToolEvent = true
			}
		case agentsession.EventMessageCompleted:
			if strings.Contains(ev.Delta, "探针巡检完成") {
				finalReply = ev.Delta
			}
		case agentsession.EventMessageDelta:
			finalReply += ev.Delta
		}
		return nil
	})
	if err != nil {
		t.Fatalf("EnhancedNativeCore.Run failed: %v", err)
	}
	if !seenProbeTool.Load() || !gotToolEvent || !strings.Contains(finalReply, "探针巡检完成") {
		t.Fatalf("native loop incomplete: seenProbeTool=%v gotToolEvent=%v finalReply=%q calls=%d",
			seenProbeTool.Load(), gotToolEvent, finalReply, modelCalls.Load())
	}
	t.Logf("EnhancedNativeCore E2E loop passed in %d model turns: %s", modelCalls.Load(), finalReply)

	// 6. 验证原生会话 Service 的持久化创建与直通斜杠指令 (/status, /skills, /mcp)
	sess, err := svc.Create(ctx, owner, agentsession.CreateRequest{
		Core:           agentsession.CoreNative,
		PermissionMode: operations.PermissionSafe,
		Title:          "Native Agent E2E Check",
	})
	if err != nil {
		t.Fatalf("svc.Create native session: %v", err)
	}
	for i, cmd := range []string{"/status", "/skills", "/mcp"} {
		if _, err := svc.Send(ctx, owner, sess.ID, agentsession.SendRequest{
			Content:         cmd,
			ClientMessageID: "cmd_" + string(rune('a'+i)),
		}); err != nil {
			t.Fatalf("svc.Send %s: %v", cmd, err)
		}
		deadline := time.Now().Add(5 * time.Second)
		settled := false
		for time.Now().Before(deadline) {
			cur, gerr := svc.Get(ctx, owner, sess.ID)
			if gerr == nil && cur.Status == agentsession.StatusIdle {
				settled = true
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if !settled {
			t.Fatalf("slash command %s did not settle to idle within 5s", cmd)
		}
	}
	t.Logf("Native Agent Service slash commands (/status, /skills, /mcp) passed on session %s", sess.ID)

	// 7. 验证第三方适配器在未安装宿主机 CLI 时的诚实 fail-closed 预检
	codexSess, err := svc.Create(ctx, owner, agentsession.CreateRequest{
		Core:           agentsession.CoreCodex,
		PermissionMode: operations.PermissionSafe,
		Title:          "Codex Preflight Check",
	})
	if err != nil {
		t.Fatalf("svc.Create codex session: %v", err)
	}
	if !descMap[agentsession.CoreCodex].Available {
		if _, err := svc.Send(ctx, owner, codexSess.ID, agentsession.SendRequest{
			Content:         "inspect server status",
			ClientMessageID: "codex_preflight_1",
		}); err == nil {
			t.Fatalf("expected codex Send to fail preflight when binary is absent")
		} else {
			t.Logf("Codex fail-closed preflight verified: %v", err)
		}
	}
}
