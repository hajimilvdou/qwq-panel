// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/capability/pluginconfig"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	"github.com/qwq-panel/qwq/internal/pluginhost/supervisor"
	"github.com/qwq-panel/qwq/internal/pluginpublic"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
	pluginconfigv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/pluginconfig/v1"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
	"google.golang.org/grpc"
)

func TestRuntimePluginConfigBackendAndPublicGateway(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(t.Context(), storage.Options{Path: filepath.Join(dir, "qwq.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	keys, err := secrets.LoadKeyRing(dir)
	if err != nil {
		t.Fatal(err)
	}
	secStore, err := secrets.New(secrets.Options{DB: db, Keys: keys})
	if err != nil {
		t.Fatal(err)
	}

	pluginsRoot := filepath.Join(dir, "plugins")
	coreSchemaDir := filepath.Join(pluginsRoot, "core.xray", "0.1.0", "schemas")
	if err := os.MkdirAll(coreSchemaDir, 0o755); err != nil {
		t.Fatal(err)
	}
	schema := `{"type":"object","properties":{"token":{"x-secret":true,"writeOnly":true,"anyOf":[{"type":"string"},{"type":"object","properties":{"$secret":{"type":"string"}},"required":["$secret"]}]},"name":{"type":"string"}}}`
	if err := os.WriteFile(filepath.Join(coreSchemaDir, "config.schema.json"), []byte(schema), 0o600); err != nil {
		t.Fatal(err)
	}

	rt, err := NewPluginRuntime(PluginRuntimeOptions{
		Units:       UnitManagerAdapter{Systemctl: &fakeSystemctl{}},
		PluginDir:   PluginDirResolver(pluginsRoot),
		PluginsRoot: pluginsRoot,
		RunDir:      filepath.Join(dir, "run"),
		StateDir:    filepath.Join(dir, "state"),
		Clock:       clock.System{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rt.HasCapabilityService("traffic") || !rt.HasCapabilityService("pluginconfig") {
		t.Fatal("default capability router must register traffic and pluginconfig")
	}

	rt.mu.Lock()
	rt.deps = HostDeps{DB: db, Secrets: secStore}
	rt.mu.Unlock()

	// 先写入一条带已提取密文引用的 core.xray 初始配置
	initialRedacted, _, err := secStore.ExtractSecrets(t.Context(), []byte(schema), []byte(`{"token":"old-secret-value","name":"v1"}`), secrets.ExtractOptions{
		Owner:   "plugins/core.xray",
		Purpose: pluginSecretPurpose,
	})
	if err != nil {
		t.Fatal(err)
	}
	storeAppliedPluginConfig(t, db, "core.xray", 1, string(initialRedacted))

	fwd := pluginconfig.Forwarder{Backend: &runtimePluginConfigBackend{rt: rt}}

	// 1. GetConfig 必须脱敏真实 sec_ 引用
	getRes, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
		Service: "pluginconfig",
		Method:  "GetConfig",
		Request: &pluginconfigv1.GetConfigRequest{TargetPluginId: "core.xray"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if getRes.Error != nil {
		t.Fatalf("unexpected GetConfig domain error: %+v", getRes.Error)
	}
	getResp := getRes.Response.(*pluginconfigv1.GetConfigResponse)
	if getResp.GetRevision() != "1" || !strings.Contains(string(getResp.GetRedactedConfigJson()), `"$secret_present":true`) {
		t.Fatalf("unexpected redacted GetConfig: %+v %s", getResp, string(getResp.GetRedactedConfigJson()))
	}

	// 2. PutConfig 使用 $keep_secret 保留原密文并更新非秘密字段
	putRes, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
		Service: "pluginconfig",
		Method:  "PutConfig",
		Request: &pluginconfigv1.PutConfigRequest{
			TargetPluginId:   "core.xray",
			ConfigJson:       []byte(`{"token":{"$keep_secret":true},"name":"v2"}`),
			ExpectedRevision: "1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if putRes.Error != nil {
		t.Fatalf("unexpected PutConfig domain error: %+v", putRes.Error)
	}
	putResp := putRes.Response.(*pluginconfigv1.PutConfigResponse)
	if putResp.GetRevision() != "2" {
		t.Fatalf("unexpected PutConfig result: %+v", putResp)
	}

	// 3. PublicGateway 未注册路由返回 404
	rec := httptest.NewRecorder()
	rt.PublicGateway().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/p/proxy.advanced/sub/unknown", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unregistered public route, got %d", rec.Code)
	}
}

type fakePublicRoutePluginServer struct {
	platformv1.UnimplementedPluginServiceServer
	pluginID string
	headers  []*platformv1.HttpHeader
	body     []byte
}

func (f *fakePublicRoutePluginServer) GetDescriptor(context.Context, *platformv1.GetDescriptorRequest) (*platformv1.GetDescriptorResponse, error) {
	return &platformv1.GetDescriptorResponse{
		Descriptor_: &platformv1.PluginDescriptor{
			PluginId: f.pluginID,
		},
	}, nil
}

func (f *fakePublicRoutePluginServer) CheckHealth(context.Context, *platformv1.CheckHealthRequest) (*platformv1.CheckHealthResponse, error) {
	return &platformv1.CheckHealthResponse{
		Status:         platformv1.CheckHealthResponse_STATUS_SERVING,
		LifecycleState: platformv1.LifecycleState_LIFECYCLE_STATE_ACTIVE,
	}, nil
}

func (f *fakePublicRoutePluginServer) ServePublicRoute(context.Context, *platformv1.ServePublicRouteRequest) (*platformv1.ServePublicRouteResponse, error) {
	return &platformv1.ServePublicRouteResponse{
		Status:  http.StatusOK,
		Headers: f.headers,
		Body:    f.body,
	}, nil
}

func TestServePublicStreamAndFallbackSanitizeResponseHeaders(t *testing.T) {
	base := shortUpdaterTempDir(t)
	runDir := filepath.Join(base, "run")
	pluginID := "ai.relay"

	// Prepare fake live plugin gRPC server on supervisor socket.
	pluginSock := supervisor.SocketPath(runDir, pluginID)
	if err := os.MkdirAll(filepath.Dir(pluginSock), 0o700); err != nil {
		t.Fatal(err)
	}
	grpcLn, err := net.Listen("unix", pluginSock)
	if err != nil {
		t.Fatalf("listen plugin.sock: %v", err)
	}
	fakeSrv := &fakePublicRoutePluginServer{
		pluginID: pluginID,
		headers: []*platformv1.HttpHeader{
			{Name: "Content-Type", Value: "application/json"},
			{Name: "X-Request-Id", Value: "req_buffered_1"},
			{Name: "X-RateLimit-Remaining", Value: "42"},
			{Name: "ETag", Value: `"v1"`},
			{Name: "Set-Cookie", Value: "qwq_session=evil; Path=/"},
			{Name: "Access-Control-Allow-Credentials", Value: "true"},
			{Name: "Content-Security-Policy", Value: "default-src * 'unsafe-inline' 'unsafe-eval'"},
			{Name: "Clear-Site-Data", Value: `"*"`},
			{Name: "Refresh", Value: "0; url=https://evil.example"},
			{Name: "Link", Value: `<https://evil.example/a.js>; rel=preload`},
		},
		body: []byte(`{"mode":"buffered"}`),
	}
	grpcServer := grpc.NewServer()
	platformv1.RegisterPluginServiceServer(grpcServer, fakeSrv)
	go func() { _ = grpcServer.Serve(grpcLn) }()
	t.Cleanup(grpcServer.Stop)

	rt, err := NewPluginRuntime(PluginRuntimeOptions{
		Units: &fakeSupervisorUnits{
			state: supervisor.UnitState{
				MainPID:     12345,
				ActiveState: "active",
				SubState:    "running",
				StartTime:   time.Unix(1700000000, 0).UTC(),
			},
		},
		PluginDir: func(string) (string, error) { return filepath.Join(base, "plugins", pluginID, "0.1.0"), nil },
		RunDir:    runDir,
		StateDir:  filepath.Join(base, "state"),
		Host:      func(string) (supervisor.HostServer, error) { return fakeHostServer{}, nil },
		Logger:    slog.New(slog.DiscardHandler),
		Clock:     clock.System{},
	})
	if err != nil {
		t.Fatalf("NewPluginRuntime: %v", err)
	}
	t.Cleanup(rt.Stop)
	if err := rt.Start(t.Context(), HostDeps{}); err != nil {
		t.Fatalf("rt.Start: %v", err)
	}
	if _, err := rt.attach(t.Context(), pluginID); err != nil {
		t.Fatalf("rt.attach: %v", err)
	}

	assertSanitized := func(t *testing.T, rec *httptest.ResponseRecorder, wantReqID string) {
		t.Helper()
		for _, forbidden := range []string{
			"Set-Cookie",
			"Access-Control-Allow-Credentials",
			"Content-Security-Policy",
			"Clear-Site-Data",
			"Refresh",
			"Link",
		} {
			if v := rec.Header().Get(forbidden); v != "" {
				t.Errorf("forbidden header %s leaked: %q", forbidden, v)
			}
		}
		if got := rec.Header().Get("X-Request-Id"); got != wantReqID {
			t.Errorf("X-Request-Id = %q, want %q", got, wantReqID)
		}
		if got := rec.Header().Get("X-RateLimit-Remaining"); got != "42" {
			t.Errorf("X-RateLimit-Remaining = %q, want 42", got)
		}
		if got := rec.Header().Get("ETag"); got != `"v1"` {
			t.Errorf("ETag = %q, want \"v1\"", got)
		}
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
		}
		if got := rec.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
			t.Errorf("X-Frame-Options = %q, want SAMEORIGIN", got)
		}
		if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
			t.Errorf("Referrer-Policy = %q, want no-referrer", got)
		}
	}

	// 1. Streaming UDS path using dedicated qwq-plugin-stream-<id>/public-stream.sock.
	streamDir := filepath.Join(base, "qwq-plugin-stream-"+pluginID)
	if err := os.MkdirAll(streamDir, 0o711); err != nil {
		t.Fatal(err)
	}
	streamSock := filepath.Join(streamDir, pluginsdk.PublicStreamSocketName)
	streamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no")
		w.Header().Set("X-Request-Id", "req_stream_1")
		w.Header().Set("X-RateLimit-Remaining", "42")
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Retry-After", "5")
		// Malicious headers that MUST be stripped:
		w.Header().Set("Set-Cookie", "qwq_session=evil; Path=/")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Content-Security-Policy", "default-src * 'unsafe-inline'")
		w.Header().Set("Clear-Site-Data", `"*"`)
		w.Header().Set("Refresh", "0; url=https://evil.example")
		w.Header().Set("Link", `<https://evil.example/x.js>; rel=preload`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "data: hi\n\n")
	})
	bridge, err := pluginsdk.StartPublicStreamBridgeAt(streamSock, "", streamHandler, func(net.Conn) error { return nil })
	if err != nil {
		t.Fatalf("StartPublicStreamBridgeAt: %v", err)
	}

	if resolved := resolvePublicStreamSocketPath(runDir, pluginID); resolved != streamSock {
		t.Fatalf("resolvePublicStreamSocketPath = %q, want %q", resolved, streamSock)
	}

	streamRec := httptest.NewRecorder()
	err = rt.ServePublicStream(t.Context(), pluginID, pluginpublic.PublicRequest{
		Method: http.MethodPost,
		Route:  "v1",
		Path:   "/v1/chat/completions",
	}, strings.NewReader(`{}`), streamRec)
	if err != nil {
		t.Fatalf("ServePublicStream (UDS): %v", err)
	}
	if streamRec.Code != http.StatusOK || streamRec.Body.String() != "data: hi\n\n" {
		t.Fatalf("unexpected stream response: code=%d body=%q", streamRec.Code, streamRec.Body.String())
	}
	assertSanitized(t, streamRec, "req_stream_1")
	if got := streamRec.Header().Get("X-Accel-Buffering"); got != "no" {
		t.Errorf("X-Accel-Buffering = %q, want no", got)
	}
	if got := streamRec.Header().Get("Retry-After"); got != "5" {
		t.Errorf("Retry-After = %q, want 5", got)
	}

	// Shut down stream bridge so ServePublicStream falls back to fallbackBufferedPublicStream.
	closeCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_ = bridge.Close(closeCtx)

	fallbackRec := httptest.NewRecorder()
	err = rt.ServePublicStream(t.Context(), pluginID, pluginpublic.PublicRequest{
		Method: http.MethodPost,
		Route:  "v1",
		Path:   "/v1/chat/completions",
	}, strings.NewReader(`{}`), fallbackRec)
	if err != nil {
		t.Fatalf("ServePublicStream (fallback): %v", err)
	}
	if fallbackRec.Code != http.StatusOK || fallbackRec.Body.String() != `{"mode":"buffered"}` {
		t.Fatalf("unexpected fallback response: code=%d body=%q", fallbackRec.Code, fallbackRec.Body.String())
	}
	assertSanitized(t, fallbackRec, "req_buffered_1")
}
