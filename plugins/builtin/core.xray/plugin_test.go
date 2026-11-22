// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/testfixture"
	"github.com/qwq-panel/qwq/sdk/coreapi"
	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/manifest"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

func testIntent(t *testing.T) []byte {
	t.Helper()
	data, err := json.Marshal(testfixture.Intent())
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func testContext() *pb.RequestContext {
	return &pb.RequestContext{InstanceId: "default", OperationId: "op-test", Locale: "zh-CN"}
}

func skeletonServer(t *testing.T, config []byte) (*pluginsdk.Server, string) {
	return pluginServer(t, New(), config)
}

func pluginServer(t *testing.T, plugin *Plugin, config []byte) (*pluginsdk.Server, string) {
	return pluginServerWithHost(t, plugin, config, nil)
}

func pluginServerWithHost(t *testing.T, plugin *Plugin, config []byte, host grpc.ClientConnInterface) (*pluginsdk.Server, string) {
	directory, err := os.MkdirTemp("", "sdk-xray-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return newPluginServer(t, plugin, config, host, filepath.Join(directory, "absent"))
}

func newPluginServer(t *testing.T, plugin *Plugin, config []byte, host grpc.ClientConnInterface, dataDir string) (*pluginsdk.Server, string) {
	t.Helper()
	srv, err := pluginsdk.Serve(t.Context(), pluginsdk.Options{
		Plugin: plugin, Manifest: Manifest(), Registrar: grpc.NewServer(),
		Host:   host,
		Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	if _, err := srv.Initialize(t.Context(), &pb.InitializeRequest{
		Context: testContext(), InstanceHandle: "test-handle", DataDir: dataDir,
		ConfigJson: config, ConfigRevision: "1",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Start(t.Context(), &pb.StartRequest{Context: testContext()}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Activate(t.Context(), &pb.ActivateRequest{Context: testContext()}); err != nil {
		t.Fatal(err)
	}
	return srv, dataDir
}

func TestManifestAndDescriptor(t *testing.T) {
	m, err := manifest.Parse(Manifest())
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != "core.xray" || m.Version != "0.1.0" || m.SchemaVersion != "1.3" ||
		m.Placement != "node" || m.Lifecycle.Startup != "eager" || !m.Lifecycle.Background ||
		m.Lifecycle.UpdateStrategy != "restart" || m.Lifecycle.EffectiveOverlapSafe() || !m.Config.HotApply || len(m.Operations) != 8 || len(m.Capabilities) != 4 {
		t.Fatal("manifest 未满足 Core v2 固定契约")
	}
	for _, operation := range m.Operations {
		if !strings.HasPrefix(operation.Permission, "core.xray:") {
			t.Fatal("permission 资源段错误")
		}
		for _, capability := range operation.Capabilities {
			if capability.Name == "secret.reveal" && operation.Name != "core.apply" && operation.Name != "core.export_client" {
				t.Fatal("普通只读操作继承了秘密能力")
			}
		}
		if operation.Name == "core.apply" && (operation.Mode != "job" || operation.Effect != "write" ||
			operation.Risk != "medium" || operation.Approval != "confirm" || !operation.Idempotent ||
			!operation.EffectivePlannable() || len(operation.Capabilities) != 4) {
			t.Fatal("Apply 声明与能力子集不一致")
		}
	}
	for name, want := range m.Files {
		if strings.HasPrefix(name, "bin/") {
			continue
		}
		data, err := os.ReadFile(filepath.FromSlash(name))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		if "sha256:"+hex.EncodeToString(digest[:]) != want {
			t.Fatalf("manifest 摘要漂移：%s", name)
		}
	}
	srv, _ := skeletonServer(t, nil)
	descriptor, err := srv.GetDescriptor(t.Context(), &pb.GetDescriptorRequest{})
	if err != nil || descriptor.GetDescriptor_().GetPluginId() != m.ID || len(descriptor.GetDescriptor_().GetOperations()) != 8 {
		t.Fatal("descriptor 与 manifest / 注册 handler 不一致")
	}
}

// ======================== 骨架必须诚实失败 ========================
func TestObserveAndUnavailableCoreAreReportedHonestly(t *testing.T) {
	srv, _ := skeletonServer(t, testIntent(t))
	for _, name := range []string{"core.observe"} {
		response, err := srv.Invoke(t.Context(), &pb.InvokeRequest{
			Context: testContext(), Operation: name, ApiVersion: "v1", PayloadJson: []byte(`{}`), Attempt: 1,
		})
		if err != nil || response.GetError().GetCode() != "CORE_API_UNAVAILABLE" || len(response.GetPayloadJson()) != 0 {
			t.Fatalf("%s 错误地返回业务成功", name)
		}
	}
	stream := &testJobStream{ctx: t.Context()}
	if err := srv.RunJob(&pb.RunJobRequest{
		Context: testContext(), Operation: "core.apply", ApiVersion: "v2", PayloadJson: []byte(`{"config_revision":"1"}`), Attempt: 1,
	}, stream); err != nil || len(stream.messages) != 1 || stream.messages[0].GetProgress().GetError().GetCode() != "CORE_BINARY_MISMATCH" {
		t.Fatal("缺少已核验核心却执行了 Apply")
	}
	plan, err := srv.PlanOperation(t.Context(), &pb.PlanOperationRequest{
		Context: testContext(), Operation: "core.apply", ApiVersion: "v2", PayloadJson: []byte(`{"config_revision":"1"}`),
	})
	if err != nil || plan.GetError().GetCode() != "NO_HOST" || len(plan.GetChanges()) != 0 {
		t.Fatal("缺少宿主连接却生成了虚假 Plan")
	}
}

func TestDesiredRevisionAndHealth(t *testing.T) {
	srv, dataDir := skeletonServer(t, []byte(`{}`))
	health, err := srv.CheckHealth(t.Context(), &pb.CheckHealthRequest{Context: testContext()})
	if err != nil || !strings.Contains(string(health.GetDetailsJson()), "UNCONFIGURED") || strings.Contains(string(health.GetDetailsJson()), `"proxy_available":true`) {
		t.Fatal("空配置没有报告 UNCONFIGURED")
	}
	config := testIntent(t)
	validated, err := srv.ValidateConfig(t.Context(), &pb.ValidateConfigRequest{Context: testContext(), ConfigJson: config, ProposedRevision: "2"})
	if err != nil || validated.GetError() != nil {
		t.Fatal("合法引用配置未通过 ValidateConfig")
	}
	response, err := srv.ApplyConfig(t.Context(), &pb.ApplyConfigRequest{Context: testContext(), ConfigJson: config, ProposedRevision: "2"})
	if err != nil || response.GetError() != nil {
		t.Fatal("desired 更新失败")
	}
	health, err = srv.CheckHealth(t.Context(), &pb.CheckHealthRequest{Context: testContext()})
	if err != nil || health.GetAppliedConfigRevision() != "2" || !strings.Contains(string(health.GetDetailsJson()), `"state":"PENDING_APPLY"`) ||
		strings.Contains(string(health.GetDetailsJson()), `"proxy_available":true`) || strings.Contains(string(health.GetDetailsJson()), "sec_") {
		t.Fatal("健康状态虚报核心可用或泄漏秘密")
	}
	bad := strings.Replace(string(config), `"enabled":true`, `"enabled":true,"native":{}`, 1)
	rejected, err := srv.ApplyConfig(t.Context(), &pb.ApplyConfigRequest{Context: testContext(), ConfigJson: []byte(bad), ProposedRevision: "3"})
	if err != nil || rejected.GetError().GetCode() != "INVALID_INTENT" {
		t.Fatal("非法配置未被拒绝")
	}
	health, err = srv.CheckHealth(t.Context(), &pb.CheckHealthRequest{Context: testContext()})
	if err != nil || health.GetAppliedConfigRevision() != "2" {
		t.Fatal("失败的配置替换破坏了旧 revision")
	}
	if _, err := os.Stat(dataDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("骨架在 DataDir 中产生了文件副作用")
	}
}

func TestSchemaAndSecretExtraction(t *testing.T) {
	schemaJSON, err := os.ReadFile("schemas/config.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(schemaJSON)))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("urn:qwq:core.xray:config", doc); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("urn:qwq:core.xray:config")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	db, err := storage.Open(t.Context(), storage.Options{Path: filepath.Join(root, "host.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	keys, err := secrets.LoadKeyRing(filepath.Join(root, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := secrets.New(secrets.Options{DB: db, Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	input := strings.NewReplacer(`{"$secret":"sec_00000000000000000000000000"}`, `"FAKE_PRIVATE_KEY"`,
		`{"$secret":"sec_00000000000000000000000001"}`, `"FAKE_UUID"`).Replace(string(testIntent(t)))
	safe, extracted, err := store.ExtractSecrets(t.Context(), schemaJSON, []byte(input), secrets.ExtractOptions{
		Owner: "plugins/core.xray", Purpose: "plugin.config",
	})
	if err != nil || len(extracted) != 2 || strings.Contains(string(safe), "FAKE_") {
		t.Fatal("配置秘密未全部提取")
	}
	decoded, err := coreapi.Decode(safe)
	if err != nil || coreapi.Validate(decoded) != nil {
		t.Fatal("提取后的引用不符合 Go Intent")
	}
	instance, err := jsonschema.UnmarshalJSON(strings.NewReader(string(safe)))
	if err != nil || schema.Validate(instance) != nil {
		t.Fatal("提取后的引用不符合配置 Schema")
	}
	srv, _ := skeletonServer(t, nil)
	response, err := srv.ValidateConfig(t.Context(), &pb.ValidateConfigRequest{Context: testContext(), ConfigJson: safe, ProposedRevision: "1"})
	if err != nil || response.GetError() != nil {
		t.Fatal("提取后的引用未通过 ValidateConfig")
	}
}

func TestDesiredAndHealthConcurrent(t *testing.T) {
	srv, _ := skeletonServer(t, testIntent(t))
	config := testIntent(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 16 {
				if _, err := srv.ApplyConfig(t.Context(), &pb.ApplyConfigRequest{Context: testContext(), ConfigJson: config, ProposedRevision: "2"}); err != nil {
					t.Error(err)
				}
				if _, err := srv.CheckHealth(t.Context(), &pb.CheckHealthRequest{Context: testContext()}); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
}

type testJobStream struct {
	ctx      context.Context
	messages []*pb.RunJobResponse
}

func (s *testJobStream) Context() context.Context { return s.ctx }
func (s *testJobStream) Send(message *pb.RunJobResponse) error {
	s.messages = append(s.messages, message)
	return nil
}
func (*testJobStream) SetHeader(metadata.MD) error  { return nil }
func (*testJobStream) SendHeader(metadata.MD) error { return nil }
func (*testJobStream) SetTrailer(metadata.MD)       {}
func (*testJobStream) SendMsg(any) error            { return errors.New("测试只接受强类型 Send") }
func (*testJobStream) RecvMsg(any) error            { return io.EOF }
