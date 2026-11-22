// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/controller/testfixtures"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/updater"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/hostauth"
	"github.com/qwq-panel/qwq/internal/storage"
	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// ======================== 未装配后端与失效上下文不能虚构消费者事实 ========================

func TestPrerequisiteConsumerSourceRejectsMissingUpdaterAndCancellation(t *testing.T) {
	c, _ := newVisibilityController(t)
	want := testfixtures.RenewalRequest().Scope.Consumers[0]
	want.Test = false
	origin := hostauth.Invocation{PluginID: "tls.certificates", InstanceID: "default", OperationID: "operation_fixture",
		Operation: "bindings.bind", Subject: "plugins/tls.certificates/resources/certificates/certificate_fixture"}
	source := c.PrerequisiteConsumerSource()
	if _, err := source.CurrentConsumer(t.Context(), origin, want); !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("缺Updater时伪造了消费者: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := source.CurrentConsumer(ctx, origin, want); !errors.Is(err, context.Canceled) {
		t.Fatalf("取消上下文仍读取配置: %v", err)
	}
}

// ======================== 真实 SQLite / updater 快照；不代替原生驱动验收 ========================

const prerequisiteConsumerFixtureJSON = `{"schema_version":"2","enabled":false,
"profiles":[{"id":"h2_fixture","enabled":false,"listen":"127.0.0.1","port":18443,"protocol":"hysteria2",
"users":[{"id":"h2-user","auth":{"$secret":"sec_00000000000000000000000002"}}],
"hysteria2":{"tls":{"binding_ref":"certbind_fixture","server_name":"proxy.example.test"}}}],
"outbound":{"type":"direct"}}`

func prerequisiteConsumerFixture(t *testing.T) (*Controller, hostauth.Invocation, certificates.Consumer) {
	t.Helper()
	c, _ := newVisibilityController(t)
	storePrerequisiteFixtureVersion(t, c.db, prerequisiteFixtureVersion())
	storeAppliedPluginConfig(t, c.db, "core.xray", 1, prerequisiteConsumerFixtureJSON)
	c.SetUpdater(loadStoredPluginUpdater(t, c.db))
	want := testfixtures.RenewalRequest().Scope.Consumers[0]
	want.Test = false
	origin := hostauth.Invocation{PluginID: "tls.certificates", InstanceID: "default", OperationID: "operation_fixture",
		Operation: "bindings.bind", Subject: "plugins/tls.certificates/resources/certificates/certificate_fixture"}
	return c, origin, want
}

func prerequisiteFixtureVersion() updater.Version {
	stamp := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	return updater.Version{PluginID: "core.xray", Version: "0.2.0+consumer-fixture", Digest: "sha256:" + strings.Repeat("a", 64),
		Status: updater.VersionActive, InstallStatus: updater.InstallInstalled, Active: true, InstalledAt: stamp, ActivatedAt: stamp, Revision: 11,
		Manifest: &manifest.Manifest{ID: "core.xray", Version: "0.2.0+consumer-fixture", Placement: operations.PlacementNode,
			Config: manifest.Config{Schema: "schemas/config.schema.json"},
			Files: map[string]string{"schemas/config.schema.json": "sha256:" + strings.Repeat("b", 64),
				"schemas/core.apply.request.json": "sha256:" + strings.Repeat("c", 64)},
			Operations: []manifest.Operation{{Name: "core.apply", APIVersion: "v2", Permission: "core.xray:apply", Mode: operations.ModeJob,
				Effect: operations.EffectWrite, RequestSchema: "schemas/core.apply.request.json"}}}}
}

func storePrerequisiteFixtureVersion(t *testing.T, db *storage.DB, version updater.Version) {
	t.Helper()
	raw, err := json.Marshal(version.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	active := 0
	if version.Active {
		active = 1
	}
	activated := ""
	if !version.ActivatedAt.IsZero() {
		activated = storage.FormatTime(version.ActivatedAt)
	}
	if err := db.Update(t.Context(), func(tx *storage.Tx) error {
		if _, err := tx.ExecContext(t.Context(), "UPDATE plugin_versions SET active=0 WHERE plugin_id=?", version.PluginID); err != nil {
			return err
		}
		_, err := tx.ExecContext(t.Context(), `INSERT INTO plugin_versions
			(plugin_id,version,digest,manifest_json,status,install_status,active,installed_at,activated_at,revision)
			VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(plugin_id,version) DO UPDATE SET
			digest=excluded.digest,manifest_json=excluded.manifest_json,status=excluded.status,
			install_status=excluded.install_status,active=excluded.active,activated_at=excluded.activated_at,revision=excluded.revision`,
			version.PluginID, version.Version, version.Digest, string(raw), version.Status, version.InstallStatus, active,
			storage.FormatTime(version.InstalledAt), activated, version.Revision)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func prerequisiteFixtureIntent(t *testing.T) *corev2.Intent {
	t.Helper()
	intent, err := corev2.Decode([]byte(prerequisiteConsumerFixtureJSON))
	if err != nil || corev2.Validate(intent) != nil {
		t.Fatalf("fixture 契约无效: %v", err)
	}
	return intent
}

func TestPrerequisiteConsumerSourceReadsActualV2AndNeverRestoresOrigin(t *testing.T) {
	c, origin, want := prerequisiteConsumerFixture(t)
	// DB 中没有该 origin operation；只读事实不能重开一个历史 executor。
	source := c.PrerequisiteConsumerSource()
	want.Test = true
	facts, err := source.CurrentConsumer(t.Context(), origin, want)
	if err != nil || facts.Consumer.Test || facts.BindingRef != "certbind_fixture" || facts.ConfigRevision != "1" ||
		facts.PluginVersion != "0.2.0+consumer-fixture" || facts.Consumer.ProfileID != want.ProfileID || facts.Consumer.SNI != want.SNI {
		t.Fatalf("没有读取真实 v2 配置事实: %v", err)
	}
	var operationsCount int
	if err := c.db.Reader().QueryRowContext(t.Context(), "SELECT COUNT(*) FROM operations").Scan(&operationsCount); err != nil || operationsCount != 0 {
		t.Fatal("读取消费者时创建或恢复了 operation")
	}
	intent := prerequisiteFixtureIntent(t)
	intent.Profiles[0].Hysteria2.TLS.BindingRef = "certbind_next"
	raw, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	storeAppliedPluginConfig(t, c.db, "core.xray", 2, string(raw))
	c.SetUpdater(loadStoredPluginUpdater(t, c.db))
	facts, err = source.CurrentConsumer(t.Context(), origin, want)
	if err != nil || facts.ConfigRevision != "2" || facts.BindingRef != "certbind_next" {
		t.Fatalf("既有来源未观察替换 updater: %v", err)
	}
}

func TestPrerequisiteConsumerSourceRejectsChangedScopeAndInvalidSnapshots(t *testing.T) {
	tests := []struct {
		name   string
		change func(*corev2.Intent, *certificates.Consumer, *hostauth.Invocation)
	}{
		{"节点", func(_ *corev2.Intent, want *certificates.Consumer, _ *hostauth.Invocation) { want.NodeID = "other" }},
		{"插件", func(_ *corev2.Intent, want *certificates.Consumer, _ *hostauth.Invocation) {
			want.PluginID = "core.other"
		}},
		{"用途", func(_ *corev2.Intent, want *certificates.Consumer, _ *hostauth.Invocation) {
			want.Purpose = "panel.https"
		}},
		{"profile", func(_ *corev2.Intent, want *certificates.Consumer, _ *hostauth.Invocation) { want.ProfileID = "other" }},
		{"SNI", func(_ *corev2.Intent, want *certificates.Consumer, _ *hostauth.Invocation) {
			want.SNI = "other.example.test"
		}},
		{"来源", func(_ *corev2.Intent, _ *certificates.Consumer, origin *hostauth.Invocation) {
			origin.PluginID = "domain.dns"
		}},
		{"实例", func(_ *corev2.Intent, _ *certificates.Consumer, origin *hostauth.Invocation) {
			origin.InstanceID = "other"
		}},
		{"旧版本", func(intent *corev2.Intent, _ *certificates.Consumer, _ *hostauth.Invocation) {
			intent.SchemaVersion = "1"
		}},
		{"错误协议", func(intent *corev2.Intent, _ *certificates.Consumer, _ *hostauth.Invocation) {
			intent.Profiles[0].Protocol = "vless"
		}},
		{"缺TLS", func(intent *corev2.Intent, _ *certificates.Consumer, _ *hostauth.Invocation) {
			intent.Profiles[0].Hysteria2.TLS = nil
		}},
		{"空绑定", func(intent *corev2.Intent, _ *certificates.Consumer, _ *hostauth.Invocation) {
			intent.Profiles[0].Hysteria2.TLS.BindingRef = ""
		}},
		{"未知用户", func(intent *corev2.Intent, _ *certificates.Consumer, _ *hostauth.Invocation) {
			intent.Profiles[0].Users = nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c, origin, want := prerequisiteConsumerFixture(t)
			intent := prerequisiteFixtureIntent(t)
			test.change(intent, &want, &origin)
			raw, err := json.Marshal(intent)
			if err != nil {
				t.Fatal(err)
			}
			storeAppliedPluginConfig(t, c.db, "core.xray", 2, string(raw))
			c.SetUpdater(loadStoredPluginUpdater(t, c.db))
			if _, err := c.PrerequisiteConsumerSource().CurrentConsumer(t.Context(), origin, want); !problem.HasCode(err, problem.PermissionDenied) {
				t.Fatalf("错误范围或配置被接受: %v", err)
			}
		})
	}
	for _, raw := range []string{`{}`, strings.Replace(prerequisiteConsumerFixtureJSON, `"schema_version":"2"`, `"schema_version":"2","schema_version":"2"`, 1),
		strings.Replace(prerequisiteConsumerFixtureJSON, `"binding_ref":"certbind_fixture"`, `"binding_ref":"certbind_fixture","test":true`, 1)} {
		c, origin, want := prerequisiteConsumerFixture(t)
		storeAppliedPluginConfig(t, c.db, "core.xray", 2, raw)
		c.SetUpdater(loadStoredPluginUpdater(t, c.db))
		if _, err := c.PrerequisiteConsumerSource().CurrentConsumer(t.Context(), origin, want); !problem.HasCode(err, problem.PermissionDenied) {
			t.Fatalf("空文档、重复字段或自报测试信任被接受: %v", err)
		}
	}
}

func TestPrerequisiteConsumerSourceRejectsUninstalledDisabledOrV1Contract(t *testing.T) {
	for _, change := range []func(*updater.Version){
		func(v *updater.Version) { v.Active = false },
		func(v *updater.Version) { v.Status = updater.VersionStopped },
		func(v *updater.Version) { v.InstallStatus = updater.InstallRemoved },
		func(v *updater.Version) { v.Manifest.ID = "core.other" },
		func(v *updater.Version) { v.Manifest.Version = "0.1.0" },
		func(v *updater.Version) { v.Manifest.Operations[0].APIVersion = "v1" },
		func(v *updater.Version) { v.Digest = "invalid" },
	} {
		c, origin, want := prerequisiteConsumerFixture(t)
		version := prerequisiteFixtureVersion()
		change(&version)
		storePrerequisiteFixtureVersion(t, c.db, version)
		c.SetUpdater(loadStoredPluginUpdater(t, c.db))
		if _, err := c.PrerequisiteConsumerSource().CurrentConsumer(t.Context(), origin, want); !problem.HasCode(err, problem.PermissionDenied) {
			t.Fatalf("错误安装事实被接受: %v", err)
		}
	}
	c, origin, want := prerequisiteConsumerFixture(t)
	if err := c.db.Update(t.Context(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(t.Context(), "INSERT INTO plugin_states(plugin_id,enabled,updated_at) VALUES ('core.xray',0,?)", storage.FormatTime(tx.Now()))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PrerequisiteConsumerSource().CurrentConsumer(t.Context(), origin, want); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("已停用插件仍可消费证书: %v", err)
	}
}

func TestPrerequisiteConsumerSnapshotIsPrivateAndReplacementInvalidatesRead(t *testing.T) {
	c, _, _ := prerequisiteConsumerFixture(t)
	snapshot, err := c.readPrerequisiteConfiguration(t.Context(), "core.xray")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(snapshot.config.Config)
	snapshot.config.Config[0] = 'x'
	current, _ := c.Updater().ActiveConfig("core.xray")
	if current.Config[0] != '{' {
		t.Fatal("快照调用者修改了 updater 配置")
	}
	snapshot.config.Config[0] = '{'
	c.SetUpdater(loadStoredPluginUpdater(t, c.db))
	if err := snapshot.requireCurrent(t.Context(), c); !problem.HasCode(err, problem.RevisionConflict) {
		t.Fatalf("换代 updater 混入原读取: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := snapshot.requireCurrent(ctx, c); !errors.Is(err, context.Canceled) {
		t.Fatalf("取消后的读取未拒绝: %v", err)
	}
}
