// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// ======================== 真实主体/Updater，候选预检无持久副作用 ========================

const configurationV1Fixture = `{"schema_version":"1","enabled":false,
"inbound":{"id":"v-main","listen":"127.0.0.1","port":18443,"protocol":"vless","transport":"raw","flow":"xtls-rprx-vision",
"security":{"mode":"reality","target":"example.test:443","server_names":["example.test"],"private_key":"new-preview-private-key","short_ids":["ab"]},
"users":[{"id":"alice","uuid":"new-preview-uuid"}]},"outbound":{"type":"direct"}}`

const configurationV2FixtureSchema = `{"type":"object","properties":{"profiles":{"type":"array","items":{"properties":{"users":{"type":"array","items":{"properties":{"auth":{"x-secret":true}}}}}}}}}`

func configurationFixture(t *testing.T, schema, config []byte) (prerequisiteReservationFixture, PluginConfigurationInput) {
	t.Helper()
	f := newPrerequisiteReservationFixture(t)
	version := prerequisiteFixtureVersion()
	digest := sha256.Sum256(schema)
	version.Manifest.Files[version.Manifest.Config.Schema] = "sha256:" + hex.EncodeToString(digest[:])
	storePrerequisiteFixtureVersion(t, f.c.db, version)
	f.c.SetUpdater(loadStoredPluginUpdater(t, f.c.db))
	return f, PluginConfigurationInput{Actor: f.host.Human, PluginID: "core.xray", ExpectedRevision: 0, Schema: schema, Config: config}
}

func configurationCounts(t *testing.T, c *Controller) [3]int {
	t.Helper()
	var counts [3]int
	for index, table := range []string{"secrets", "plugin_configs", "operations"} {
		if err := c.db.Reader().QueryRowContext(t.Context(), "SELECT COUNT(*) FROM "+table).Scan(&counts[index]); err != nil {
			t.Fatal(err)
		}
	}
	return counts
}

func TestPluginConfigurationPreflightAcceptsCompleteV1WithoutPersistingSecrets(t *testing.T) {
	schema, err := os.ReadFile("../../plugins/builtin/core.xray/schemas/config.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	f, input := configurationFixture(t, schema, []byte(configurationV1Fixture))
	before := configurationCounts(t, f.c)
	original := bytes.Clone(input.Config)
	if err := f.c.ValidatePluginConfiguration(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	if configurationCounts(t, f.c) != before || !bytes.Equal(input.Config, original) {
		t.Fatal("普通核心配置预检创建了秘密/配置/operation或修改原输入")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := f.c.ValidatePluginConfiguration(ctx, input); err == nil {
		t.Fatal("取消上下文继续验证")
	}
}

func TestPluginConfigurationPreflightRejectsUnreservedH2BeforeWrites(t *testing.T) {
	raw := strings.Replace(prerequisiteConsumerFixtureJSON, `{"$secret":"sec_00000000000000000000000002"}`, `"new-preview-auth"`, 1)
	f, input := configurationFixture(t, []byte(configurationV2FixtureSchema), []byte(raw))
	before := configurationCounts(t, f.c)
	if err := f.c.ValidatePluginConfiguration(t.Context(), input); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("未预留绑定进入配置保存: %v", err)
	}
	if configurationCounts(t, f.c) != before {
		t.Fatal("未预留绑定拒绝后产生持久副作用")
	}
	f.c.prerequisites.Store(nil)
	if err := f.c.ValidatePluginConfiguration(t.Context(), input); !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("缺真实绑定后端仍保存H2配置: %v", err)
	}
}

func TestPluginConfigurationPreflightRejectsRawDuplicatesScopeAndChangedSchema(t *testing.T) {
	tests := []struct {
		name   string
		change func(*PluginConfigurationInput)
		code   problem.Code
	}{
		{"重复版本", func(input *PluginConfigurationInput) {
			input.Config = []byte(strings.Replace(configurationV1Fixture, `"schema_version":"1"`, `"schema_version":"1","schema_version":"1"`, 1))
		}, problem.ValidationFailed},
		{"重复嵌套", func(input *PluginConfigurationInput) {
			input.Config = []byte(strings.Replace(configurationV1Fixture, `"id":"alice"`, `"id":"alice","id":"alice"`, 1))
		}, problem.ValidationFailed},
		{"配置版本", func(input *PluginConfigurationInput) { input.ExpectedRevision = 1 }, problem.RevisionConflict},
		{"schema换代", func(input *PluginConfigurationInput) { input.Schema = append(bytes.Clone(input.Schema), ' ') }, problem.RevisionConflict},
		{"系统主体", func(input *PluginConfigurationInput) { input.Actor.Kind = "system" }, problem.PermissionDenied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			schema, err := os.ReadFile("../../plugins/builtin/core.xray/schemas/config.schema.json")
			if err != nil {
				t.Fatal(err)
			}
			f, input := configurationFixture(t, schema, []byte(configurationV1Fixture))
			test.change(&input)
			before := configurationCounts(t, f.c)
			if err := f.c.ValidatePluginConfiguration(t.Context(), input); !problem.HasCode(err, test.code) {
				t.Fatalf("无效配置预检错误码不符: %v", err)
			}
			if configurationCounts(t, f.c) != before {
				t.Fatal("被拒绝的候选产生持久副作用")
			}
		})
	}
}
