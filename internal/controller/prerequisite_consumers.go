// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"bytes"
	"context"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/updater"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/hostauth"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	corev1 "github.com/qwq-panel/qwq/sdk/coreapi"
	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
)

// ======================== 已安装契约与已提交配置的本地事实 ========================

type prerequisiteConsumerSource struct{ controller *Controller }

// PrerequisiteConsumerSource 每次读取当前 updater，不缓存消费者或授权结论。
// 已结束 operation 的 origin 仅用于核对来源范围，不能恢复旧 executor。
func (c *Controller) PrerequisiteConsumerSource() hostauth.ConsumerSource {
	return prerequisiteConsumerSource{controller: c}
}

type prerequisiteConfiguration struct {
	updater *updater.Updater
	version updater.Version
	config  updater.ConfigRevision
	found   bool
	coreV2  bool
}

func (s prerequisiteConsumerSource) CurrentConsumer(ctx context.Context, origin hostauth.Invocation, input certificates.Consumer) (hostauth.ConsumerFacts, error) {
	if ctx == nil {
		return hostauth.ConsumerFacts{}, prerequisiteSourceUnavailable()
	}
	if err := ctx.Err(); err != nil {
		return hostauth.ConsumerFacts{}, err
	}
	c := s.controller
	if c == nil || c.closed.Load() || c.Updater() == nil {
		return hostauth.ConsumerFacts{}, prerequisiteSourceUnavailable()
	}
	want, err := c.prerequisiteConsumer(input)
	if err != nil || !validPrerequisiteOrigin(origin) {
		return hostauth.ConsumerFacts{}, prerequisiteConsumerDenied()
	}
	snapshot, err := c.readPrerequisiteConfiguration(ctx, want.PluginID)
	if err != nil {
		return hostauth.ConsumerFacts{}, err
	}
	defer clear(snapshot.config.Config)
	if !snapshot.found {
		return hostauth.ConsumerFacts{}, prerequisiteConsumerDenied()
	}
	intent, err := corev2.Decode(snapshot.config.Config)
	if err != nil || corev2.Validate(intent) != nil {
		return hostauth.ConsumerFacts{}, prerequisiteConsumerDenied()
	}
	// 停用 profile 仍是已提交配置引用，首次配置可以先保存再显式绑定/应用。
	// 这里不把 desired 配置解释为正在运行的数据面或已部署 generation。
	for _, profile := range intent.Profiles {
		if profile.ID != want.ProfileID {
			continue
		}
		tls, _, ok := ExtractProfileTLSBinding(profile)
		if !ok || !ProfileMatchesConsumerPurpose(profile, want.Purpose) {
			return hostauth.ConsumerFacts{}, prerequisiteConsumerDenied()
		}
		actual, err := certificates.CanonicalConsumer(certificates.Consumer{NodeID: want.NodeID, PluginID: snapshot.version.PluginID,
			ProfileID: profile.ID, SNI: tls.ServerName, Purpose: want.Purpose})
		if err != nil || actual != want || !names.ID(tls.BindingRef) {
			return hostauth.ConsumerFacts{}, prerequisiteConsumerDenied()
		}
		if err := snapshot.requireCurrent(ctx, c); err != nil {
			return hostauth.ConsumerFacts{}, err
		}
		return hostauth.ConsumerFacts{Consumer: actual, BindingRef: tls.BindingRef,
			ConfigRevision: strconv.FormatInt(snapshot.config.Revision, 10), PluginVersion: snapshot.version.Version}, nil
	}
	return hostauth.ConsumerFacts{}, prerequisiteConsumerDenied()
}

func (c *Controller) prerequisiteConsumer(input certificates.Consumer) (certificates.Consumer, error) {
	consumer, err := certificates.CanonicalConsumer(input)
	if err != nil || c == nil || c.ops == nil || consumer.NodeID != c.ops.NodeID() || consumer.PluginID != "core.xray" ||
		consumer.Purpose == "panel.https" || !IsValidCertificateConsumerPurpose(consumer.Purpose) || !corev1.ValidID(consumer.ProfileID) {
		return certificates.Consumer{}, prerequisiteConsumerDenied()
	}
	// Core Intent v2 没有测试信任字段；只能返回真实契约允许的生产事实。
	consumer.Test = false
	return consumer, nil
}

func validPrerequisiteOrigin(origin hostauth.Invocation) bool {
	return origin.PluginID == "tls.certificates" && origin.InstanceID == operations.ControllerDispatchInstance &&
		names.ID(origin.OperationID) && names.ID(origin.Operation) && strings.HasPrefix(origin.Subject, "plugins/tls.certificates/resources/") &&
		!strings.ContainsAny(origin.Subject, "\\\x00\r\n")
}

func (c *Controller) readPrerequisiteConfiguration(ctx context.Context, pluginID string) (prerequisiteConfiguration, error) {
	return c.readPluginConfiguration(ctx, pluginID, true)
}

func (c *Controller) readPluginConfiguration(ctx context.Context, pluginID string, coreV2 bool) (prerequisiteConfiguration, error) {
	if err := ctx.Err(); err != nil {
		return prerequisiteConfiguration{}, err
	}
	u := c.Updater()
	if c.closed.Load() || u == nil {
		return prerequisiteConfiguration{}, prerequisiteSourceUnavailable()
	}
	version, installed := u.Active(pluginID)
	if !installed || !validInstalledConfigurationVersion(version, pluginID) || (coreV2 && !supportsPrerequisiteConsumer(version, pluginID)) {
		return prerequisiteConfiguration{}, prerequisiteConsumerDenied()
	}
	enabled, err := u.Enabled(ctx, pluginID)
	if err != nil {
		return prerequisiteConfiguration{}, err
	}
	if !enabled {
		return prerequisiteConfiguration{}, prerequisiteConsumerDenied()
	}
	config, found := u.ActiveConfig(pluginID)
	if found && (config.PluginID != pluginID || config.Revision <= 0 || !config.Active || config.AppliedAt.IsZero() ||
		len(config.Config) == 0 || len(config.Config) > corev2.MaxSize) {
		return prerequisiteConfiguration{}, prerequisiteConsumerDenied()
	}
	config.Config = bytes.Clone(config.Config)
	snapshot := prerequisiteConfiguration{updater: u, version: version, config: config, found: found, coreV2: coreV2}
	if err := snapshot.requireCurrent(ctx, c); err != nil {
		clear(config.Config)
		return prerequisiteConfiguration{}, err
	}
	return snapshot, nil
}

// 已有 operation.api_version 显式区分原生 Core v2 驱动，不新增 manifest/ABI 字段。
// v1 安装包即使残留 v2 JSON 也不能成为支持 Hysteria2 的安装事实。
func supportsPrerequisiteConsumer(version updater.Version, pluginID string) bool {
	m := version.Manifest
	if !validInstalledConfigurationVersion(version, pluginID) || m.Placement != operations.PlacementNode {
		return false
	}
	for _, operation := range m.Operations {
		if operation.Name == "core.apply" {
			return operation.APIVersion == "v2" && operation.Permission == "core.xray:apply" && operation.Mode == operations.ModeJob &&
				operation.Effect == operations.EffectWrite && validPrerequisiteDigest(m.Files[operation.RequestSchema])
		}
	}
	return false
}

func validInstalledConfigurationVersion(version updater.Version, pluginID string) bool {
	m := version.Manifest
	return version.PluginID == pluginID && version.Active && version.Status == updater.VersionActive && version.InstallStatus == updater.InstallInstalled &&
		version.Version != "" && !version.ActivatedAt.IsZero() && validPrerequisiteDigest(version.Digest) && m != nil && m.ID == pluginID &&
		m.Version == version.Version && m.Config.Schema != "" && validPrerequisiteDigest(m.Files[m.Config.Schema])
}

func validPrerequisiteDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	hexadecimal := strings.TrimPrefix(value, "sha256:")
	raw, err := hex.DecodeString(hexadecimal)
	return err == nil && hex.EncodeToString(raw) == hexadecimal
}

// ======================== 读取前后复核同一配置代际 ========================

func (snapshot prerequisiteConfiguration) requireCurrent(ctx context.Context, c *Controller) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c == nil || c.closed.Load() || c.Updater() != snapshot.updater {
		return prerequisiteConsumerChanged()
	}
	version, installed := snapshot.updater.Active(snapshot.version.PluginID)
	config, found := snapshot.updater.ActiveConfig(snapshot.version.PluginID)
	if !installed || !validInstalledConfigurationVersion(version, snapshot.version.PluginID) ||
		(snapshot.coreV2 && !supportsPrerequisiteConsumer(version, snapshot.version.PluginID)) || !samePrerequisiteVersion(snapshot.version, version) ||
		found != snapshot.found || (found && (config.PluginID != snapshot.config.PluginID || config.Revision != snapshot.config.Revision ||
		config.Seq != snapshot.config.Seq || config.Active != snapshot.config.Active || !config.AppliedAt.Equal(snapshot.config.AppliedAt) ||
		!bytes.Equal(config.Config, snapshot.config.Config))) {
		return prerequisiteConsumerChanged()
	}
	enabled, err := snapshot.updater.Enabled(ctx, snapshot.version.PluginID)
	if err != nil {
		return err
	}
	if !enabled || c.Updater() != snapshot.updater || c.closed.Load() {
		return prerequisiteConsumerChanged()
	}
	return ctx.Err()
}

func samePrerequisiteVersion(before, after updater.Version) bool {
	return before.PluginID == after.PluginID && before.Version == after.Version && before.Digest == after.Digest && before.Revision == after.Revision &&
		before.ActivatedAt.Equal(after.ActivatedAt) && before.Manifest.Config == after.Manifest.Config
}

func prerequisiteSourceUnavailable() error {
	return problem.New(problem.Unavailable, "证书消费者的宿主配置来源尚未装配。")
}

func prerequisiteConsumerDenied() error {
	return problem.New(problem.PermissionDenied, "实际安装契约或已提交配置不能确认该证书消费者。")
}

func prerequisiteConsumerChanged() error {
	return problem.New(problem.RevisionConflict, "证书消费者的安装或配置在读取期间已经变化。")
}
