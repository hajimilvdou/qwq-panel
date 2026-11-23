// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/hostauth"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/secrets"
	corev1 "github.com/qwq-panel/qwq/sdk/coreapi"
	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
)

// ======================== 候选配置从原始输入到精确消费引用 ========================

// PluginConfigurationInput 由真实宿主配置边界构造，Actor 不能来自请求 DTO。
type PluginConfigurationInput struct {
	Actor            actor.Actor
	PluginID         string
	ExpectedRevision int64
	Schema           json.RawMessage
	Config           json.RawMessage
}

func (PluginConfigurationInput) String() string {
	return "controller.PluginConfigurationInput{[REDACTED]}"
}
func (PluginConfigurationInput) GoString() string {
	return "controller.PluginConfigurationInput{[REDACTED]}"
}
func (PluginConfigurationInput) MarshalJSON() ([]byte, error) {
	return []byte(`{"redacted":true}`), nil
}

// ValidatePluginConfiguration 在秘密提取前校验完整候选；实际保存适配器也再次调用。
// 普通无证书配置不会创建 Invocation、预留或材料，权限仍使用当前实际主体。
func (c *Controller) ValidatePluginConfiguration(ctx context.Context, input PluginConfigurationInput) error {
	if ctx == nil || c == nil || c.closed.Load() || c.auth == nil || c.ops == nil {
		return prerequisiteSourceUnavailable()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !names.ID(input.PluginID) || input.Actor.Valid() != nil || input.Actor.Kind == actor.System || input.ExpectedRevision < 0 {
		return prerequisiteConsumerDenied()
	}
	resource := authz.Resource{Name: "host.plugins", NodeID: c.ops.NodeID(), Action: "host.plugins.config", Subject: "plugins/" + input.PluginID + "/config"}
	if err := c.auth.Authorize(ctx, input.Actor, "host.plugins:config", resource); err != nil {
		return err
	}
	if input.PluginID != "core.xray" {
		return ctx.Err()
	}
	// 原文先拒绝重复键、UTF-8/对象/深度错误；投影不能覆盖掉攻击者的重复成员。
	var envelope map[string]json.RawMessage
	if !hostauth.DecodePersistedObject(input.Config, &envelope, corev2.MaxSize) {
		return invalidCoreConfiguration()
	}
	var version string
	if json.Unmarshal(envelope["schema_version"], &version) != nil || (version != "1" && version != "2") {
		return invalidCoreConfiguration()
	}
	snapshot, err := c.readPluginConfiguration(ctx, input.PluginID, version == "2")
	if err != nil {
		return err
	}
	defer clear(snapshot.config.Config)
	actualRevision := int64(0)
	if snapshot.found {
		actualRevision = snapshot.config.Revision
	}
	if input.ExpectedRevision != actualRevision {
		return prerequisiteConsumerChanged()
	}
	schemaDigest := sha256.Sum256(input.Schema)
	if "sha256:"+hex.EncodeToString(schemaDigest[:]) != snapshot.version.Manifest.Files[snapshot.version.Manifest.Config.Schema] {
		return prerequisiteConsumerChanged()
	}
	var consumers []hostauth.ConsumerConfiguration
	err = secrets.ValidateWithSecretReferences(input.Schema, input.Config, func(projected []byte) error {
		if version == "1" {
			intent, err := corev1.Decode(projected)
			if err != nil || corev1.Validate(intent) != nil {
				return invalidCoreConfiguration()
			}
			return nil
		}
		intent, err := corev2.Decode(projected)
		if err != nil || corev2.Validate(intent) != nil {
			return invalidCoreConfiguration()
		}
		for _, profile := range intent.Profiles {
			binding, purpose, ok := ExtractProfileTLSBinding(profile)
			if !ok {
				continue
			}
			consumer, err := certificates.CanonicalConsumer(certificates.Consumer{NodeID: c.ops.NodeID(), PluginID: input.PluginID,
				ProfileID: profile.ID, SNI: binding.ServerName, Purpose: purpose})
			if err != nil {
				return invalidCoreConfiguration()
			}
			consumers = append(consumers, hostauth.ConsumerConfiguration{BindingRef: binding.BindingRef, Consumer: consumer})
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(consumers) != 0 {
		authority := c.prerequisiteAuthority()
		if authority == nil {
			return prerequisiteSourceUnavailable()
		}
		if err := authority.ValidateConsumerConfiguration(ctx, input.Actor, c.ops.NodeID(), input.PluginID,
			strconv.FormatInt(input.ExpectedRevision, 10), consumers); err != nil {
			return prerequisiteConfigurationProblem(err)
		}
	}
	if err := snapshot.requireCurrent(ctx, c); err != nil {
		return err
	}
	return c.auth.Authorize(ctx, input.Actor, "host.plugins:config", resource)
}

func invalidCoreConfiguration() error {
	return problem.Validation(problem.Violation{Pointer: "/config", Code: "INVALID_CORE_CONFIGURATION", Message: "必须提供合法的完整核心配置。"})
}

func prerequisiteConfigurationProblem(err error) error {
	var known *problem.Error
	if errors.As(err, &known) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	code := problem.PermissionDenied
	switch fault.Code(err) {
	case "REVISION_CONFLICT":
		code = problem.RevisionConflict
	case "NOT_FOUND":
		code = problem.NotFound
	case "BACKEND_REQUIRED", "INTERNAL":
		code = problem.Unavailable
	case "VALIDATION_FAILED":
		code = problem.ValidationFailed
	}
	return problem.New(code, "证书消费登记与当前配置不符，请刷新配置及绑定状态。")
}
