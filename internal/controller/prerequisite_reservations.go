// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"strconv"

	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/hostauth"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	corev1 "github.com/qwq-panel/qwq/sdk/coreapi"
	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
)

// ======================== 拟建消费者依赖真实私有派发与配置写权限 ========================

// PrerequisiteReservationSource 返回计划核验器，结果不能冒充已有 profile。
func (c *Controller) PrerequisiteReservationSource() hostauth.ConsumerReservationSource {
	return prerequisiteConsumerSource{controller: c}
}

func (s prerequisiteConsumerSource) AuthorizeReservation(ctx context.Context, origin hostauth.Invocation, input certificates.Consumer) (hostauth.ConsumerReservationFacts, error) {
	if ctx == nil {
		return hostauth.ConsumerReservationFacts{}, prerequisiteSourceUnavailable()
	}
	if err := ctx.Err(); err != nil {
		return hostauth.ConsumerReservationFacts{}, err
	}
	c := s.controller
	authority := c.prerequisiteAuthority()
	if authority == nil {
		return hostauth.ConsumerReservationFacts{}, prerequisiteSourceUnavailable()
	}
	want, err := c.prerequisiteConsumer(input)
	if err != nil {
		return hostauth.ConsumerReservationFacts{}, err
	}
	actualOrigin, err := authority.CurrentInvocation(ctx)
	if err != nil {
		return hostauth.ConsumerReservationFacts{}, err
	}
	if actualOrigin != origin || !validPrerequisiteOrigin(origin) || origin.Operation != "bindings.reserve" {
		return hostauth.ConsumerReservationFacts{}, prerequisiteConsumerDenied()
	}
	args, err := hostauth.DecodeArguments[hostauth.ReserveBindingArgs](ctx, authority)
	if err != nil {
		return hostauth.ConsumerReservationFacts{}, err
	}
	accepted, err := c.prerequisiteConsumer(args.Consumer)
	if err != nil || accepted != want || !names.ID(args.CertificateID) ||
		origin.Subject != "plugins/tls.certificates/resources/certificates/"+args.CertificateID {
		return hostauth.ConsumerReservationFacts{}, prerequisiteConsumerDenied()
	}
	var snapshot prerequisiteConfiguration
	if want.PluginID == "core.xray" {
		snapshot, err = c.readPrerequisiteConfiguration(ctx, want.PluginID)
	} else {
		snapshot, err = c.readPluginConfiguration(ctx, want.PluginID, false)
	}
	if err != nil {
		return hostauth.ConsumerReservationFacts{}, err
	}
	defer clear(snapshot.config.Config)
	revision := "0"
	if snapshot.found {
		if want.PluginID == "core.xray" {
			// 新安装 v2 驱动可以显式迁移旧 v1 快照；这只核对已有配置前置条件，
			// 不把旧 VLESS 或待建立 H2 profile 当成 CurrentConsumer 的事实。
			if !validPrerequisiteConfiguration(snapshot.config.Config) {
				return hostauth.ConsumerReservationFacts{}, prerequisiteConsumerDenied()
			}
		}
		revision = strconv.FormatInt(snapshot.config.Revision, 10)
	}
	if revision != args.ExpectedConfigRevision {
		return hostauth.ConsumerReservationFacts{}, prerequisiteConsumerChanged()
	}
	if err := authority.AuthorizeCurrent(ctx, "host.plugins:config", authz.Resource{Name: "host.plugins", NodeID: want.NodeID,
		Action: "host.plugins.config", Subject: "plugins/" + want.PluginID + "/config"}); err != nil {
		return hostauth.ConsumerReservationFacts{}, err
	}
	if err := snapshot.requireCurrent(ctx, c); err != nil {
		return hostauth.ConsumerReservationFacts{}, err
	}
	current, err := authority.CurrentInvocation(ctx)
	if err != nil {
		return hostauth.ConsumerReservationFacts{}, err
	}
	if current != origin || c.prerequisiteAuthority() != authority {
		return hostauth.ConsumerReservationFacts{}, prerequisiteConsumerDenied()
	}
	return hostauth.ConsumerReservationFacts{Consumer: want, ConfigRevision: revision, PluginVersion: snapshot.version.Version}, nil
}

func validPrerequisiteConfiguration(raw []byte) bool {
	if intent, err := corev2.Decode(raw); err == nil && corev2.Validate(intent) == nil {
		return true
	}
	intent, err := corev1.Decode(raw)
	return err == nil && corev1.Validate(intent) == nil
}
