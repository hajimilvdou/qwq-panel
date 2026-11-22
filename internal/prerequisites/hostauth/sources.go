// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
)

// ======================== 控制器事实与实际服务身份的窄接缝 ========================

// ConsumerFacts 只描述本次已确认配置，不是可以缓存或序列化恢复的授权许可。
// Test、profile/SNI/用途必须来自真实宿主配置，不能由请求的布尔标志替代。
type ConsumerFacts struct {
	Consumer       certificates.Consumer
	ConfigRevision string
	PluginVersion  string
	BindingRef     string
}

// ConsumerSource 由宿主从真实 Updater/节点配置构造；每个关键阶段重新调用。
type ConsumerSource interface {
	CurrentConsumer(context.Context, Invocation, certificates.Consumer) (ConsumerFacts, error)
}

// ConsumerReservationFacts 来自实际安装能力、当前配置版本与宿主授权；
// 规划中的 profile 不因此成为已有配置，Test 不接受请求自报。
type ConsumerReservationFacts struct {
	Consumer       certificates.Consumer
	ConfigRevision string
	PluginVersion  string
}

// ConsumerReservationSource 核验拟建消费者与真实 operation/配置写权限，
// 不生成 binding ID，也不把计划参数冒充 CurrentConsumer 的配置事实。
type ConsumerReservationSource interface {
	AuthorizeReservation(context.Context, Invocation, certificates.Consumer) (ConsumerReservationFacts, error)
}

// ConsumerConfiguration 仅由宿主解析真实候选配置，不携带 owner 或权限。
type ConsumerConfiguration struct {
	BindingRef string
	Consumer   certificates.Consumer
}

// RenewalServiceRequest 只携带已确认的固定策略范围，不重复可被换用的 owner/证书字段。
type RenewalServiceRequest struct {
	PolicyID  string
	Scope     certificates.RenewalScope
	ExpiresAt time.Time
}

// RenewalServiceSource 只能使用实际人类会话创建或确认受限服务账号。
// Session-less Approval 元数据和 RPC 提供的 actor 不能用于身份 bootstrap。
type RenewalServiceSource interface {
	EnsureRenewalService(context.Context, actor.Actor, RenewalServiceRequest) (string, error)
}

func (ConsumerFacts) String() string   { return "hostauth.ConsumerFacts{[REDACTED]}" }
func (ConsumerFacts) GoString() string { return "hostauth.ConsumerFacts{[REDACTED]}" }
func (ConsumerReservationFacts) String() string {
	return "hostauth.ConsumerReservationFacts{[REDACTED]}"
}
func (ConsumerReservationFacts) GoString() string {
	return "hostauth.ConsumerReservationFacts{[REDACTED]}"
}
func (RenewalServiceRequest) String() string   { return "hostauth.RenewalServiceRequest{[REDACTED]}" }
func (RenewalServiceRequest) GoString() string { return "hostauth.RenewalServiceRequest{[REDACTED]}" }
