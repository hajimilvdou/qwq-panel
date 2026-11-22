// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"

	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
)

// ======================== 业务 payload 固定到已接受原意图 ========================

func validateDNSIntent(operation string, input DNSArgs) error {
	noRecordTarget := input.Name == "" && input.Type == "" && input.Value == ""
	valid := false
	switch operation {
	case "records.list":
		valid = input.AttemptID == "" && input.Change == nil && noRecordTarget
	case "records.apply":
		valid = names.ID(input.AttemptID) && input.Change != nil && noRecordTarget
	case "records.reconcile":
		valid = names.ID(input.AttemptID) && input.Change == nil && noRecordTarget
	case "dns.check":
		valid = input.AttemptID == "" && input.Change == nil && input.Name != "" && input.Type.Supported() && input.Value != ""
	}
	if !valid {
		return fault.New("VALIDATION_FAILED", "DNS operation 的参数与动作不匹配")
	}
	return nil
}

// AcceptedDNSRequest 为受控 capability 后端构造唯一写请求。RPC 中的替代
// change、caller、attempt 或 scope 不能进入执行器；原 expected_revision 仍生效。
func (a *Authority) AcceptedDNSRequest(ctx context.Context) (dns.Request, error) {
	value, err := a.current(ctx)
	if err != nil {
		return dns.Request{}, err
	}
	input, err := DecodeArguments[DNSArgs](ctx, a)
	if err != nil {
		return dns.Request{}, err
	}
	grant, found := ctx.Value(dnsExecutionKey{}).(*dnsExecution)
	if !found || grant == nil || input.Change == nil || value.invocation.Operation != "records.apply" {
		return dns.Request{}, fault.New("PERMISSION_DENIED", "当前执行上下文没有原 DNS 写意图")
	}
	caller := dns.Caller{OwnerID: a.ownerID, OperationID: value.invocation.OperationID}
	if err := a.checkDNS(ctx, caller, grant.scope, dns.Manage); err != nil {
		return dns.Request{}, err
	}
	if !validDigest(value.snapshot.ExpectedRevision) {
		return dns.Request{}, fault.New("VALIDATION_FAILED", "原 DNS 意图缺少完整快照版本")
	}
	return dns.Request{Caller: caller, Scope: grant.scope, AttemptID: input.AttemptID,
		ExpectedRevision: value.snapshot.ExpectedRevision, Change: *input.Change}, nil
}

// AcceptedDNSCheck 复用同一记录校验；传播查询也只能检查原已接受的目标值。
func (a *Authority) AcceptedDNSCheck(ctx context.Context) (dns.Record, error) {
	value, err := a.current(ctx)
	if err != nil {
		return dns.Record{}, err
	}
	input, err := DecodeArguments[DNSArgs](ctx, a)
	if err != nil {
		return dns.Record{}, err
	}
	grant, found := ctx.Value(dnsExecutionKey{}).(*dnsExecution)
	if !found || grant == nil || value.invocation.Operation != "dns.check" {
		return dns.Record{}, fault.New("PERMISSION_DENIED", "当前执行上下文没有原 DNS 检查意图")
	}
	caller := dns.Caller{OwnerID: a.ownerID, OperationID: value.invocation.OperationID}
	if err := a.checkDNS(ctx, caller, grant.scope, dns.Read); err != nil {
		return dns.Record{}, err
	}
	return dns.CanonicalRecord(grant.scope, dns.Record{Type: input.Type, Name: input.Name, Value: input.Value, TTL: 60})
}
