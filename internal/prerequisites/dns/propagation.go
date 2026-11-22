// SPDX-License-Identifier: AGPL-3.0-only

package dns

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
)

// ======================== 权威与递归 DNS 传播 ========================

type SourceKind string

const (
	Authoritative SourceKind = "authoritative"
	Recursive     SourceKind = "recursive"
)

// Observation 的来源由宿主解析器确定，插件不能传递 DNS 服务地址。
type Observation struct {
	Source      string     `json:"source"`
	Kind        SourceKind `json:"kind"`
	Values      []string   `json:"values"`
	CollectedAt time.Time  `json:"collected_at"`
	Matches     bool       `json:"matches"`
}

// Resolver 查询固定解析器和受控 zone 的权威服务器，不接受任意目标地址。
type Resolver interface {
	Observe(context.Context, Scope, string, RecordType) ([]Observation, error)
}

type PropagationRequest struct {
	Caller Caller
	Scope  Scope
	Record Record
}

type Propagation struct {
	Ready        bool          `json:"ready"`
	Code         string        `json:"code,omitempty"`
	Observations []Observation `json:"observations"`
	CollectedAt  time.Time     `json:"collected_at"`
	Attempts     int           `json:"attempts"`
}

type CheckerOptions struct {
	Resolver    Resolver
	Authorizer  Authorizer
	Clock       clock.Clock
	MaxAttempts int
	Interval    time.Duration
	MaxWait     time.Duration
}

// Checker 限制查询次数与总等待，不创建常驻忙轮询。
type Checker struct {
	resolver   Resolver
	authorizer Authorizer
	clock      clock.Clock
	attempts   int
	interval   time.Duration
	maxWait    time.Duration
}

func NewChecker(options CheckerOptions) (*Checker, error) {
	if options.Resolver == nil || options.Authorizer == nil {
		return nil, fault.New("BACKEND_REQUIRED", "解析检查需要受控解析器和授权后端")
	}
	if options.Clock == nil {
		options.Clock = clock.System{}
	}
	if options.MaxAttempts == 0 {
		options.MaxAttempts = 3
	}
	if options.Interval == 0 {
		options.Interval = 10 * time.Second
	}
	if options.MaxWait == 0 {
		options.MaxWait = 5 * time.Minute
	}
	if options.MaxAttempts < 1 || options.MaxAttempts > 5 || options.Interval < time.Second || options.Interval > time.Minute || options.MaxWait < options.Interval || options.MaxWait > 10*time.Minute {
		return nil, fault.New("VALIDATION_FAILED", "DNS 检查重试上限无效")
	}
	return &Checker{resolver: options.Resolver, authorizer: options.Authorizer, clock: options.Clock,
		attempts: options.MaxAttempts, interval: options.Interval, maxWait: options.MaxWait}, nil
}

// Check 只读取一次；TXT 允许同名多个值，其他类型要求当前目标值一致。
func (c *Checker) Check(ctx context.Context, request PropagationRequest) (Propagation, error) {
	if err := ctx.Err(); err != nil {
		return Propagation{}, err
	}
	if err := validateScope(request.Scope); err != nil {
		return Propagation{}, err
	}
	if !names.ID(request.Caller.OwnerID) {
		return Propagation{}, fault.New("PERMISSION_DENIED", "解析检查调用者无效")
	}
	record, err := normalizeRecord(request.Scope, request.Record, true)
	if err != nil {
		return Propagation{}, err
	}
	if err := c.authorizer.Authorize(ctx, request.Caller, request.Scope, Read); err != nil {
		return Propagation{}, err
	}
	observations, err := c.resolver.Observe(ctx, request.Scope, record.Name, record.Type)
	if err != nil {
		return Propagation{}, providerFailure(err)
	}
	if len(observations) == 0 || len(observations) > 16 {
		return Propagation{}, fault.New("DNS_NO_SOURCES", "缺少有效的权威或递归 DNS 采样")
	}
	result := Propagation{Ready: true, Observations: make([]Observation, 0, len(observations)), CollectedAt: c.clock.Now().UTC(), Attempts: 1}
	seen := map[string]bool{}
	authoritative, recursive := false, false
	for _, sample := range observations {
		if sample.Source == "" || len(sample.Source) > 253 || strings.ContainsAny(sample.Source, "\x00\r\n") || (sample.Kind != Authoritative && sample.Kind != Recursive) || sample.CollectedAt.IsZero() || len(sample.Values) > 128 {
			return Propagation{}, fault.New("DNS_INVALID_RESPONSE", "DNS 来源或响应格式无效")
		}
		key := string(sample.Kind) + "\x00" + sample.Source
		if seen[key] {
			return Propagation{}, fault.New("DNS_INVALID_RESPONSE", "DNS 采样来源重复")
		}
		seen[key] = true
		if sample.Kind == Authoritative {
			authoritative = true
		} else {
			recursive = true
		}
		values := make([]string, 0, len(sample.Values))
		for _, value := range sample.Values {
			candidate := record
			candidate.Value = value
			normalized, err := normalizeRecord(request.Scope, candidate, true)
			if err != nil {
				return Propagation{}, fault.New("DNS_INVALID_RESPONSE", "DNS 返回不支持的记录值")
			}
			values = append(values, normalized.Value)
		}
		slices.Sort(values)
		values = slices.Compact(values)
		sample.Values = values
		sample.Matches = slices.Contains(values, record.Value) && (record.Type == TXT || len(values) == 1)
		result.Ready = result.Ready && sample.Matches
		result.Observations = append(result.Observations, sample)
	}
	if !authoritative || !recursive {
		return Propagation{}, fault.New("DNS_NO_SOURCES", "必须同时采样权威与递归 DNS")
	}
	if !result.Ready {
		result.Code = "DNS_NOT_PROPAGATED"
		if record.Type == AAAA {
			result.Code = "AAAA_NODE_MISMATCH"
		}
	}
	return result, nil
}

// Wait 按 Retry-After 与固定上限重读，取消或撤权立即结束。
func (c *Checker) Wait(ctx context.Context, request PropagationRequest) (Propagation, error) {
	deadline := c.clock.Now().Add(c.maxWait)
	bounded, cancel := context.WithTimeout(ctx, c.maxWait)
	defer cancel()
	var last Propagation
	for attempt := 1; attempt <= c.attempts; attempt++ {
		result, err := c.Check(bounded, request)
		result.Attempts = attempt
		last = result
		if err == nil && result.Ready {
			return result, nil
		}
		if err != nil && fault.Code(err) != "PROVIDER_UNAVAILABLE" && fault.Code(err) != "RATE_LIMITED" {
			return result, err
		}
		if attempt == c.attempts {
			if err != nil {
				return result, err
			}
			return result, fault.New(result.Code, "DNS 传播未在查询次数上限内完成")
		}
		delay := c.interval
		if retry := fault.Retry(err).Sub(c.clock.Now()); retry > delay {
			delay = retry
		}
		if !c.clock.Now().Add(delay).Before(deadline) {
			return result, fault.New("DNS_TIMEOUT", "DNS 传播等待达到时间上限")
		}
		select {
		case <-bounded.Done():
			return result, bounded.Err()
		case <-c.clock.After(delay):
		}
	}
	return last, fault.New("DNS_TIMEOUT", "DNS 传播检查已结束")
}
