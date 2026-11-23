// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/coreproc"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/metrics"
	"github.com/qwq-panel/qwq/sdk/coreapi"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

type counterReader interface {
	ReadCounters(context.Context) (coreproc.CounterSnapshot, error)
}

func decodeObserveInput(payload []byte) (metrics.Filter, error) {
	invalid := pluginsdk.Errorf("INVALID_REQUEST", "统计过滤字段或稳定 ID 无效")
	if len(payload) > 16<<10 {
		return metrics.Filter{}, invalid
	}
	if len(bytes.TrimSpace(payload)) == 0 {
		payload = []byte(`{}`)
	}
	var fields map[string]json.RawMessage
	if sandbox.DecodeHelperDocument(payload, &fields) != nil {
		return metrics.Filter{}, invalid
	}
	filter := metrics.Filter{}
	for name, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return metrics.Filter{}, invalid
		}
		switch name {
		case "kind":
			if json.Unmarshal(value, &filter.Kind) != nil || filter.Kind != "inbound" && filter.Kind != "user" {
				return metrics.Filter{}, invalid
			}
		case "ids":
			if json.Unmarshal(value, &filter.IDs) != nil || len(filter.IDs) > coreapi.MaxUsers {
				return metrics.Filter{}, invalid
			}
			seen := map[string]bool{}
			for _, id := range filter.IDs {
				if _, err := coreapi.UserEmail(id); err != nil || seen[id] {
					return metrics.Filter{}, invalid
				}
				seen[id] = true
			}
		default:
			return metrics.Filter{}, invalid
		}
	}
	return filter, nil
}

func (i *instance) observe(ctx context.Context, request pluginsdk.Request) (pluginsdk.Response, error) {
	filter, err := decodeObserveInput(request.Payload)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	if i.driver == nil {
		return pluginsdk.Response{}, skeletonError()
	}
	result, err := i.driver.observe(ctx, filter)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	return readResponse(result)
}

func (d *driverRuntime) observe(parent context.Context, filter metrics.Filter) (metrics.Result, error) {
	unavailable := pluginsdk.Errorf("CORE_API_UNAVAILABLE", "当前核心统计暂不可用")
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	before := d.controller.Observe()
	if before.Busy || !before.Active || !d.trusted {
		return metrics.Result{}, unavailable
	}
	metadata, err := d.store.Committed(ctx)
	if err != nil {
		return metrics.Result{}, mapApplyError(err)
	}
	if metadata == nil || !metadata.Current.Enabled || metadata.State != "RUNNING" {
		return metrics.Result{}, unavailable
	}
	reader, ok := d.process.(counterReader)
	if !ok {
		return metrics.Result{}, unavailable
	}
	snapshot, err := reader.ReadCounters(ctx)
	if err != nil {
		if parent.Err() != nil {
			return metrics.Result{}, parent.Err()
		}
		return metrics.Result{}, unavailable
	}
	after := d.controller.Observe()
	if after.Busy || before.Serial != after.Serial || !after.Active || snapshot.Digest != metadata.Current.Digest || snapshot.Epoch == "" {
		return metrics.Result{}, unavailable
	}
	var result metrics.Result
	switch {
	case metadata.Current.Summary != nil:
		result, err = metrics.Normalize(metadata.Current.Summary, snapshot.Values, filter, snapshot.Epoch, time.Now())
	case metadata.Current.SummaryV2 != nil:
		values := snapshot.Values
		if d.anytls != nil {
			if extra := d.alignAnyTLSCounters(snapshot.Epoch, d.anytls.Counters()); len(extra) > 0 {
				merged := make(map[string]int64, len(values)+len(extra))
				for k, v := range values {
					merged[k] = v
				}
				for k, v := range extra {
					merged[k] += v
				}
				values = merged
			}
		}
		result, err = metrics.NormalizeV2(metadata.Current.SummaryV2, values, filter, snapshot.Epoch, time.Now())
	default:
		return metrics.Result{}, unavailable
	}
	if err != nil {
		return metrics.Result{}, unavailable
	}
	return result, nil
}
