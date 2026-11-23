// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"context"
	"errors"

	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	metricsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/metrics/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Forwarder 只提供本地 ReadMetrics，不调用 root helper 或执行外部进程。
type Forwarder struct{ Collector *Collector }

func (f Forwarder) Forward(ctx context.Context, call hostsvc.CapabilityCall) (hostsvc.CapabilityResult, error) {
	if call.Service != "metrics" || call.Method != "ReadMetrics" || f.Collector == nil {
		return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "能力执行器尚未接入")
	}
	var reqMounts []string
	if req, ok := call.Request.(*metricsv1.ReadMetricsRequest); ok && req != nil {
		reqMounts = req.GetDiskMounts()
	}
	snapshot, err := f.Collector.CollectMounts(ctx, reqMounts)
	if err != nil {
		if errors.Is(err, ErrInvalidMounts) {
			return hostsvc.CapabilityResult{}, status.Error(codes.InvalidArgument, "磁盘挂载点配置无效")
		}
		if ctx.Err() != nil {
			return hostsvc.CapabilityResult{}, status.FromContextError(ctx.Err()).Err()
		}
		return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "宿主指标当前不可用")
	}
	return hostsvc.CapabilityResult{Response: &metricsv1.ReadMetricsResponse{Snapshot: snapshot}}, nil
}

var _ hostsvc.CapabilityForwarder = Forwarder{}
