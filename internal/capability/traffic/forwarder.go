// SPDX-License-Identifier: AGPL-3.0-only

package traffic

import (
	"context"
	"encoding/json"

	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	"github.com/qwq-panel/qwq/internal/sandbox"
	trafficv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/traffic/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Helper 抽象特权辅助进程客户端（与 *sandbox.CapabilityClient 对齐）。
type Helper interface {
	Call(ctx context.Context, req sandbox.CapabilityRequest) (sandbox.CapabilityResponse, error)
}

// Forwarder 将 hostsvc 的 TrafficService 能力调用转发至 qwq-capability helper。
type Forwarder struct {
	Helper Helper
}

// Forward 实现 hostsvc.CapabilityForwarder。
func (f Forwarder) Forward(ctx context.Context, call hostsvc.CapabilityCall) (hostsvc.CapabilityResult, error) {
	if f.Helper == nil {
		return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "流量整形辅助进程不可用")
	}
	callerID := call.PluginID
	if callerID == "" {
		callerID = "proxy.advanced"
	}
	switch call.Method {
	case "GetShapingStatus":
		resp, err := f.Helper.Call(ctx, sandbox.CapabilityRequest{Op: "traffic.status", ID: callerID})
		if err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "调用流量整形辅助进程失败")
		}
		if !resp.OK {
			return helperFail(resp), nil
		}
		var out StatusPayload
		if err := json.Unmarshal(resp.ResultJSON, &out); err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Internal, "解析流量整形状态失败")
		}
		pbClasses := make([]*trafficv1.UserShapingClass, 0, len(out.Classes))
		for _, c := range out.Classes {
			pbClasses = append(pbClasses, &trafficv1.UserShapingClass{
				TrafficMark:   c.TrafficMark,
				DownLimitKbps: c.DownLimitKbps,
				UpLimitKbps:   c.UpLimitKbps,
			})
		}
		return hostsvc.CapabilityResult{
			Response: &trafficv1.GetShapingStatusResponse{
				Supported:          out.Supported,
				UplinkIfbSupported: out.UplinkIFBSupported,
				DegradedReason:     out.DegradedReason,
				EgressInterface:    out.EgressInterface,
				Classes:            pbClasses,
				Revision:           out.Revision,
			},
		}, nil

	case "ApplyShapingRules":
		req, ok := call.Request.(*trafficv1.ApplyShapingRulesRequest)
		if !ok {
			return hostsvc.CapabilityResult{}, status.Error(codes.InvalidArgument, "无效的 ApplyShapingRules 请求")
		}
		classes := make([]ClassSpec, 0, len(req.GetClasses()))
		for _, c := range req.GetClasses() {
			classes = append(classes, ClassSpec{
				TrafficMark:   c.GetTrafficMark(),
				DownLimitKbps: c.GetDownLimitKbps(),
				UpLimitKbps:   c.GetUpLimitKbps(),
			})
		}
		payload, err := json.Marshal(ApplyInput{
			Classes:          classes,
			ExpectedRevision: req.GetExpectedRevision(),
		})
		if err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Internal, "编码流量整形请求失败")
		}
		resp, err := f.Helper.Call(ctx, sandbox.CapabilityRequest{Op: "traffic.apply", ID: callerID, ParamsJSON: payload})
		if err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "调用流量整形辅助进程失败")
		}
		if !resp.OK {
			return helperFail(resp), nil
		}
		var out ApplyPayload
		if err := json.Unmarshal(resp.ResultJSON, &out); err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Internal, "解析流量整形结果失败")
		}
		return hostsvc.CapabilityResult{
			Response: &trafficv1.ApplyShapingRulesResponse{
				Revision:       out.Revision,
				DegradedUplink: out.DegradedUplink,
			},
		}, nil

	case "ClearShapingRules":
		req, ok := call.Request.(*trafficv1.ClearShapingRulesRequest)
		if !ok {
			return hostsvc.CapabilityResult{}, status.Error(codes.InvalidArgument, "无效的 ClearShapingRules 请求")
		}
		payload, err := json.Marshal(ClearInput{ExpectedRevision: req.GetExpectedRevision()})
		if err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Internal, "编码清理请求失败")
		}
		resp, err := f.Helper.Call(ctx, sandbox.CapabilityRequest{Op: "traffic.clear", ID: callerID, ParamsJSON: payload})
		if err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "调用流量整形辅助进程失败")
		}
		if !resp.OK {
			return helperFail(resp), nil
		}
		var out ClearPayload
		if err := json.Unmarshal(resp.ResultJSON, &out); err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Internal, "解析清理结果失败")
		}
		return hostsvc.CapabilityResult{
			Response: &trafficv1.ClearShapingRulesResponse{Revision: out.Revision},
		}, nil

	default:
		return hostsvc.CapabilityResult{}, status.Error(codes.Unimplemented, "不支持的 traffic 方法")
	}
}

func helperFail(resp sandbox.CapabilityResponse) hostsvc.CapabilityResult {
	code := resp.Code
	if code == "" {
		code = "INTERNAL"
	}
	return hostsvc.CapabilityResult{
		Error: &hostsvc.DomainError{Code: code, Message: resp.Error},
	}
}
