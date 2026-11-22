// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"net"
	"sync/atomic"
	"testing"
	"time"

	metricsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/metrics/v1"
	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type hostMetricsFixture struct {
	metricsv1.UnimplementedMetricsServiceServer
	reads  atomic.Int64
	second chan struct{}
}

// timedMonitorPlugin 对齐夹具每次推进一秒的宿主时间，保留原联调速率和单位契约。
type timedMonitorPlugin struct {
	*Plugin
	at time.Time
}

func (p *timedMonitorPlugin) NewInstance(ctx context.Context, info pluginsdk.InstanceInfo) (pluginsdk.Instance, error) {
	created, err := p.Plugin.NewInstance(ctx, info)
	if err != nil {
		return nil, err
	}
	created.(*instance).samples.now = func() time.Time {
		p.at = p.at.Add(time.Second)
		return p.at
	}
	return created, nil
}

func (f *hostMetricsFixture) ReadMetrics(_ context.Context, request *metricsv1.ReadMetricsRequest) (*metricsv1.ReadMetricsResponse, error) {
	if request.Context == nil || request.Context.InstanceHandle != "host-metrics-instance" || request.Context.OperationId != "" {
		return nil, status.Error(codes.PermissionDenied, "read metrics context is not bound to the instance")
	}
	n := f.reads.Add(1)
	if n == 2 {
		close(f.second)
	}
	return &metricsv1.ReadMetricsResponse{Snapshot: sample(n*1000, uint64(n*25), uint64(n*75), uint64(n*1000), uint64(n*2))}, nil
}

func TestMonitorHostCapabilityToSnapshotAndWidgets(t *testing.T) {
	listener := bufconn.Listen(128 << 10)
	hostServer := grpc.NewServer()
	fixture := &hostMetricsFixture{second: make(chan struct{})}
	metricsv1.RegisterMetricsServiceServer(hostServer, fixture)
	go func() { _ = hostServer.Serve(listener) }()
	t.Cleanup(func() { hostServer.Stop(); _ = listener.Close() })
	connection, err := grpc.NewClient("passthrough:///host-metrics", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	server, err := pluginsdk.Serve(t.Context(), pluginsdk.Options{Plugin: &timedMonitorPlugin{Plugin: New(), at: time.Now()}, Manifest: Manifest(), Registrar: quietRegistrar{}, Host: connection, DefaultGracePeriod: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	request := &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}
	if _, err := server.Initialize(t.Context(), &pb.InitializeRequest{Context: request, InstanceHandle: "host-metrics-instance", ConfigJson: []byte(`{"sample_interval_ms":500}`), ConfigRevision: "1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Start(t.Context(), &pb.StartRequest{Context: request}); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Activate(t.Context(), &pb.ActivateRequest{Context: request}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-fixture.second:
	case <-time.After(3 * time.Second):
		t.Fatal("host metrics were not requested through the capability client")
	}
	// RPC 返回不代表后台已提交样本，按结果条件等待，避免依赖固定 sleep。
	deadline := time.Now().Add(2 * time.Second)
	for {
		response, err := server.Invoke(t.Context(), &pb.InvokeRequest{Context: request, Operation: "monitor.snapshot", ApiVersion: "v1", PayloadJson: []byte(`{}`)})
		if err != nil || response.GetError() != nil {
			t.Fatal("snapshot read failed after valid host metrics")
		}
		var payload snapshotResponse
		if err := json.Unmarshal(response.PayloadJson, &payload); err != nil {
			t.Fatal(err)
		}
		if payload.Current.CPU != nil {
			if *payload.Current.CPU != 25 || payload.Current.Memory == nil || *payload.Current.Memory != 60 || payload.Current.NetRX == nil || *payload.Current.NetRX != 8000 {
				t.Fatal("host capability snapshot was not derived correctly")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("sample never became visible through the real SDK invoke handler")
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-t.Context().Done():
			timer.Stop()
			t.Fatal("test canceled")
		case <-timer.C:
		}
	}
	widget, err := server.Invoke(t.Context(), &pb.InvokeRequest{Context: request, Operation: "monitor.stat.cpu", ApiVersion: "v1", PayloadJson: []byte(`{}`)})
	if err != nil || widget.GetError() != nil {
		t.Fatal("CPU widget read failed")
	}
	var stat statResponse
	if json.Unmarshal(widget.PayloadJson, &stat) != nil || stat.Value != 25 || stat.Level != "ok" {
		t.Fatal("widget did not return the shell's current contract")
	}
	if _, err := server.Deactivate(t.Context(), &pb.DeactivateRequest{Context: request}); err != nil {
		t.Fatal(err)
	}
	paused, err := server.Invoke(t.Context(), &pb.InvokeRequest{Context: request, Operation: "monitor.stat.cpu", ApiVersion: "v1", PayloadJson: []byte(`{}`)})
	if err != nil || paused.GetError().GetCode() != "UNAVAILABLE" {
		t.Fatal("paused host metrics were advertised as a current value")
	}
}
