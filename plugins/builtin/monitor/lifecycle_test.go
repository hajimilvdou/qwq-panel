// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	metricsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/metrics/v1"
	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
	"google.golang.org/grpc"
)

type quietRegistrar struct{}

func (quietRegistrar) RegisterService(*grpc.ServiceDesc, any) {}

type countingSource struct {
	reads   atomic.Int64
	sampled chan struct{}
}

func (s *countingSource) Read(context.Context) (*metricsv1.MetricsSnapshot, error) {
	n := s.reads.Add(1)
	select {
	case s.sampled <- struct{}{}:
	default:
	}
	return sample(n*1000, uint64(n*25), uint64(n*75), uint64(n*1000), uint64(n*2)), nil
}

func TestMonitorSDKLifecycleStopsTrackedSampling(t *testing.T) {
	source := &countingSource{sampled: make(chan struct{}, 1)}
	server, err := pluginsdk.Serve(t.Context(), pluginsdk.Options{Plugin: &Plugin{source: source}, Manifest: Manifest(), Registrar: quietRegistrar{}, DefaultGracePeriod: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx := &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}
	if _, err := server.Initialize(t.Context(), &pb.InitializeRequest{Context: ctx, InstanceHandle: "monitor-instance", ConfigJson: []byte(`{"sample_interval_ms":500}`), ConfigRevision: "1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Start(t.Context(), &pb.StartRequest{Context: ctx}); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Activate(t.Context(), &pb.ActivateRequest{Context: ctx}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-source.sampled:
	case <-time.After(2 * time.Second):
		t.Fatal("active monitor never sampled")
	}
	if _, err := server.Deactivate(t.Context(), &pb.DeactivateRequest{Context: ctx}); err != nil {
		t.Fatal(err)
	}
	count := source.reads.Load()
	timer := time.NewTimer(600 * time.Millisecond)
	defer timer.Stop()
	<-timer.C
	if source.reads.Load() != count {
		t.Fatal("sampler continued after SDK deactivation")
	}
	if _, err := server.Stop(t.Context(), &pb.StopRequest{Context: ctx}); err != nil {
		t.Fatal(err)
	}
	if _, err := server.ReleaseInstance(t.Context(), &pb.ReleaseInstanceRequest{Context: ctx}); err != nil {
		t.Fatal(err)
	}
}
