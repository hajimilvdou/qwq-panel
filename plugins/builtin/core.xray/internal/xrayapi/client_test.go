// SPDX-License-Identifier: AGPL-3.0-only

package xrayapi

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/xrayapi/wire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const inboundCounter = "inbound>>>qwq-in-proof>>>traffic>>>uplink"
const userCounter = "user>>>qwq-user-proof>>>traffic>>>downlink"

// fakeStats 经真实 Unix/gRPC 传输测试客户端边界，不替代真实 Xray 证据。
type fakeStats struct {
	wire.UnimplementedStatsServiceServer
	calls atomic.Int32
	query func(context.Context, *wire.QueryStatsRequest) (*wire.QueryStatsResponse, error)
}

func (f *fakeStats) QueryStats(ctx context.Context, request *wire.QueryStatsRequest) (*wire.QueryStatsResponse, error) {
	f.calls.Add(1)
	if request.GetReset_() {
		return nil, status.Error(codes.PermissionDenied, "reset is forbidden in this fixture")
	}
	if f.query != nil {
		return f.query(ctx, request)
	}
	response := &wire.QueryStatsResponse{}
	for name, value := range map[string]int64{inboundCounter: 0, userCounter: 42} {
		if strings.Contains(name, request.GetPattern()) {
			response.Stat = append(response.Stat, &wire.Stat{Name: name, Value: value})
		}
	}
	return response, nil
}

func fakeEndpoint(t *testing.T, service *fakeStats) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "api.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	server := grpc.NewServer()
	wire.RegisterStatsServiceServer(server, service)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		listener.Close()
		if err := <-done; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("fake server: %v", err)
		}
	})
	return socket
}

func fakeClient(t *testing.T, endpoint string) *Client {
	t.Helper()
	client, err := New(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func TestFakeClientPreservesZeroAndMissing(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	server := &fakeStats{}
	client := fakeClient(t, fakeEndpoint(t, server))
	value, err := client.Get(t.Context(), inboundCounter)
	if err != nil || value != 0 {
		t.Fatalf("present zero = %d, %v", value, err)
	}
	if _, err := client.Get(t.Context(), "user>>>qwq-user-absent>>>traffic>>>uplink"); !errors.Is(err, ErrMissing) {
		t.Fatalf("missing = %v", err)
	}
	counters, err := client.Counters(t.Context())
	if err != nil || len(counters) != 2 || counters[userCounter] != 42 {
		t.Fatalf("counters = %v, %v", counters, err)
	}
	before := server.calls.Load()
	if _, err := client.Get(t.Context(), "user>>>.*>>>traffic>>>uplink"); !errors.Is(err, ErrCounter) {
		t.Fatalf("arbitrary pattern = %v", err)
	}
	if server.calls.Load() != before {
		t.Fatal("invalid name reached the server")
	}
}

func TestFakeClientRejectsNonPrivateSocket(t *testing.T) {
	socket := fakeEndpoint(t, &fakeStats{})
	for _, mode := range []os.FileMode{0o666, 0o644} {
		if err := os.Chmod(socket, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := New(socket); !errors.Is(err, ErrSocket) {
			t.Fatalf("mode %o accepted", mode)
		}
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(socket), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := New(socket); !errors.Is(err, ErrSocket) {
		t.Fatal("shared directory accepted")
	}
	if err := os.Chmod(filepath.Dir(socket), 0o700); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(filepath.Dir(socket), "real.sock")
	if err := os.Rename(socket, real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, socket); err != nil {
		t.Fatal(err)
	}
	if _, err := New(socket); !errors.Is(err, ErrSocket) {
		t.Fatal("symlink socket accepted")
	}
}

func TestFakeClientBoundsResponseAndDeadline(t *testing.T) {
	for _, scenario := range []string{"count", "bytes", "duplicate", "negative", "deadline"} {
		t.Run(scenario, func(t *testing.T) {
			server := &fakeStats{query: func(ctx context.Context, request *wire.QueryStatsRequest) (*wire.QueryStatsResponse, error) {
				switch scenario {
				case "deadline":
					<-ctx.Done()
					return nil, status.FromContextError(ctx.Err()).Err()
				case "bytes":
					return &wire.QueryStatsResponse{Stat: []*wire.Stat{{Name: strings.Repeat("x", MaxResponse+1)}}}, nil
				case "count":
					response := &wire.QueryStatsResponse{}
					for range MaxCounters + 1 {
						response.Stat = append(response.Stat, &wire.Stat{Name: inboundCounter})
					}
					return response, nil
				case "duplicate":
					return &wire.QueryStatsResponse{Stat: []*wire.Stat{{Name: inboundCounter}, {Name: inboundCounter}}}, nil
				default:
					return &wire.QueryStatsResponse{Stat: []*wire.Stat{{Name: inboundCounter, Value: -1}}}, nil
				}
			}}
			client := fakeClient(t, fakeEndpoint(t, server))
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			if _, err := client.Counters(ctx); err == nil {
				t.Fatal("invalid or timed out response was accepted")
			}
		})
	}
}
