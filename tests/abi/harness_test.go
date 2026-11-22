// SPDX-License-Identifier: AGPL-3.0-only

package abi_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// testTimeout bounds every wait in this package; no test sleeps to wait for a state.
const testTimeout = 4 * time.Second

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	t.Cleanup(cancel)
	return ctx
}

// serve starts a gRPC server on an in-memory bufconn listener and returns a client connection to
// it. Each plugin gets its own pair of connections, standing in for the per-plugin UDS (ADR-0003).
// Cleanup closes the client and stops the server after its handlers have returned.
func serve(t *testing.T, register func(*grpc.Server)) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.WaitForHandlers(true))
	register(srv)
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
	})
	return conn
}

// recv waits for a value on ch.
func recv[T any](t *testing.T, ch chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(testTimeout):
		t.Fatalf("timed out waiting for %s", what)
		panic("unreachable")
	}
}

func wantCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if got := status.Code(err); got != want {
		t.Fatalf("gRPC status = %v (%v), want %v", got, err, want)
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func capability(name, scope string) *pb.Capability { return &pb.Capability{Name: name, Scope: scope} }

func human(id string) *pb.Actor { return &pb.Actor{Kind: pb.ActorKind_ACTOR_KIND_HUMAN, Id: id} }

// subjectSegment is the segment grammar from the platform.proto header.
var subjectSegment = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,128}$`)

// validRelativeSubject checks a plugin-supplied relative subject. The grammar alone admits "."
// and ".." as segments; the host rejects them as well so that a prefixed subject can never be
// read as a path outside the plugin's namespace (see report).
func validRelativeSubject(s string) error {
	for _, seg := range strings.Split(s, "/") {
		if !subjectSegment.MatchString(seg) || seg == "." || seg == ".." {
			return fmt.Errorf("invalid relative subject %q", s)
		}
	}
	return nil
}

// riskFloor is the capability floor of ADR-0004 D6, as given in the P0-T7 brief.
func riskFloor(c *pb.Capability) pb.RiskLevel {
	n := c.GetName()
	switch {
	case strings.HasPrefix(n, "state.kv."):
		return pb.RiskLevel_RISK_LEVEL_LOW
	case strings.HasPrefix(n, "system."), n == "secret.reveal", n == "network.egress":
		return pb.RiskLevel_RISK_LEVEL_HIGH
	}
	return pb.RiskLevel_RISK_LEVEL_UNSPECIFIED
}

// effectiveRisk = max(declared risk, capability floor); the floor is taken over the operation's
// capabilities, or over every plugin capability when the operation declares none (ADR-0007 #4).
func effectiveRisk(plugin *pb.PluginDescriptor, op *pb.OperationDescriptor) pb.RiskLevel {
	caps := op.GetCapabilities()
	if len(caps) == 0 {
		caps = plugin.GetCapabilities()
	}
	r := op.GetRisk()
	for _, c := range caps {
		r = max(r, riskFloor(c))
	}
	if op.GetEffect() == pb.OperationEffect_OPERATION_EFFECT_DESTRUCTIVE {
		r = pb.RiskLevel_RISK_LEVEL_HIGH
	}
	return r
}

func findOp(d *pb.PluginDescriptor, name string) *pb.OperationDescriptor {
	for _, op := range d.GetOperations() {
		if op.GetName() == name {
			return op
		}
	}
	return nil
}

// terminal reports whether s is a terminal state known to ABI v1.0. A value added by a later
// minor is not terminal here, which is exactly what an old SDK would conclude (see report).
func terminal(s pb.OperationState) bool {
	switch s {
	case pb.OperationState_OPERATION_STATE_SUCCEEDED, pb.OperationState_OPERATION_STATE_FAILED,
		pb.OperationState_OPERATION_STATE_CANCELED, pb.OperationState_OPERATION_STATE_REJECTED,
		pb.OperationState_OPERATION_STATE_EXPIRED:
		return true
	}
	return false
}

// errorFromStatus is how the trial plugins turn a failed host call into their own ErrorDetail.
// The ABI defines no such mapping; the codes below are the trial's choice (see report).
func errorFromStatus(err error) *pb.ErrorDetail {
	st := status.Convert(err)
	code := map[codes.Code]string{
		codes.PermissionDenied: "PERMISSION_DENIED", codes.NotFound: "NOT_FOUND",
		codes.Unavailable: "UNAVAILABLE", codes.DeadlineExceeded: "DEADLINE_EXCEEDED",
		codes.Canceled: "CANCELED", codes.Unimplemented: "UNIMPLEMENTED",
		codes.Aborted: "REVISION_CONFLICT", codes.Unauthenticated: "UNAUTHENTICATED",
	}[st.Code()]
	if code == "" {
		code = "INTERNAL"
	}
	if errors.Is(err, context.Canceled) {
		code = "CANCELED"
	}
	return &pb.ErrorDetail{Code: code, Message: st.Message(), Retryable: st.Code() == codes.Unavailable}
}
