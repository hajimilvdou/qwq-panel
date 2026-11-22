// SPDX-License-Identifier: AGPL-3.0-only

package sshd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/sandbox"
	sshdv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/sshd/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

type memoryState struct{ raw []byte }

func (m *memoryState) Lock(context.Context) (func(), error) { return func() {}, nil }
func (m *memoryState) Read() ([]byte, bool, error)          { return slices.Clone(m.raw), m.raw != nil, nil }
func (m *memoryState) Commit(raw []byte) error              { m.raw = slices.Clone(raw); return nil }

type fakeRepository struct {
	raw         []byte
	external    []uint32
	onCandidate func()
	commits     int
}

func (f *fakeRepository) Read(context.Context, Match) (Snapshot, error) {
	digest := sha256.Sum256(f.raw)
	policy, err := parseDropIn(f.raw)
	if err != nil {
		return Snapshot{}, err
	}
	ports := uniquePorts(append(slices.Clone(policy.Ports), f.external...))
	if len(ports) == 0 {
		ports = []uint32{22}
	}
	return Snapshot{Revision: hex.EncodeToString(digest[:]), Content: slices.Clone(f.raw), Exists: f.raw != nil, Ports: ports, Settings: policySettings(policy), Writable: true}, nil
}
func (f *fakeRepository) Candidate(ctx context.Context, before Snapshot, raw []byte, match Match) (Snapshot, error) {
	clone := *f
	clone.raw = slices.Clone(raw)
	if f.onCandidate != nil {
		f.onCandidate()
	}
	return clone.Read(ctx, match)
}
func (f *fakeRepository) Commit(raw []byte) error { f.commits++; f.raw = slices.Clone(raw); return nil }

type fakeRuntime struct {
	repository      *fakeRepository
	ports           []uint32
	failVerify      bool
	failReload      int
	verifyCount     int
	extraPorts      []uint32
	admissionErr    error
	admissionChecks int
}

func (f *fakeRuntime) Ports(context.Context) ([]uint32, error)         { return slices.Clone(f.ports), nil }
func (*fakeRuntime) ManagementPorts(context.Context) ([]uint32, error) { return []uint32{8443}, nil }
func (*fakeRuntime) Conflicts(context.Context, uint32) (bool, error)   { return false, nil }
func (f *fakeRuntime) RequireSSHPort(ctx context.Context, port uint32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.admissionChecks++
	return f.admissionErr
}
func (f *fakeRuntime) Reload(ctx context.Context) error {
	if f.failReload > 0 {
		f.failReload--
		return errors.New("injected reload failure")
	}
	current, err := f.repository.Read(ctx, Match{})
	f.ports = uniquePorts(append(slices.Clone(current.Ports), f.extraPorts...))
	return err
}
func (f *fakeRuntime) Verify(_ context.Context, port uint32) (string, error) {
	f.verifyCount++
	if f.failVerify || !slices.Contains(f.ports, port) {
		return "", errors.New("injected verification failure")
	}
	return "SSH-2.0-test", nil
}

func fixture(t *testing.T) (*Service, *fakeRepository, *fakeRuntime) {
	t.Helper()
	repository := &fakeRepository{raw: []byte(managedHeader + "Port 2222\n")}
	runtime := &fakeRuntime{repository: repository, ports: []uint32{2222}}
	service := &Service{Repository: repository, Runtime: runtime, Transactions: &memoryState{}, Now: func() time.Time { return time.Unix(1000, 0) }}
	return service, repository, runtime
}
func portCall(t *testing.T, s *Service, r *fakeRepository, stage, reference, operation string) sandbox.CapabilityResponse {
	t.Helper()
	current, err := r.Read(context.Background(), Match{})
	if err != nil {
		t.Fatal(err)
	}
	params := PortMutation{Kind: "port", NewPort: 2233, Stage: stage, TransactionRef: reference, ExpectedRevision: current.Revision, OperationID: operation, InstanceID: "default", HostPorts: []uint32{8443}}
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	response, err := s.Run(context.Background(), sandbox.CapabilityRequest{Op: "sshd.write-dropin", ID: "security.basic", ParamsJSON: raw})
	if err != nil {
		t.Fatal(err)
	}
	return response
}
func portResponse(t *testing.T, result sandbox.CapabilityResponse) *sshdv1.SetPortResponse {
	t.Helper()
	if !result.OK {
		t.Fatalf("result = %s", result.Code)
	}
	response := new(sshdv1.SetPortResponse)
	if err := protojson.Unmarshal(result.ResultJSON, response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestPortStagesAndBinding(t *testing.T) {
	s, r, runtime := fixture(t)
	if result := portCall(t, s, r, "", "", "op_00000000000000000000000001"); result.Code != "VALIDATION_FAILED" {
		t.Fatalf("unspecified = %s", result.Code)
	}
	added := portResponse(t, portCall(t, s, r, "ADD_NEW", "", "op_00000000000000000000000001"))
	if added.TransactionRef == "" || !slices.Equal(runtime.ports, []uint32{2222, 2233}) {
		t.Fatal("old listener was not preserved")
	}
	if result := portCall(t, s, r, "COMMIT_NEW", added.TransactionRef, "op_00000000000000000000000002"); result.Code != "PERMISSION_DENIED" {
		t.Fatalf("binding = %s", result.Code)
	}
	runtime.failVerify = true
	before := r.commits
	if result := portCall(t, s, r, "COMMIT_NEW", added.TransactionRef, "op_00000000000000000000000001"); result.Code != "PORT_VERIFY_FAILED" {
		t.Fatalf("verification = %s", result.Code)
	}
	if r.commits != before || !slices.Contains(runtime.ports, 2222) {
		t.Fatal("failed verification removed old port")
	}
	runtime.failVerify = false
	portResponse(t, portCall(t, s, r, "COMMIT_NEW", added.TransactionRef, "op_00000000000000000000000001"))
	if !slices.Equal(runtime.ports, []uint32{2233}) {
		t.Fatalf("ports = %v", runtime.ports)
	}
	portResponse(t, portCall(t, s, r, "ROLLBACK", added.TransactionRef, "op_00000000000000000000000001"))
	if !slices.Equal(runtime.ports, []uint32{2222}) {
		t.Fatal("rollback did not restore original listener")
	}
}

func TestPortCandidateCASAndRecovery(t *testing.T) {
	t.Run("external change", func(t *testing.T) {
		s, r, _ := fixture(t)
		r.onCandidate = func() { r.raw = []byte(managedHeader + "Port 2299\n") }
		if result := portCall(t, s, r, "ADD_NEW", "", "op_00000000000000000000000001"); result.Code != "PRECONDITION_FAILED" {
			t.Fatalf("code = %s", result.Code)
		}
		if r.commits != 0 {
			t.Fatal("overwrote external config")
		}
	})
	t.Run("reload failure", func(t *testing.T) {
		s, r, runtime := fixture(t)
		original := slices.Clone(r.raw)
		runtime.failReload = 1
		if result := portCall(t, s, r, "ADD_NEW", "", "op_00000000000000000000000001"); result.Code != "UNAVAILABLE" {
			t.Fatalf("code = %s", result.Code)
		}
		if !slices.Equal(r.raw, original) || !slices.Equal(runtime.ports, []uint32{2222}) {
			t.Fatal("recovery was not confirmed")
		}
	})
	t.Run("external additive port", func(t *testing.T) {
		s, r, _ := fixture(t)
		r.external = []uint32{2200}
		if result := portCall(t, s, r, "ADD_NEW", "", "op_00000000000000000000000001"); result.Code != "CONFLICT" {
			t.Fatalf("code = %s", result.Code)
		}
		if r.commits != 0 {
			t.Fatal("started a transaction which cannot commit")
		}
	})
}

func TestExpiredCommitRetainsDualPorts(t *testing.T) {
	s, r, runtime := fixture(t)
	added := portResponse(t, portCall(t, s, r, "ADD_NEW", "", "op_00000000000000000000000001"))
	s.Now = func() time.Time { return time.Unix(1000, 0).Add(time.Hour) }
	if result := portCall(t, s, r, "COMMIT_NEW", added.TransactionRef, "op_00000000000000000000000001"); result.Code != "PRECONDITION_FAILED" {
		t.Fatalf("expired = %s", result.Code)
	}
	if !slices.Contains(runtime.ports, 2222) {
		t.Fatal("expired transaction removed old port")
	}
}
