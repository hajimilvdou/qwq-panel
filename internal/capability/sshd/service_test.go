// SPDX-License-Identifier: AGPL-3.0-only

package sshd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
	hasExternalConn bool
}

func (f *fakeRuntime) Ports(context.Context) ([]uint32, error)         { return slices.Clone(f.ports), nil }
func (*fakeRuntime) ManagementPorts(context.Context) ([]uint32, error) { return []uint32{8443}, nil }
func (*fakeRuntime) Conflicts(context.Context, uint32) (bool, error)   { return false, nil }
func (f *fakeRuntime) HasExternalConnection(context.Context, uint32) bool {
	return f.hasExternalConn
}
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
func portCallAs(t *testing.T, s *Service, r *fakeRepository, pluginID, instanceID, stage, reference, operation string) sandbox.CapabilityResponse {
	t.Helper()
	current, err := r.Read(context.Background(), Match{})
	if err != nil {
		t.Fatal(err)
	}
	params := PortMutation{Kind: "port", NewPort: 2233, Stage: stage, TransactionRef: reference, ExpectedRevision: current.Revision, OperationID: operation, InstanceID: instanceID, HostPorts: []uint32{8443}}
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	response, err := s.Run(context.Background(), sandbox.CapabilityRequest{Op: "sshd.write-dropin", ID: pluginID, ParamsJSON: raw})
	if err != nil {
		t.Fatal(err)
	}
	return response
}
func portCall(t *testing.T, s *Service, r *fakeRepository, stage, reference, operation string) sandbox.CapabilityResponse {
	return portCallAs(t, s, r, "security.basic", "default", stage, reference, operation)
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
	// ADD_NEW 不接受自治 OperationID。
	if result := portCall(t, s, r, "ADD_NEW", "", "auton:sshd_saga_rollback"); result.Code != "VALIDATION_FAILED" {
		t.Fatalf("autonomous ADD_NEW = %s", result.Code)
	}
	added := portResponse(t, portCall(t, s, r, "ADD_NEW", "", "op_00000000000000000000000001"))
	if added.TransactionRef == "" || !slices.Equal(runtime.ports, []uint32{2222, 2233}) {
		t.Fatal("old listener was not preserved")
	}
	// 错误 TransactionRef 必须返回 PERMISSION_DENIED。
	wrongRef := strings.Repeat("a", len(added.TransactionRef))
	if wrongRef == added.TransactionRef {
		wrongRef = strings.Repeat("b", len(added.TransactionRef))
	}
	if result := portCall(t, s, r, "COMMIT_NEW", wrongRef, "op_00000000000000000000000002"); result.Code != "PERMISSION_DENIED" {
		t.Fatalf("wrong ref = %s", result.Code)
	}
	// 跨插件与跨实例携带合法 TransactionRef 必须返回 PERMISSION_DENIED。
	if result := portCallAs(t, s, r, "other.plugin", "default", "COMMIT_NEW", added.TransactionRef, "op_00000000000000000000000002"); result.Code != "PERMISSION_DENIED" {
		t.Fatalf("cross plugin = %s", result.Code)
	}
	if result := portCallAs(t, s, r, "security.basic", "other", "COMMIT_NEW", added.TransactionRef, "op_00000000000000000000000002"); result.Code != "PERMISSION_DENIED" {
		t.Fatalf("cross instance = %s", result.Code)
	}
	// COMMIT_NEW 不接受自治 OperationID。
	if result := portCall(t, s, r, "COMMIT_NEW", added.TransactionRef, "auton:sshd_saga_rollback"); result.Code != "VALIDATION_FAILED" {
		t.Fatalf("autonomous COMMIT_NEW = %s", result.Code)
	}
	runtime.failVerify = true
	before := r.commits
	// 同一插件实例携带合法 TransactionRef 与新派发 OperationID 可进入验证阶段。
	if result := portCall(t, s, r, "COMMIT_NEW", added.TransactionRef, "op_00000000000000000000000002"); result.Code != "PORT_VERIFY_FAILED" {
		t.Fatalf("verification = %s", result.Code)
	}
	if r.commits != before || !slices.Contains(runtime.ports, 2222) {
		t.Fatal("failed verification removed old port")
	}
	runtime.failVerify = false
	portResponse(t, portCall(t, s, r, "COMMIT_NEW", added.TransactionRef, "op_00000000000000000000000002"))
	if !slices.Equal(runtime.ports, []uint32{2233}) {
		t.Fatalf("ports = %v", runtime.ports)
	}
	// 回滚允许使用新的正式 OperationID，且恢复原始监听端口。
	portResponse(t, portCall(t, s, r, "ROLLBACK", added.TransactionRef, "op_00000000000000000000000003"))
	if !slices.Equal(runtime.ports, []uint32{2222}) {
		t.Fatal("rollback did not restore original listener")
	}

	// 再次准备双端口，验证后台超时自治凭证 auton:sshd_saga_rollback 可执行 ROLLBACK。
	added2 := portResponse(t, portCall(t, s, r, "ADD_NEW", "", "op_00000000000000000000000004"))
	portResponse(t, portCall(t, s, r, "ROLLBACK", added2.TransactionRef, "auton:sshd_saga_rollback"))
	if !slices.Equal(runtime.ports, []uint32{2222}) {
		t.Fatal("autonomous rollback did not restore original listener")
	}
}

func TestVerifyPortExternalConnectionAndProcNetParser(t *testing.T) {
	s, _, runtime := fixture(t)
	verify := func(port uint32) *sshdv1.VerifyPortResponse {
		raw, err := json.Marshal(struct {
			Port uint32 `json:"port"`
		}{Port: port})
		if err != nil {
			t.Fatal(err)
		}
		res, err := s.Run(context.Background(), sandbox.CapabilityRequest{Op: "sshd.verify-port", ID: "security.basic", ParamsJSON: raw})
		if err != nil || !res.OK {
			t.Fatalf("verify-port failed: ok=%v code=%s err=%v", res.OK, res.Code, err)
		}
		out := new(sshdv1.VerifyPortResponse)
		if err := protojson.Unmarshal(res.ResultJSON, out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	if got := verify(2222); !got.Reachable || got.HasExternalConnection {
		t.Fatalf("expected reachable without external conn, got %+v", got)
	}
	runtime.hasExternalConn = true
	if got := verify(2222); !got.Reachable || !got.HasExternalConnection {
		t.Fatalf("expected reachable with external conn, got %+v", got)
	}

	dir := t.TempDir()
	// 端口 2222 = 0x08AE；127.0.0.1 = 0100007F；169.254.1.2 = 0201FEA9；203.0.113.9 = 097100CB
	tcp4 := filepath.Join(dir, "tcp")
	content4 := strings.Join([]string{
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
		"   0: 00000000:08AE 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1",
		"   1: 0100007F:08AE 0100007F:C350 01 00000000:00000000 00:00000000 00000000     0        0 2",
		"   2: 0201FEA9:08AE 0201FEA9:C351 01 00000000:00000000 00:00000000 00000000     0        0 3",
	}, "\n") + "\n"
	if err := os.WriteFile(tcp4, []byte(content4), 0o600); err != nil {
		t.Fatal(err)
	}
	if scanHostProcNetTCP(tcp4, 2222, false) {
		t.Fatal("loopback/link-local/listen must not count as external IPv4 SSH connection")
	}
	content4 += "   3: 0100000A:08AE 097100CB:C352 01 00000000:00000000 00:00000000 00000000     0        0 4\n"
	if err := os.WriteFile(tcp4, []byte(content4), 0o600); err != nil {
		t.Fatal(err)
	}
	if !scanHostProcNetTCP(tcp4, 2222, false) {
		t.Fatal("expected external IPv4 ESTABLISHED connection to be detected")
	}

	// IPv6: ::1 = 00000000000000000000000001000000；2001:db8::1 = B80D0120 00000000 00000000 01000000
	tcp6 := filepath.Join(dir, "tcp6")
	content6 := strings.Join([]string{
		"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
		"   0: 00000000000000000000000001000000:08AE 00000000000000000000000001000000:C350 01 00000000:00000000 00:00000000 00000000 0 0 1",
		"   1: 0000000000000000FFFF00000100000A:08AE B80D0120000000000000000001000000:C353 01 00000000:00000000 00:00000000 00000000 0 0 2",
	}, "\n") + "\n"
	if err := os.WriteFile(tcp6, []byte(content6), 0o600); err != nil {
		t.Fatal(err)
	}
	if !scanHostProcNetTCP(tcp6, 2222, true) {
		t.Fatal("expected external IPv6 ESTABLISHED connection to be detected")
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
