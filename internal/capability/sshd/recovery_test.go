// SPDX-License-Identifier: AGPL-3.0-only

package sshd

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/qwq-panel/qwq/internal/sandbox"
	sshdv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/sshd/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func helperCall(t *testing.T, s *Service, pluginID, verb string, params any) sandbox.CapabilityResponse {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.Run(context.Background(), sandbox.CapabilityRequest{Op: verb, ID: pluginID, ParamsJSON: raw})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func pending(t *testing.T, s *Service, plugin, instance string) *sshdv1.GetDropInResponse {
	t.Helper()
	result := helperCall(t, s, plugin, "sshd.get-dropin", struct {
		InstanceID string `json:"instance_id"`
	}{instance})
	if !result.OK {
		t.Fatalf("pending = %s", result.Code)
	}
	response := new(sshdv1.GetDropInResponse)
	if err := protojson.Unmarshal(result.ResultJSON, response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestInterruptedTransactionHasExplicitRecovery(t *testing.T) {
	s, r, runtime := fixture(t)
	portResponse(t, portCall(t, s, r, "ADD_NEW", "", "op_00000000000000000000000001"))
	owned := pending(t, s, "security.basic", "default")
	if !owned.TransactionPending || owned.TransactionRef == "" || owned.TransactionKind != "port" {
		t.Fatal("pending transaction cannot be resumed")
	}
	for _, target := range []struct{ plugin, instance string }{{"other.plugin", "default"}, {"security.basic", "other"}} {
		foreign := pending(t, s, target.plugin, target.instance)
		if !foreign.TransactionPending || foreign.TransactionRef != "" || foreign.TransactionOperationId != "" {
			t.Fatal("foreign transaction details leaked")
		}
	}
	current, err := r.Read(context.Background(), Match{})
	if err != nil {
		t.Fatal(err)
	}
	mutation := RecoveryMutation{ExpectedRevision: current.Revision, TransactionRef: owned.TransactionRef, OperationID: "op_00000000000000000000000002", InstanceID: "default"}
	if result := helperCall(t, s, "other.plugin", "sshd.recover-dropin", mutation); result.Code != "PERMISSION_DENIED" {
		t.Fatal("foreign recovery accepted")
	}
	mutation.ExpectedRevision = "0000000000000000000000000000000000000000000000000000000000000000"
	if result := helperCall(t, s, "security.basic", "sshd.recover-dropin", mutation); result.Code != "PRECONDITION_FAILED" {
		t.Fatal("stale recovery accepted")
	}
	mutation.ExpectedRevision = current.Revision
	// 模拟 helper 退出后由新已授权 operation 接续；普通 COMMIT 仍不接受新 operation。
	if result := portCall(t, s, r, "COMMIT_NEW", owned.TransactionRef, mutation.OperationID); result.Code != "PERMISSION_DENIED" {
		t.Fatal("normal transaction binding was loosened")
	}
	restarted := *s
	if result := helperCall(t, &restarted, "security.basic", "sshd.recover-dropin", mutation); !result.OK {
		t.Fatalf("recovery = %s", result.Code)
	}
	if !slices.Equal(runtime.ports, []uint32{2222}) || pending(t, s, "security.basic", "default").TransactionPending {
		t.Fatal("original listener or journal was not restored")
	}
}

func TestRecoveryDoesNotOverwriteThirdParty(t *testing.T) {
	s, r, _ := fixture(t)
	portResponse(t, portCall(t, s, r, "ADD_NEW", "", "op_00000000000000000000000001"))
	owned := pending(t, s, "security.basic", "default")
	r.raw = []byte(managedHeader + "Port 2499\n")
	current, err := r.Read(context.Background(), Match{})
	if err != nil {
		t.Fatal(err)
	}
	before := r.commits
	mutation := RecoveryMutation{ExpectedRevision: current.Revision, TransactionRef: owned.TransactionRef, OperationID: "op_00000000000000000000000002", InstanceID: "default"}
	if result := helperCall(t, s, "security.basic", "sshd.recover-dropin", mutation); result.Code != "PRECONDITION_FAILED" || r.commits != before {
		t.Fatal("overwrote third-party configuration")
	}
}

type fakeRecoveryGuard struct {
	addresses []string
	err       error
}

func (g *fakeRecoveryGuard) Check(_ context.Context, user, address string, _ Snapshot) error {
	g.addresses = append(g.addresses, address)
	if user != "alice" {
		return errors.New("unexpected recovery user")
	}
	return g.err
}

func TestLoginRequiresAllRecoveryAddresses(t *testing.T) {
	s, r, _ := fixture(t)
	current, err := r.Read(context.Background(), Match{})
	if err != nil {
		t.Fatal(err)
	}
	disabled := false
	mutation := LoginMutation{Kind: "login", PasswordAuth: &disabled, ExpectedRevision: current.Revision, RecoveryUser: "alice", HostAddresses: []string{"192.0.2.1", "192.0.2.2"}, OperationID: "op_00000000000000000000000001", InstanceID: "default"}
	if result := helperCall(t, s, "security.basic", "sshd.write-dropin", mutation); result.Code != "PRECONDITION_FAILED" || r.commits != 0 {
		t.Fatal("login policy changed without recovery proof")
	}
	guard := &fakeRecoveryGuard{err: errors.New("no usable key")}
	s.Recovery = guard
	if result := helperCall(t, s, "security.basic", "sshd.write-dropin", mutation); result.Code != "PRECONDITION_FAILED" || r.commits != 0 {
		t.Fatal("unusable key accepted")
	}
	guard.err, guard.addresses = nil, nil
	if result := helperCall(t, s, "security.basic", "sshd.write-dropin", mutation); !result.OK {
		t.Fatalf("login = %s", result.Code)
	}
	if !slices.Equal(guard.addresses, mutation.HostAddresses) {
		t.Fatal("not all management address matches were checked")
	}
	after, err := r.Read(context.Background(), Match{})
	if err != nil || settingValue(after.Settings, "passwordauthentication") != "no" || settingValue(after.Settings, "kbdinteractiveauthentication") != "no" {
		t.Fatal("password alternate authentication was left enabled")
	}
}

func TestLoginJournalSurvivesHelperRestart(t *testing.T) {
	s, r, runtime := fixture(t)
	before, err := r.Read(context.Background(), Match{})
	if err != nil {
		t.Fatal(err)
	}
	disabled := false
	raw := renderDropIn(loginPolicy{Ports: before.Ports, PasswordAuth: &disabled, KeyboardAuth: &disabled})
	candidate, err := r.Candidate(context.Background(), before, raw, Match{})
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := s.begin("login", "security.basic", "default", "op_00000000000000000000000001", before, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Commit(raw); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	restarted := *s
	current, err := r.Read(context.Background(), Match{})
	if err != nil {
		t.Fatal(err)
	}
	mutation := RecoveryMutation{ExpectedRevision: current.Revision, TransactionRef: record.Reference, OperationID: "op_00000000000000000000000002", InstanceID: "default"}
	if result := helperCall(t, &restarted, "security.basic", "sshd.recover-dropin", mutation); !result.OK {
		t.Fatalf("interrupted login recovery = %s", result.Code)
	}
	after, err := r.Read(context.Background(), Match{})
	if err != nil || after.Revision != before.Revision {
		t.Fatal("login original snapshot lost")
	}
}

func TestRemoveDropInVerifiesBaselineBeforeRemoval(t *testing.T) {
	s, r, runtime := fixture(t)
	before, err := r.Read(context.Background(), Match{})
	if err != nil {
		t.Fatal(err)
	}
	mutation := RemoveMutation{ExpectedRevision: before.Revision, OperationID: "op_00000000000000000000000001", InstanceID: "default"}
	if result := helperCall(t, s, "security.basic", "sshd.remove-dropin", mutation); !result.OK {
		t.Fatalf("remove = %s", result.Code)
	}
	if r.raw != nil || !slices.Equal(runtime.ports, []uint32{22}) || runtime.verifyCount < 3 {
		t.Fatal("baseline listener was not verified before removal")
	}
}
