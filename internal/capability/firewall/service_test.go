// SPDX-License-Identifier: AGPL-3.0-only

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/qwq-panel/qwq/internal/capability/local"
	"github.com/qwq-panel/qwq/internal/sandbox"
	firewallv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/firewall/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

type fakeState struct {
	mu         sync.Mutex
	raw        []byte
	failCommit bool
}

func (s *fakeState) Lock(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	return s.mu.Unlock, nil
}
func (s *fakeState) Read() ([]byte, bool, error) {
	return append([]byte(nil), s.raw...), s.raw != nil, nil
}
func (s *fakeState) Commit(raw []byte) error {
	if s.failCommit {
		s.failCommit = false
		return errors.New("TEST-ONLY-disk-full")
	}
	s.raw = append([]byte(nil), raw...)
	return nil
}

type fakeGuard struct {
	ports    []uint32
	managers []Manager
}

func (g *fakeGuard) PreservedPorts(context.Context) ([]uint32, error) { return g.ports, nil }
func (g *fakeGuard) Managers(context.Context) ([]Manager, error)      { return g.managers, nil }

type nftFake struct {
	table                bool
	chain                bool
	doc                  []byte
	writes               int
	checks               int
	failCheck            bool
	failApplyAfterCommit bool
	driftOnCheck         []byte
	afterWrite           func(int)
}

func (n *nftFake) Execute(ctx context.Context, tool local.Tool, args []string, input []byte) (local.Result, error) {
	if err := ctx.Err(); err != nil {
		return local.Result{}, err
	}
	if tool != local.Nft {
		return local.Result{}, errors.New("unexpected tool")
	}
	switch strings.Join(args, " ") {
	case "-j list tables":
		if n.table {
			return local.Result{Output: []byte(`{"nftables":[{"table":{"family":"inet","name":"qwq"}}]}`)}, nil
		}
		return local.Result{Output: []byte(`{"nftables":[]}`)}, nil
	case "-j list chains":
		if n.chain {
			return local.Result{Output: []byte(`{"nftables":[{"chain":{"family":"inet","table":"qwq","name":"input"}}]}`)}, nil
		}
		return local.Result{Output: []byte(`{"nftables":[]}`)}, nil
	case "-j list chain inet qwq input":
		return local.Result{Output: append([]byte(nil), n.doc...)}, nil
	case "-j --check -f -":
		n.checks++
		if n.failCheck {
			return local.Result{ExitCode: 1}, nil
		}
		if n.driftOnCheck != nil {
			n.table, n.chain, n.doc = true, true, n.driftOnCheck
			n.driftOnCheck = nil
		}
		return local.Result{}, nil
	case "-j -f -":
		n.writes++
		var tx struct {
			Nftables []map[string]json.RawMessage `json:"nftables"`
		}
		if err := json.Unmarshal(input, &tx); err != nil {
			return local.Result{}, err
		}
		objects := []json.RawMessage{[]byte(`{"table":{"family":"inet","name":"qwq"}}`)}
		for _, command := range tx.Nftables {
			if command["delete"] != nil {
				n.chain = false
			}
			if object := command["add"]; object != nil {
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(object, &fields); err != nil {
					return local.Result{}, err
				}
				if fields["table"] != nil {
					n.table = true
					continue
				}
				if fields["chain"] != nil {
					n.chain = true
				}
				objects = append(objects, object)
			}
		}
		n.doc, _ = json.Marshal(struct {
			Nftables []json.RawMessage `json:"nftables"`
		}{objects})
		if n.afterWrite != nil {
			n.afterWrite(n.writes)
		}
		if n.failApplyAfterCommit {
			n.failApplyAfterCommit = false
			return local.Result{}, errors.New("TEST-ONLY-ambiguous-transport")
		}
		return local.Result{}, nil
	default:
		return local.Result{}, errors.New("unexpected nft arguments")
	}
}

func firewallFixture() (*Service, *nftFake, *fakeState, *fakeGuard) {
	executor, state, guard := new(nftFake), new(fakeState), &fakeGuard{ports: []uint32{22, 8443}}
	return &Service{Executor: executor, State: state, Guard: guard}, executor, state, guard
}

func getFirewall(t *testing.T, s *Service) *firewallv1.GetRulesetResponse {
	t.Helper()
	result, err := s.Run(t.Context(), sandbox.CapabilityRequest{Op: "firewall.get", ID: "security.basic"})
	if err != nil || !result.OK {
		t.Fatalf("get failed: code=%s err=%v", result.Code, err)
	}
	response := new(firewallv1.GetRulesetResponse)
	if err := protojson.Unmarshal(result.ResultJSON, response); err != nil {
		t.Fatal(err)
	}
	return response
}

func applyFirewall(t *testing.T, s *Service, revision string) sandbox.CapabilityResponse {
	t.Helper()
	params, err := json.Marshal(Mutation{Ruleset: []byte(testRuleset), ExpectedRevision: revision, PreservedPorts: []uint32{22, 8443}, HostPorts: []uint32{8443}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.Run(t.Context(), sandbox.CapabilityRequest{Op: "firewall.apply", ID: "security.basic", ParamsJSON: params})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestFirewallApplyCASAndPersistence(t *testing.T) {
	s, n, state, _ := firewallFixture()
	before := getFirewall(t, s)
	if before.PersistencePending {
		t.Fatal("missing firewall falsely reports persistence drift")
	}
	result := applyFirewall(t, s, before.Revision)
	if !result.OK {
		t.Fatalf("apply failed: %s", result.Code)
	}
	if n.writes != 1 || n.checks != 1 {
		t.Fatal("write did not follow a successful native preflight")
	}
	after := getFirewall(t, s)
	if after.PersistencePending || after.Revision == before.Revision || !bytes.Equal(after.RulesetJson, state.raw) {
		t.Fatal("live/persisted state or revision is inconsistent")
	}
	result = applyFirewall(t, s, before.Revision)
	if result.OK || result.Code != "PRECONDITION_FAILED" || n.writes != 1 {
		t.Fatal("stale revision was executed")
	}
}

func TestFirewallPreflightCoexistenceAndDrift(t *testing.T) {
	t.Run("preflight rejects", func(t *testing.T) {
		s, n, state, _ := firewallFixture()
		before := getFirewall(t, s)
		n.failCheck = true
		result := applyFirewall(t, s, before.Revision)
		if result.OK || n.writes != 0 || state.raw != nil {
			t.Fatal("failed preflight changed state")
		}
	})
	t.Run("manager blocks", func(t *testing.T) {
		s, n, _, guard := firewallFixture()
		before := getFirewall(t, s)
		guard.managers = []Manager{{Kind: "ufw", Active: true}}
		result := applyFirewall(t, s, before.Revision)
		if result.Code != "CONFLICT" || n.checks != 0 || n.writes != 0 {
			t.Fatal("coexisting manager was bypassed")
		}
	})
	t.Run("check detects concurrent change", func(t *testing.T) {
		s, n, _, _ := firewallFixture()
		before := getFirewall(t, s)
		other, err := Minimal([]uint32{22, 8443})
		if err != nil {
			t.Fatal(err)
		}
		n.driftOnCheck, err = other.Definition()
		if err != nil {
			t.Fatal(err)
		}
		result := applyFirewall(t, s, before.Revision)
		if result.Code != "PRECONDITION_FAILED" || n.writes != 0 {
			t.Fatal("concurrent state was overwritten")
		}
	})
}

func TestFirewallRollbackAndCrashVisibility(t *testing.T) {
	t.Run("rollback does not claim an unrelated state", func(t *testing.T) {
		s, n, state, _ := firewallFixture()
		old, _ := Minimal([]uint32{22, 8443})
		n.doc, _ = old.Definition()
		n.table, n.chain = true, true
		persisted, _ := Normalize([]byte(testRuleset), []uint32{22, 8443}, []uint32{22, 8443})
		state.raw, _ = persisted.Definition()
		before := getFirewall(t, s)
		if !before.PersistencePending {
			t.Fatal("fixture must have preexisting persistence drift")
		}
		third, _ := Minimal([]uint32{22, 8443, 9999})
		thirdDefinition, _ := third.Definition()
		state.failCommit = true
		n.afterWrite = func(count int) {
			if count == 2 {
				n.doc = thirdDefinition
			}
		}
		result := applyFirewall(t, s, before.Revision)
		if result.OK || result.Code != "RECOVERY_REQUIRED" {
			t.Fatal("an unrelated live policy was falsely claimed as restored")
		}
	})
	for _, kind := range []string{"disk failure", "ambiguous execution"} {
		t.Run(kind, func(t *testing.T) {
			s, n, state, _ := firewallFixture()
			before := getFirewall(t, s)
			state.failCommit = kind == "disk failure"
			n.failApplyAfterCommit = kind == "ambiguous execution"
			result := applyFirewall(t, s, before.Revision)
			if result.OK || n.chain || state.raw != nil {
				t.Fatalf("failure did not roll back: %s", result.Code)
			}
		})
	}
	t.Run("crash drift is visible", func(t *testing.T) {
		s, n, state, _ := firewallFixture()
		old, _ := Minimal([]uint32{22, 8443})
		state.raw, _ = old.Definition()
		candidate, _ := Normalize([]byte(testRuleset), []uint32{22, 8443}, []uint32{22, 8443})
		n.doc, _ = candidate.Definition()
		n.table, n.chain = true, true
		if !getFirewall(t, s).PersistencePending {
			t.Fatal("live state after a crash was falsely reported as persisted")
		}
	})
}

func TestFirewallSyncPanelPortHotUpdatesActiveChain(t *testing.T) {
	s, n, _, _ := firewallFixture()
	panelPortState := new(fakeState)
	s.PanelPortState = panelPortState

	// 先激活一条 default-drop 防火墙链（只保留 22, 8443）
	before := getFirewall(t, s)
	if res := applyFirewall(t, s, before.Revision); !res.OK {
		t.Fatalf("initial apply failed: %+v", res)
	}

	// 热同步面板新端口 45001：必须同时写入 panel-port.json 并在活跃 inet qwq input 中放行 45001
	resp, err := s.Run(t.Context(), sandbox.CapabilityRequest{
		Op:         "firewall.sync-panel-port",
		ID:         "controller",
		ParamsJSON: []byte(`{"port":45001}`),
	})
	if err != nil || !resp.OK {
		t.Fatalf("firewall.sync-panel-port failed: resp=%+v err=%v", resp, err)
	}
	if !bytes.Contains(panelPortState.raw, []byte(`45001`)) {
		t.Fatalf("expected panel-port.json to contain 45001, got %q", string(panelPortState.raw))
	}
	if !bytes.Contains(n.doc, []byte(`45001`)) {
		t.Fatalf("expected active nftables input chain to immediately allow new panel port 45001, got %s", string(n.doc))
	}
	// 再次切换至 45002：必须放行 45002 并自动回收退役端口 45001（不再永久残留）
	resp2, err := s.Run(t.Context(), sandbox.CapabilityRequest{
		Op:         "firewall.sync-panel-port",
		ID:         "controller",
		ParamsJSON: []byte(`{"port":45002}`),
	})
	if err != nil || !resp2.OK {
		t.Fatalf("second firewall.sync-panel-port failed: resp=%+v err=%v", resp2, err)
	}
	if !bytes.Contains(n.doc, []byte(`45002`)) || bytes.Contains(n.doc, []byte(`45001`)) {
		t.Fatalf("expected 45002 allowed and retired 45001 removed, got %s", string(n.doc))
	}
	// Tightening to loopback 127.0.0.1 must close 45002 on public nftables while keeping SSH 22.
	resp3, err := s.Run(t.Context(), sandbox.CapabilityRequest{
		Op:         "firewall.sync-panel-port",
		ID:         "controller",
		ParamsJSON: []byte(`{"port":45002,"listen_host":"127.0.0.1"}`),
	})
	if err != nil || !resp3.OK {
		t.Fatalf("loopback firewall.sync-panel-port failed: resp=%+v err=%v", resp3, err)
	}
	if bytes.Contains(n.doc, []byte(`45002`)) {
		t.Fatalf("expected loopback listen_host to close 45002 on public chain, got %s", string(n.doc))
	}
}
