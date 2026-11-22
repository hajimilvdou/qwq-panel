// SPDX-License-Identifier: AGPL-3.0-only

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// ======================== 运行规则和重启后的持久规则必须共同保护新入口 ========================

func TestFirewallSSHAdmissionUsesLiveAndSavedPolicy(t *testing.T) {
	for _, test := range []struct {
		name        string
		live, saved []uint32
		allow       bool
	}{
		{name: "no managed firewall", allow: true},
		{name: "old port only", live: []uint32{2222}, saved: []uint32{2222}},
		{name: "new port protected", live: []uint32{2222, 2233}, saved: []uint32{2222, 2233}, allow: true},
		{name: "live only", live: []uint32{2222, 2233}},
		{name: "saved only", saved: []uint32{2222, 2233}},
		{name: "saved policy would close new port", live: []uint32{2222, 2233}, saved: []uint32{2222}},
		{name: "live policy still closes new port", live: []uint32{2222}, saved: []uint32{2222, 2233}},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, native, state := sshAdmissionFixture(t, test.live, test.saved)
			before := append([]byte(nil), state.raw...)
			err := s.RequireSSHPort(t.Context(), 2233)
			if (err == nil) != test.allow {
				t.Errorf("新端口入站判定错误：allow=%v error=%v", test.allow, err)
			}
			if native.writes != 0 || native.checks != 0 || !bytes.Equal(state.raw, before) {
				t.Fatal("入站核验写入了原生规则或持久策略")
			}
		})
	}
}

func TestFirewallSSHAdmissionDoesNotTrustCommentsOrLateRules(t *testing.T) {
	for _, test := range []struct {
		name   string
		ports  []uint32
		change func(*testing.T, *nftDocument)
	}{
		{name: "port in comment", ports: []uint32{2222}, change: func(t *testing.T, doc *nftDocument) {
			doc.Nftables = append(doc.Nftables, sshAdmissionDrop("new port 2233"))
		}},
		{name: "drop before preserve", ports: []uint32{2233}, change: func(t *testing.T, doc *nftDocument) {
			rules := append([]nftObject{sshAdmissionDrop("deny first")}, doc.Nftables[2:]...)
			doc.Nftables = append(doc.Nftables[:2], rules...)
		}},
		{name: "new port in a later preserve rule", ports: []uint32{2222}, change: func(t *testing.T, doc *nftDocument) {
			guards, err := guardRules([]uint32{2233})
			if err != nil {
				t.Fatal(err)
			}
			doc.Nftables = append(doc.Nftables, sshAdmissionDrop("deny new"), nftObject{Rule: &guards[0]})
		}},
		{name: "loopback disguised as preserve", ports: []uint32{2233}, change: func(t *testing.T, doc *nftDocument) {
			doc.Nftables[2].Rule.Expr[0] = json.RawMessage(`{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"lo"}}`)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, native, state := sshAdmissionFixture(t, test.ports, test.ports)
			var doc nftDocument
			if err := json.Unmarshal(native.doc, &doc); err != nil {
				t.Fatal(err)
			}
			test.change(t, &doc)
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			// 两份真实策略完全一致，拒绝必须来自端口/规则顺序核验而非漂移。
			native.doc, state.raw = raw, append([]byte(nil), raw...)
			if err := s.RequireSSHPort(t.Context(), 2233); err == nil {
				t.Fatal("不安全的规则顺序、回环或注释被当成了新端口公网放行")
			}
		})
	}
}

func TestFirewallSSHAdmissionAcceptsSafeGeneratedPrefix(t *testing.T) {
	s, native, state := sshAdmissionFixture(t, []uint32{2233}, []uint32{2233})
	var doc nftDocument
	if err := json.Unmarshal(native.doc, &doc); err != nil {
		t.Fatal(err)
	}
	doc.Nftables[2], doc.Nftables[3], doc.Nftables[4] = doc.Nftables[3], doc.Nftables[4], doc.Nftables[2]
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	native.doc, state.raw = raw, append([]byte(nil), raw...)
	if err := s.RequireSSHPort(t.Context(), 2233); err != nil {
		t.Fatalf("自有回环/已建立连接接受规则不能破坏真正的新端口放行：%v", err)
	}
}

func TestFirewallSSHAdmissionRejectsUnknownState(t *testing.T) {
	s, native, state := sshAdmissionFixture(t, []uint32{2233}, []uint32{2233})
	native.doc, state.raw = []byte(`{"nftables":`), []byte(`{"nftables":`)
	if err := s.RequireSSHPort(t.Context(), 2233); err == nil {
		t.Fatal("无法解析真实防火墙状态时仍允许摘旧")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.RequireSSHPort(ctx, 2233); !errors.Is(err, context.Canceled) {
		t.Fatalf("取消后仍继续读取防火墙：%v", err)
	}
	for _, port := range []uint32{0, 65536} {
		if err := s.RequireSSHPort(t.Context(), port); err == nil {
			t.Fatal("接受了非法入站端口")
		}
	}
}

func sshAdmissionFixture(t *testing.T, live, saved []uint32) (*Service, *nftFake, *fakeState) {
	t.Helper()
	definition := func(ports []uint32) []byte {
		if len(ports) == 0 {
			return nil
		}
		rules, err := Minimal(ports)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := rules.Definition()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	native := &nftFake{table: len(live) != 0, chain: len(live) != 0, doc: definition(live)}
	state := &fakeState{raw: definition(saved)}
	return &Service{Executor: native, State: state}, native, state
}

func sshAdmissionDrop(comment string) nftObject {
	return nftObject{Rule: &ruleObject{Family: "inet", Table: "qwq", Chain: "input", Comment: comment, Expr: []json.RawMessage{[]byte(`{"drop":null}`)}}}
}
