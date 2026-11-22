// SPDX-License-Identifier: AGPL-3.0-only

package sshd

import (
	"slices"
	"testing"
)

func TestCommitDoesNotReportExtraOldListenerAsRemoved(t *testing.T) {
	s, r, runtime := fixture(t)
	added := portResponse(t, portCall(t, s, r, "ADD_NEW", "", "op_00000000000000000000000001"))
	// 模拟标准 socket 的外部覆盖仍维持旧监听；配置预检不能代替运行态验证。
	runtime.extraPorts = []uint32{2222}
	result := portCall(t, s, r, "COMMIT_NEW", added.TransactionRef, "op_00000000000000000000000001")
	if result.OK || result.Code != "UNAVAILABLE" || !slices.Equal(runtime.ports, []uint32{2222, 2233}) {
		t.Fatal("extra old listener was reported as a successful single-port commit")
	}
	current := pending(t, s, "security.basic", "default")
	if !current.TransactionPending || current.TransactionStage != "ADDED" {
		t.Fatal("dual-port transaction was not preserved for recovery")
	}
}

func TestInitialConfigAndListenerMismatchIsReadOnly(t *testing.T) {
	s, r, runtime := fixture(t)
	runtime.ports = []uint32{2299}
	result := portCall(t, s, r, "ADD_NEW", "", "op_00000000000000000000000001")
	if result.Code != "CONFLICT" || r.commits != 0 {
		t.Fatal("wrote config while listener sources were inconsistent")
	}
}
