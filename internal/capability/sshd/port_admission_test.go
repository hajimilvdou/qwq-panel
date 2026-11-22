// SPDX-License-Identifier: AGPL-3.0-only

package sshd

import (
	"bytes"
	"errors"
	"slices"
	"testing"
)

// ======================== 摘除旧端口前必须证明公网入站放行 ========================

func TestSSHPortCommitRequiresFirewallAdmission(t *testing.T) {
	s, repository, runtime := fixture(t)
	operation := "op_00000000000000000000000001"
	added := portResponse(t, portCall(t, s, repository, "ADD_NEW", "", operation))
	runtime.admissionErr = errors.New("firewall: the new SSH port is not preserved")
	beforeContent := slices.Clone(repository.raw)
	beforePorts := slices.Clone(runtime.ports)
	beforeRecord := slices.Clone(s.Transactions.(*memoryState).raw)
	beforeCommits := repository.commits
	result := portCall(t, s, repository, "COMMIT_NEW", added.TransactionRef, operation)
	if result.OK || result.Code != "PRECONDITION_FAILED" {
		t.Errorf("新端口未放行仍摘除了旧端口：ok=%v code=%q", result.OK, result.Code)
	}
	if repository.commits != beforeCommits || !bytes.Equal(repository.raw, beforeContent) ||
		!slices.Equal(runtime.ports, beforePorts) || !bytes.Equal(s.Transactions.(*memoryState).raw, beforeRecord) {
		t.Error("防火墙拒绝后仍改变了 SSH 配置、监听或事务记录")
	}
	if runtime.admissionChecks != 1 {
		t.Errorf("未读取当前防火墙入站事实：checks=%d", runtime.admissionChecks)
	}
}

func TestSSHPortCommitRetriesAfterFirewallAdmission(t *testing.T) {
	s, repository, runtime := fixture(t)
	operation := "op_00000000000000000000000001"
	added := portResponse(t, portCall(t, s, repository, "ADD_NEW", "", operation))
	runtime.admissionErr = errors.New("firewall: current policy cannot be confirmed")
	if result := portCall(t, s, repository, "COMMIT_NEW", added.TransactionRef, operation); result.Code != "PRECONDITION_FAILED" {
		t.Fatalf("无法核验防火墙时未保留双端口：code=%q", result.Code)
	}
	if !slices.Equal(runtime.ports, []uint32{2222, 2233}) {
		t.Fatal("防火墙拒绝丢失了双端口回退入口")
	}
	runtime.admissionErr = nil
	portResponse(t, portCall(t, s, repository, "COMMIT_NEW", added.TransactionRef, operation))
	if !slices.Equal(runtime.ports, []uint32{2233}) || runtime.admissionChecks != 2 {
		t.Fatal("放行后不能复用原事务完成提交，或未重新核验当前防火墙")
	}
}

func TestSSHPortAddRetainsOldPortBeforeFirewallAdmission(t *testing.T) {
	s, repository, runtime := fixture(t)
	runtime.admissionErr = errors.New("firewall: new port is not allowed yet")
	portResponse(t, portCall(t, s, repository, "ADD_NEW", "", "op_00000000000000000000000001"))
	if !slices.Equal(runtime.ports, []uint32{2222, 2233}) || runtime.admissionChecks != 0 {
		t.Fatal("入站放行检查阻断了安全的双端口准备，或准备阶段丢失旧入口")
	}
}

func TestSystemRuntimeSSHAdmissionRequiresBackend(t *testing.T) {
	if err := (SystemRuntime{}).RequireSSHPort(t.Context(), 2233); err == nil {
		t.Fatal("未装配真实防火墙后端时静默跳过入站核验")
	}
}
