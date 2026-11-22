// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	firewallv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/firewall/v1"
	sshdv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/sshd/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ======================== 7 步双端口零断连 SSH 改端口 Saga ========================

const (
	minUserSSHPort = 1024
	maxUserSSHPort = 65535
)

type portSagaState struct {
	TransactionRef   string `json:"transaction_ref"`
	OldPort          uint32 `json:"old_port"`
	NewPort          uint32 `json:"new_port"`
	DeadlineUnix     int64  `json:"deadline_unix"`
	CreatedAtUnix    int64  `json:"created_at_unix"`
	SSHDRevision     string `json:"sshd_revision"`
	FirewallRevision string `json:"firewall_revision"`
	FirewallManaged  bool   `json:"firewall_managed"`
}

type sshdChangePortPrepareRequest struct {
	NewPort          uint32 `json:"new_port"`
	TimeoutSeconds   uint32 `json:"timeout_seconds"`
	SkipFirewall     bool   `json:"skip_firewall"`
	ExpectedRevision string `json:"expected_revision"`
}

type sshdChangePortActionRequest struct {
	TransactionRef   string `json:"transaction_ref"`
	ExpectedRevision string `json:"expected_revision"`
}

type sshdPortSagaResponse struct {
	Stage           string   `json:"stage"`
	TransactionRef  string   `json:"transaction_ref"`
	OldPort         uint32   `json:"old_port"`
	NewPort         uint32   `json:"new_port"`
	ListeningPorts  []uint32 `json:"listening_ports"`
	Banner          string   `json:"banner,omitempty"`
	DeadlineUnix    int64    `json:"deadline_unix,omitempty"`
	Revision        string   `json:"revision"`
	FirewallManaged bool     `json:"firewall_managed"`
}

// handleSSHDChangePortPrepare 执行准备阶段：校验端口 -> 防火墙双端口放行 -> SetPort(ADD_NEW) -> VerifyPort -> KV 持久化事务。
func (i *instance) handleSSHDChangePortPrepare(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in sshdChangePortPrepareRequest
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, err
	}
	if in.NewPort < minUserSSHPort || in.NewPort > maxUserSSHPort {
		return pluginsdk.Result{}, invalidField("/new_port", "OUT_OF_RANGE", "新 SSH 端口必须在 1024..65535 之间")
	}
	if in.TimeoutSeconds > 3600 {
		return pluginsdk.Result{}, invalidField("/timeout_seconds", "OUT_OF_RANGE", "超时时间不能超过 3600 秒")
	}

	i.sagaMu.Lock()
	defer i.sagaMu.Unlock()

	host := req.Host()
	if existing, found, err := i.loadPortSaga(ctx, host); err != nil {
		return pluginsdk.Result{}, err
	} else if found {
		return pluginsdk.Result{}, pluginsdk.Errorf("CONFLICT", "存在未完结的 SSH 改端口事务（%s），请先提交或回滚", existing.TransactionRef)
	}

	// 第 1 步：读取当前 SSHD 生效配置与 drop-in 快照。
	sshdRead, sshdReadMeta, err := sshdClientReadOnly(ctx, host)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	effResp, err := sshdRead.GetEffectiveConfig(ctx, &sshdv1.GetEffectiveConfigRequest{Context: sshdReadMeta})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(effResp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	dropResp, err := sshdRead.GetDropIn(ctx, &sshdv1.GetDropInRequest{Context: sshdReadMeta})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(dropResp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	if dropResp.GetTransactionPending() {
		return pluginsdk.Result{}, pluginsdk.Errorf("CONFLICT", "宿主已记录未完结的 SSH 改端口事务，请先完成提交或回滚")
	}

	currentPorts := extractListeningPorts(effResp.GetSettings())
	oldPort := currentPorts[0]
	if slices.Contains(currentPorts, in.NewPort) {
		return pluginsdk.Result{}, invalidField("/new_port", "UNCHANGED", "新 SSH 端口不能与当前监听端口相同")
	}

	sshdExpectedRev := resolveRevision(in.ExpectedRevision, req, "sshd/config")
	if sshdExpectedRev == "" {
		sshdExpectedRev = effResp.GetRevision()
	}
	if sshdExpectedRev == "" {
		sshdExpectedRev = dropResp.GetRevision()
	}

	// 第 2 步：若托管防火墙，则追加放行新端口并明确保留旧端口与宿主保留端口。
	var fwManaged bool
	var fwRevision string
	if !in.SkipFirewall {
		fwRead, fwReadMeta, err := firewallClientReadOnly(ctx, host)
		if err != nil {
			return pluginsdk.Result{}, err
		}
		fwSnap, err := fwRead.GetRuleset(ctx, &firewallv1.GetRulesetRequest{Context: fwReadMeta})
		if err != nil {
			return pluginsdk.Result{}, err
		}
		if err := protoError(fwSnap.GetError()); err != nil {
			return pluginsdk.Result{}, err
		}
		fwWrite, fwWriteMeta, err := firewallClientWrite(ctx, host)
		if err != nil {
			return pluginsdk.Result{}, err
		}
		dualPorts := mergePorts(fwSnap.GetPreservedPorts(), oldPort, in.NewPort)
		applyResp, err := fwWrite.ApplyRuleset(ctx, &firewallv1.ApplyRulesetRequest{
			Context:          fwWriteMeta,
			RulesetJson:      rulesetOrMinimal(fwSnap.GetRulesetJson()),
			ExpectedRevision: fwSnap.GetRevision(),
			PreservedPorts:   dualPorts,
		})
		if err != nil {
			return pluginsdk.Result{}, err
		}
		if err := protoError(applyResp.GetError()); err != nil {
			return pluginsdk.Result{}, err
		}
		fwManaged = true
		fwRevision = applyResp.GetRevision()
	}

	// 第 3 步：通知 sshd 进入 ADD_NEW 双端口监听阶段。
	sshdWrite, sshdWriteMeta, err := sshdClientWrite(ctx, host)
	if err != nil {
		if fwManaged {
			_ = i.restoreFirewallPorts(ctx, host, oldPort, in.NewPort)
		}
		return pluginsdk.Result{}, err
	}
	setResp, err := sshdWrite.SetPort(ctx, &sshdv1.SetPortRequest{
		Context:          sshdWriteMeta,
		NewPort:          in.NewPort,
		ExpectedRevision: sshdExpectedRev,
		Stage:            sshdv1.PortChangeStage_PORT_CHANGE_STAGE_ADD_NEW,
	})
	if err != nil {
		if fwManaged {
			_ = i.restoreFirewallPorts(ctx, host, oldPort, in.NewPort)
		}
		return pluginsdk.Result{}, err
	}
	if err := protoError(setResp.GetError()); err != nil {
		if fwManaged {
			_ = i.restoreFirewallPorts(ctx, host, oldPort, in.NewPort)
		}
		return pluginsdk.Result{}, err
	}

	txRef := strings.TrimSpace(setResp.GetTransactionRef())
	if txRef == "" {
		txRef = fmt.Sprintf("saga-%d-%d", in.NewPort, i.nowTime().UnixNano())
	}

	// 第 4 步：回环探测新端口 SSH 横幅；不可达时立即回滚，绝不残留半开状态。
	verifyResp, verifyErr := sshdRead.VerifyPort(ctx, &sshdv1.VerifyPortRequest{
		Context: sshdReadMeta,
		Port:    in.NewPort,
	})
	if verifyErr != nil || protoError(verifyResp.GetError()) != nil || !verifyResp.GetReachable() {
		_, _ = sshdWrite.SetPort(ctx, &sshdv1.SetPortRequest{
			Context:          sshdWriteMeta,
			NewPort:          in.NewPort,
			ExpectedRevision: setResp.GetRevision(),
			Stage:            sshdv1.PortChangeStage_PORT_CHANGE_STAGE_ROLLBACK,
			TransactionRef:   txRef,
		})
		if fwManaged {
			_ = i.restoreFirewallPorts(ctx, host, oldPort, in.NewPort)
		}
		if verifyErr != nil {
			return pluginsdk.Result{}, verifyErr
		}
		if err := protoError(verifyResp.GetError()); err != nil {
			return pluginsdk.Result{}, err
		}
		return pluginsdk.Result{}, pluginsdk.Errorf("PORT_VERIFY_FAILED", "新 SSH 端口 %d 回环探测不可达，已自动回滚至端口 %d", in.NewPort, oldPort)
	}

	// 第 5 步：将事务状态与超时截止时间持久化到 KV，等待用户从新端口确认。
	timeoutSec := in.TimeoutSeconds
	if timeoutSec == 0 {
		timeoutSec = i.configSnapshot().PortSagaTimeoutSeconds
	}
	now := i.nowTime()
	saga := portSagaState{
		TransactionRef:   txRef,
		OldPort:          oldPort,
		NewPort:          in.NewPort,
		DeadlineUnix:     now.Add(time.Duration(timeoutSec) * time.Second).Unix(),
		CreatedAtUnix:    now.Unix(),
		SSHDRevision:     setResp.GetRevision(),
		FirewallRevision: fwRevision,
		FirewallManaged:  fwManaged,
	}
	if err := i.savePortSaga(ctx, host, saga); err != nil {
		// 持久化失败同样回滚，避免成为后台不可追踪的悬空事务。
		_, _ = sshdWrite.SetPort(ctx, &sshdv1.SetPortRequest{
			Context:          sshdWriteMeta,
			NewPort:          in.NewPort,
			ExpectedRevision: setResp.GetRevision(),
			Stage:            sshdv1.PortChangeStage_PORT_CHANGE_STAGE_ROLLBACK,
			TransactionRef:   txRef,
		})
		if fwManaged {
			_ = i.restoreFirewallPorts(ctx, host, oldPort, in.NewPort)
		}
		return pluginsdk.Result{}, err
	}
	i.setOverviewSagaPending(ctx, host, true)

	listening := make([]uint32, 0, len(setResp.GetListeningPorts()))
	listening = append(listening, setResp.GetListeningPorts()...)
	return marshalResult(sshdPortSagaResponse{
		Stage:           "prepared",
		TransactionRef:  saga.TransactionRef,
		OldPort:         saga.OldPort,
		NewPort:         saga.NewPort,
		ListeningPorts:  listening,
		Banner:          verifyResp.GetBanner(),
		DeadlineUnix:    saga.DeadlineUnix,
		Revision:        saga.SSHDRevision,
		FirewallManaged: saga.FirewallManaged,
	})
}

// handleSSHDChangePortCommit 执行第 6-7 步：校验 transaction_ref -> VerifyPort -> COMMIT_NEW -> 移除旧端口防火墙放行 -> 清理 KV。
func (i *instance) handleSSHDChangePortCommit(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in sshdChangePortActionRequest
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, err
	}
	txRef := strings.TrimSpace(in.TransactionRef)
	if txRef == "" {
		return pluginsdk.Result{}, invalidField("/transaction_ref", "REQUIRED", "提交新 SSH 端口必须提供 transaction_ref")
	}

	i.sagaMu.Lock()
	defer i.sagaMu.Unlock()

	host := req.Host()
	saga, found, err := i.loadPortSaga(ctx, host)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if !found {
		return pluginsdk.Result{}, pluginsdk.Errorf("NOT_FOUND", "未找到待确认的 SSH 改端口事务")
	}
	if saga.TransactionRef != txRef {
		return pluginsdk.Result{}, pluginsdk.Errorf("PRECONDITION_FAILED", "transaction_ref 与当前挂起事务不匹配")
	}

	// 提交前再次确认新端口可达，防止半途故障导致失联。
	sshdRead, sshdReadMeta, err := sshdClientReadOnly(ctx, host)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	verifyResp, err := sshdRead.VerifyPort(ctx, &sshdv1.VerifyPortRequest{
		Context: sshdReadMeta,
		Port:    saga.NewPort,
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(verifyResp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	if !verifyResp.GetReachable() {
		return pluginsdk.Result{}, pluginsdk.Errorf("PORT_VERIFY_FAILED", "新 SSH 端口 %d 当前不可达，已拒绝提交（可继续排查或执行回滚）", saga.NewPort)
	}

	expectedRev := resolveRevision(in.ExpectedRevision, req, "sshd/config")
	if expectedRev == "" {
		expectedRev = saga.SSHDRevision
	}
	sshdWrite, sshdWriteMeta, err := sshdClientWrite(ctx, host)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	commitResp, err := sshdWrite.SetPort(ctx, &sshdv1.SetPortRequest{
		Context:          sshdWriteMeta,
		NewPort:          saga.NewPort,
		ExpectedRevision: expectedRev,
		Stage:            sshdv1.PortChangeStage_PORT_CHANGE_STAGE_COMMIT_NEW,
		TransactionRef:   saga.TransactionRef,
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(commitResp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}

	// 若准备阶段托管了防火墙，则提交完成后移除旧端口放行并保留新端口。
	if saga.FirewallManaged {
		if err := i.commitFirewallPorts(ctx, host, saga.OldPort, saga.NewPort); err != nil {
			return pluginsdk.Result{}, err
		}
	}

	if err := host.DeleteState(ctx, kvKeyPortSaga, ""); err != nil {
		return pluginsdk.Result{}, err
	}
	i.setOverviewSagaPending(ctx, host, false)

	listening := make([]uint32, 0, len(commitResp.GetListeningPorts()))
	listening = append(listening, commitResp.GetListeningPorts()...)
	return marshalResult(sshdPortSagaResponse{
		Stage:           "committed",
		TransactionRef:  saga.TransactionRef,
		OldPort:         saga.OldPort,
		NewPort:         saga.NewPort,
		ListeningPorts:  listening,
		Banner:          verifyResp.GetBanner(),
		Revision:        commitResp.GetRevision(),
		FirewallManaged: saga.FirewallManaged,
	})
}

// handleSSHDChangePortRollback 手动回滚未确认的 SSH 改端口事务。
func (i *instance) handleSSHDChangePortRollback(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in sshdChangePortActionRequest
	if err := decodeOptionalJSON(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, err
	}
	reqTxRef := strings.TrimSpace(in.TransactionRef)

	i.sagaMu.Lock()
	defer i.sagaMu.Unlock()

	host := req.Host()
	saga, found, err := i.loadPortSaga(ctx, host)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if !found {
		if reqTxRef == "" {
			return pluginsdk.Result{}, pluginsdk.Errorf("NOT_FOUND", "当前不存在可回滚的 SSH 改端口事务")
		}
		saga = portSagaState{TransactionRef: reqTxRef}
	} else if reqTxRef != "" && saga.TransactionRef != reqTxRef {
		return pluginsdk.Result{}, pluginsdk.Errorf("PRECONDITION_FAILED", "transaction_ref 与当前挂起事务不匹配")
	}

	expectedRev := resolveRevision(in.ExpectedRevision, req, "sshd/config")
	out, err := i.executePortRollbackLocked(ctx, host, saga, expectedRev)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(out)
}

func (i *instance) executePortRollbackLocked(ctx context.Context, host *pluginsdk.Host, saga portSagaState, explicitRev string) (sshdPortSagaResponse, error) {
	expectedRev := explicitRev
	if expectedRev == "" {
		expectedRev = saga.SSHDRevision
	}
	sshdWrite, sshdWriteMeta, err := sshdClientWrite(ctx, host)
	if err != nil {
		return sshdPortSagaResponse{}, err
	}
	rbResp, err := sshdWrite.SetPort(ctx, &sshdv1.SetPortRequest{
		Context:          sshdWriteMeta,
		NewPort:          saga.NewPort,
		ExpectedRevision: expectedRev,
		Stage:            sshdv1.PortChangeStage_PORT_CHANGE_STAGE_ROLLBACK,
		TransactionRef:   saga.TransactionRef,
	})
	if err != nil {
		return sshdPortSagaResponse{}, err
	}
	if err := protoError(rbResp.GetError()); err != nil {
		return sshdPortSagaResponse{}, err
	}
	if saga.FirewallManaged {
		if err := i.restoreFirewallPorts(ctx, host, saga.OldPort, saga.NewPort); err != nil {
			return sshdPortSagaResponse{}, err
		}
	}
	if err := host.DeleteState(ctx, kvKeyPortSaga, ""); err != nil {
		return sshdPortSagaResponse{}, err
	}
	i.setOverviewSagaPending(ctx, host, false)

	listening := make([]uint32, 0, len(rbResp.GetListeningPorts()))
	listening = append(listening, rbResp.GetListeningPorts()...)
	return sshdPortSagaResponse{
		Stage:           "rolled_back",
		TransactionRef:  saga.TransactionRef,
		OldPort:         saga.OldPort,
		NewPort:         saga.NewPort,
		ListeningPorts:  listening,
		Revision:        rbResp.GetRevision(),
		FirewallManaged: saga.FirewallManaged,
	}, nil
}

// ======================== 后台超时自动回滚守护协程 ========================

func (i *instance) sagaWatchLoop(ctx context.Context) {
	interval := defaultSagaWatchPollInterval
	if i.sagaIntervalOverride > 0 {
		interval = i.sagaIntervalOverride
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			i.checkExpiredPortSaga(ctx)
		}
	}
}

func (i *instance) checkExpiredPortSaga(ctx context.Context) {
	host := i.Host()
	if host == nil || host.Conn() == nil {
		return
	}
	saga, found, err := i.loadPortSaga(ctx, host)
	if err != nil || !found {
		return
	}
	if i.nowTime().Unix() < saga.DeadlineUnix {
		return
	}
	i.sagaMu.Lock()
	defer i.sagaMu.Unlock()
	// 加锁后二次读取，避免与并发 commit/rollback 重复执行。
	saga, found, err = i.loadPortSaga(ctx, host)
	if err != nil || !found || i.nowTime().Unix() < saga.DeadlineUnix {
		return
	}
	if _, err := i.executePortRollbackLocked(ctx, host, saga, ""); err != nil {
		i.Logger().Warn("SSH 改端口事务超时自动回滚失败", "transaction_ref", saga.TransactionRef, "error", err.Error())
		return
	}
	i.Logger().Info("SSH 改端口事务超时未确认，已自动回滚", "transaction_ref", saga.TransactionRef, "old_port", saga.OldPort, "new_port", saga.NewPort)
}

// ======================== Saga KV 与防火墙/端口辅助 ========================

func (i *instance) loadPortSaga(ctx context.Context, host *pluginsdk.Host) (portSagaState, bool, error) {
	if host == nil || host.Conn() == nil {
		return portSagaState{}, false, pluginsdk.ErrNoHost
	}
	raw, _, found, err := host.GetState(ctx, kvKeyPortSaga)
	if err != nil {
		return portSagaState{}, false, err
	}
	if !found || len(bytes.TrimSpace(raw)) == 0 {
		return portSagaState{}, false, nil
	}
	var saga portSagaState
	if err := json.Unmarshal(raw, &saga); err != nil {
		return portSagaState{}, false, pluginsdk.Errorf("INTERNAL", "KV 中的 SSH 端口事务数据损坏")
	}
	return saga, true, nil
}

func (i *instance) savePortSaga(ctx context.Context, host *pluginsdk.Host, saga portSagaState) error {
	raw, err := json.Marshal(saga)
	if err != nil {
		return err
	}
	_, err = host.PutState(ctx, kvKeyPortSaga, raw, pluginsdk.PutOption{})
	return err
}

func (i *instance) commitFirewallPorts(ctx context.Context, host *pluginsdk.Host, oldPort, newPort uint32) error {
	fwRead, fwReadMeta, err := firewallClientReadOnly(ctx, host)
	if err != nil {
		return err
	}
	snap, err := fwRead.GetRuleset(ctx, &firewallv1.GetRulesetRequest{Context: fwReadMeta})
	if err != nil {
		return err
	}
	if err := protoError(snap.GetError()); err != nil {
		return err
	}
	fwWrite, fwWriteMeta, err := firewallClientWrite(ctx, host)
	if err != nil {
		return err
	}
	ports := mergePorts(removePort(snap.GetPreservedPorts(), oldPort), newPort)
	resp, err := fwWrite.ApplyRuleset(ctx, &firewallv1.ApplyRulesetRequest{
		Context:          fwWriteMeta,
		RulesetJson:      rulesetOrMinimal(snap.GetRulesetJson()),
		ExpectedRevision: snap.GetRevision(),
		PreservedPorts:   ports,
	})
	if err != nil {
		return err
	}
	return protoError(resp.GetError())
}

func (i *instance) restoreFirewallPorts(ctx context.Context, host *pluginsdk.Host, oldPort, newPort uint32) error {
	fwRead, fwReadMeta, err := firewallClientReadOnly(ctx, host)
	if err != nil {
		return err
	}
	snap, err := fwRead.GetRuleset(ctx, &firewallv1.GetRulesetRequest{Context: fwReadMeta})
	if err != nil {
		return err
	}
	if err := protoError(snap.GetError()); err != nil {
		return err
	}
	fwWrite, fwWriteMeta, err := firewallClientWrite(ctx, host)
	if err != nil {
		return err
	}
	ports := mergePorts(removePort(snap.GetPreservedPorts(), newPort), oldPort)
	resp, err := fwWrite.ApplyRuleset(ctx, &firewallv1.ApplyRulesetRequest{
		Context:          fwWriteMeta,
		RulesetJson:      rulesetOrMinimal(snap.GetRulesetJson()),
		ExpectedRevision: snap.GetRevision(),
		PreservedPorts:   ports,
	})
	if err != nil {
		return err
	}
	return protoError(resp.GetError())
}

func extractListeningPorts(settings []*sshdv1.Setting) []uint32 {
	ports := make([]uint32, 0, 2)
	for _, s := range settings {
		if s == nil || !strings.EqualFold(strings.TrimSpace(s.GetKey()), "port") {
			continue
		}
		for _, field := range strings.Fields(s.GetValue()) {
			n, err := strconv.ParseUint(field, 10, 32)
			if err == nil && n >= 1 && n <= 65535 {
				ports = append(ports, uint32(n))
			}
		}
	}
	if len(ports) == 0 {
		return []uint32{22}
	}
	slices.Sort(ports)
	return slices.Compact(ports)
}

func rulesetOrMinimal(raw []byte) []byte {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && json.Valid(trimmed) {
		return trimmed
	}
	return []byte(`{"nftables":[{"table":{"family":"inet","name":"qwq"}},{"chain":{"family":"inet","table":"qwq","name":"input","type":"filter","hook":"input","prio":0,"policy":"accept"}}]}`)
}

func mergePorts(base []uint32, extra ...uint32) []uint32 {
	out := make([]uint32, 0, len(base)+len(extra))
	for _, p := range base {
		if p >= 1 && p <= 65535 {
			out = append(out, p)
		}
	}
	for _, p := range extra {
		if p >= 1 && p <= 65535 {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func removePort(base []uint32, target uint32) []uint32 {
	out := make([]uint32, 0, len(base))
	for _, p := range base {
		if p != target && p >= 1 && p <= 65535 {
			out = append(out, p)
		}
	}
	return out
}
