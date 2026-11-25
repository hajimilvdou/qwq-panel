// SPDX-License-Identifier: AGPL-3.0-only

package firewall

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/capability/local"
	"github.com/qwq-panel/qwq/internal/sandbox"
	firewallv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/firewall/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Manager 保留实际活动状态；无法确认的已有管理者同样触发共存保护。
type Manager struct {
	Kind      string
	Active    bool
	Detail    string
	Uncertain bool
}

// Guard 提供 helper 自行核验的事实，不能从插件消息中推导。
type Guard interface {
	PreservedPorts(context.Context) ([]uint32, error)
	Managers(context.Context) ([]Manager, error)
}

// Service 只执行闭合 firewall verb，所有状态读取/写入在跨进程锁内进行。
type Service struct {
	Executor       local.Executor
	State          local.State
	Guard          Guard
	PanelPortState local.State
}

// Mutation 的 HostPorts 由宿主 forwarder 注入，helper 还会并入自己的当前事实。
type Mutation struct {
	Ruleset          json.RawMessage `json:"ruleset_json,omitempty"`
	ExpectedRevision string          `json:"expected_revision"`
	PreservedPorts   []uint32        `json:"preserved_ports,omitempty"`
	HostPorts        []uint32        `json:"host_preserved_ports"`
}

func (s *Service) Run(ctx context.Context, request sandbox.CapabilityRequest) (sandbox.CapabilityResponse, error) {
	if s.Executor == nil || s.State == nil || s.Guard == nil {
		return failure("UNAVAILABLE", "防火墙执行器未配置"), nil
	}
	if len(request.Secret) != 0 || request.Cursor != "" {
		return failure("VALIDATION_FAILED", "防火墙请求包含不支持的字段"), nil
	}
	params := request.ParamsJSON
	if len(params) == 0 {
		params = []byte("{}")
	}
	if request.Op == "firewall.restore" {
		if decodeObject(params, new(struct{})) != nil {
			return failure("VALIDATION_FAILED", "恢复请求不能提供新策略"), nil
		}
		if err := s.Restore(ctx); err != nil {
			return failure("UNAVAILABLE", "已保存的防火墙策略未能恢复"), nil
		}
		return sandbox.CapabilityResponse{OK: true}, nil
	}
	if request.Op == "firewall.sync-panel-port" {
		return s.syncPanelPort(ctx, params), nil
	}
	if request.Op == "firewall.takeover_status" {
		return s.takeoverStatusOp(ctx), nil
	}
	if request.Op == "firewall.takeover" {
		return s.takeoverManagerOp(ctx, params), nil
	}
	if request.Op == "firewall.restore_manager" {
		return s.restoreManagerOp(ctx, params), nil
	}
	if request.Op == "firewall.detect" {
		if decodeObject(params, new(struct{})) != nil {
			return failure("VALIDATION_FAILED", "检测请求格式无效"), nil
		}
		managers, err := s.Guard.Managers(ctx)
		if err != nil {
			return failure("UNAVAILABLE", "共存状态暂不可用"), nil
		}
		response := new(firewallv1.DetectManagersResponse)
		for _, manager := range managers {
			response.Managers = append(response.Managers, &firewallv1.Manager{Kind: manager.Kind, Active: manager.Active, Detail: manager.Detail})
		}
		return packed(response), nil
	}
	unlock, err := s.State.Lock(ctx)
	if err != nil {
		return failure("UNAVAILABLE", "防火墙资源锁不可用"), nil
	}
	defer unlock()
	required, err := s.Guard.PreservedPorts(ctx)
	if err != nil {
		return failure("UNAVAILABLE", "当前管理端口无法核验"), nil
	}
	required, err = preservedPorts(required, required)
	if err != nil {
		return failure("UNAVAILABLE", "当前管理端口无效"), nil
	}
	current, err := s.readSnapshot(ctx)
	if err != nil {
		return failure("UNAVAILABLE", "防火墙实时状态或持久状态不可用"), nil
	}
	if request.Op == "firewall.get" {
		if decodeObject(params, new(struct{})) != nil {
			return failure("VALIDATION_FAILED", "读取请求格式无效"), nil
		}
		return packed(&firewallv1.GetRulesetResponse{RulesetJson: current.definition, Revision: current.revision, PreservedPorts: required, PersistencePending: current.pending}), nil
	}
	if request.Op != "firewall.apply" && request.Op != "firewall.reset" {
		return failure("VALIDATION_FAILED", "防火墙动作不受支持"), nil
	}
	var mutation Mutation
	if decodeObject(params, &mutation) != nil || len(mutation.ExpectedRevision) != 64 {
		return failure("VALIDATION_FAILED", "防火墙参数无效"), nil
	}
	if _, err := hex.DecodeString(mutation.ExpectedRevision); err != nil {
		return failure("VALIDATION_FAILED", "防火墙版本格式无效"), nil
	}
	if mutation.ExpectedRevision != current.revision {
		return failure("PRECONDITION_FAILED", "防火墙状态已变化，请重新预演"), nil
	}
	if len(mutation.HostPorts) == 0 {
		return failure("PRECONDITION_FAILED", "缺少宿主管理端口事实"), nil
	}
	required, err = preservedPorts(required, mergePorts(required, mutation.HostPorts))
	if err != nil {
		return failure("VALIDATION_FAILED", "宿主管理端口无效"), nil
	}
	managers, err := s.Guard.Managers(ctx)
	if err != nil {
		return failure("UNAVAILABLE", "共存状态暂不可用"), nil
	}
	for _, manager := range managers {
		if manager.Active || manager.Uncertain {
			return failure("CONFLICT", "存在尚未接管的防火墙管理者"), nil
		}
	}
	var desired *Ruleset
	if request.Op == "firewall.reset" {
		if len(mutation.Ruleset) != 0 || len(mutation.PreservedPorts) != 0 {
			return failure("VALIDATION_FAILED", "重置请求包含额外策略"), nil
		}
		desired, err = Minimal(required)
	} else {
		desired, err = Normalize(mutation.Ruleset, required, mutation.PreservedPorts)
	}
	if err != nil {
		return failure("VALIDATION_FAILED", "规则集不符合安全白名单或缺少保留端口"), nil
	}
	return s.apply(ctx, current, desired, required), nil
}

func (s *Service) apply(ctx context.Context, before snapshot, desired *Ruleset, required []uint32) sandbox.CapabilityResponse {
	definition, err := desired.Definition()
	if err != nil {
		return failure("VALIDATION_FAILED", "候选规则集无效")
	}
	transaction, err := desired.Transaction(before.tableExists, before.chainExists)
	if err != nil {
		return failure("VALIDATION_FAILED", "候选事务无效")
	}
	if _, err := s.execute(ctx, []string{"-j", "--check", "-f", "-"}, transaction); err != nil {
		return failure("VALIDATION_FAILED", "nft 原生预检未通过")
	}
	checked, err := s.readSnapshot(ctx)
	if err != nil {
		return failure("UNAVAILABLE", "预检后的实时状态无法核验")
	}
	if checked.revision != before.revision {
		return failure("PRECONDITION_FAILED", "预检期间防火墙状态已变化")
	}
	currentPorts, err := s.Guard.PreservedPorts(ctx)
	if err != nil {
		return failure("UNAVAILABLE", "写入前管理端口无法核验")
	}
	if _, err := preservedPorts(currentPorts, required); err != nil {
		return failure("PRECONDITION_FAILED", "预检期间管理端口已变化")
	}
	if ctx.Err() != nil {
		return failure("CANCELED", "防火墙变更已取消")
	}
	if _, err := s.execute(ctx, []string{"-j", "-f", "-"}, transaction); err != nil {
		if !s.rollback(ctx, before, definition, required) {
			return failure("RECOVERY_REQUIRED", "执行结果不确定，恢复未完成，请检查实时状态")
		}
		return failure("UNAVAILABLE", "防火墙执行失败，已恢复旧策略")
	}
	after, err := s.readSnapshot(ctx)
	if err != nil || !bytes.Equal(after.definition, definition) {
		if !s.rollback(ctx, before, definition, required) {
			return failure("RECOVERY_REQUIRED", "写后核验失败，恢复未完成，请检查实时状态")
		}
		return failure("UNAVAILABLE", "写后核验失败，已恢复旧策略")
	}
	if err := s.State.Commit(definition); err != nil {
		if !s.rollback(ctx, before, definition, required) {
			return failure("RECOVERY_REQUIRED", "策略保存失败，恢复未完成，请检查实时状态")
		}
		return failure("UNAVAILABLE", "策略保存失败，已恢复旧策略")
	}
	committed, err := s.readSnapshot(ctx)
	if err != nil || committed.pending || !bytes.Equal(committed.definition, definition) {
		return failure("RECOVERY_REQUIRED", "提交结果无法确认，请检查实时与持久状态")
	}
	return packed(&firewallv1.ApplyRulesetResponse{Revision: committed.revision})
}

// rollback 使用独立短 deadline；只恢复自己的候选状态，不覆盖第三方并发修改。
func (s *Service) rollback(ctx context.Context, before snapshot, candidate []byte, required []uint32) bool {
	recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	current, err := s.readSnapshot(recovery)
	if err != nil {
		return false
	}
	if !bytes.Equal(current.definition, before.definition) {
		if !bytes.Equal(current.definition, candidate) {
			return false
		}
		var transaction []byte
		if before.chainExists {
			_, oldPorts, err := snapshotDefinition(before.definition, true)
			if err != nil {
				return false
			}
			old, err := Normalize(before.definition, required, mergePorts(required, oldPorts))
			if err != nil {
				return false
			}
			transaction, err = old.Transaction(current.tableExists, current.chainExists)
			if err != nil {
				return false
			}
		} else {
			transaction = []byte(`{"nftables":[{"delete":{"chain":{"family":"inet","table":"qwq","name":"input"}}}]}`)
		}
		if _, err := s.execute(recovery, []string{"-j", "--check", "-f", "-"}, transaction); err != nil {
			return false
		}
		if _, err := s.execute(recovery, []string{"-j", "-f", "-"}, transaction); err != nil {
			return false
		}
	}
	if before.persistedExists {
		err = s.State.Commit(before.persisted)
	} else {
		err = s.State.Commit(nil)
	}
	if err != nil {
		return false
	}
	after, err := s.readSnapshot(recovery)
	if err != nil || after.chainExists != before.chainExists || after.persistedExists != before.persistedExists || !bytes.Equal(after.persisted, before.persisted) {
		return false
	}
	// 只核对本能力拥有的 input 策略；首次失败留下的空 qwq 表不属于策略变化。
	return !before.chainExists || bytes.Equal(after.definition, before.definition)
}

func mergePorts(a, b []uint32) []uint32 {
	ports := append(append([]uint32(nil), a...), b...)
	slices.Sort(ports)
	return slices.Compact(ports)
}

func (s *Service) syncPanelPort(ctx context.Context, params []byte) sandbox.CapabilityResponse {
	var req struct {
		Port       uint32 `json:"port"`
		ListenHost string `json:"listen_host,omitempty"`
	}
	if decodeObject(params, &req) != nil || req.Port == 0 || req.Port > 65535 {
		return failure("VALIDATION_FAILED", "面板端口参数无效")
	}
	listenHost := strings.TrimSpace(req.ListenHost)
	if listenHost != "" && !strings.EqualFold(listenHost, "localhost") {
		trimmed := strings.Trim(listenHost, "[]")
		ip, perr := netip.ParseAddr(trimmed)
		if perr != nil || ip.IsMulticast() {
			return failure("VALIDATION_FAILED", "面板监听主机地址无效")
		}
	}
	loopbackOnly := listenHost != "" && IsLoopbackOnlyHost(listenHost)
	unlock, err := s.State.Lock(ctx)
	if err != nil {
		return failure("UNAVAILABLE", "防火墙资源锁不可用")
	}
	defer unlock()
	rawPort, err := json.Marshal(AuthoritativePanelPortHint{
		Port:       uint16(req.Port),
		ListenHost: listenHost,
		UpdatedAt:  time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return failure("INTERNAL", "编码面板端口配置失败")
	}
	portState := s.PanelPortState
	if portState == nil {
		portState = local.FileState{Directory: "/var/lib/qwq-capability", Name: "panel-port.json", Mode: 0644}
	}
	var prevPanelPort uint32
	prevRaw, prevExists, rerr := portState.Read()
	if rerr == nil && prevExists && len(prevRaw) > 0 {
		var prev struct {
			Port uint32 `json:"port"`
		}
		if json.Unmarshal(prevRaw, &prev) == nil && prev.Port > 0 && prev.Port <= 65535 {
			prevPanelPort = prev.Port
		}
	}
	var prevRequired []uint32
	if prevPanelPort == 0 && s.Guard != nil {
		prevRequired, _ = s.Guard.PreservedPorts(ctx)
	}
	rollbackPortState := func() {
		if prevExists {
			_ = portState.Commit(prevRaw)
		} else {
			_ = portState.Commit(nil)
		}
	}
	if err := portState.Commit(rawPort); err != nil {
		return failure("UNAVAILABLE", "写入面板端口状态失败")
	}
	current, err := s.readSnapshot(ctx)
	if err != nil {
		rollbackPortState()
		return failure("UNAVAILABLE", "读取当前防火墙规则快照失败")
	}
	if !current.chainExists {
		return sandbox.CapabilityResponse{OK: true}
	}
	managers, err := s.Guard.Managers(ctx)
	if err != nil {
		rollbackPortState()
		return failure("UNAVAILABLE", "检测系统既有防火墙管理器失败")
	}
	for _, manager := range managers {
		if manager.Active || manager.Uncertain {
			return sandbox.CapabilityResponse{OK: true}
		}
	}
	required, err := s.Guard.PreservedPorts(ctx)
	if err != nil {
		rollbackPortState()
		return failure("UNAVAILABLE", "识别保留管理端口失败")
	}
	if !loopbackOnly {
		required = mergePorts(required, []uint32{req.Port})
	}
	_, oldPorts, err := snapshotDefinition(current.definition, true)
	if err != nil {
		rollbackPortState()
		return failure("UNAVAILABLE", "解析当前防火墙保留端口失败")
	}
	// Retire the superseded panel port (or close the panel port entirely when
	// tightened back to loopback), without touching SSH or user rules.
	retireSet := make(map[uint32]bool)
	if prevPanelPort != 0 && (prevPanelPort != req.Port || loopbackOnly) {
		retireSet[prevPanelPort] = true
	} else if prevPanelPort == 0 && len(prevRequired) > 0 {
		for _, p := range prevRequired {
			if !slices.Contains(required, p) {
				retireSet[p] = true
			}
		}
	}
	if loopbackOnly {
		retireSet[req.Port] = true
	}
	if len(retireSet) > 0 {
		filtered := make([]uint32, 0, len(oldPorts))
		for _, p := range oldPorts {
			if !retireSet[p] || slices.Contains(required, p) {
				filtered = append(filtered, p)
			}
		}
		oldPorts = filtered
	}
	declared := mergePorts(required, oldPorts)
	desired, err := Normalize(current.definition, required, declared)
	if err != nil {
		rollbackPortState()
		return failure("UNAVAILABLE", "重建防火墙面板保留端口规则失败")
	}
	desiredDef, err := desired.Definition()
	if err != nil {
		rollbackPortState()
		return failure("INTERNAL", "编码防火墙目标规则失败")
	}
	if bytes.Equal(desiredDef, current.definition) {
		return sandbox.CapabilityResponse{OK: true}
	}
	resp := s.apply(ctx, current, desired, required)
	if !resp.OK {
		rollbackPortState()
		return resp
	}
	return sandbox.CapabilityResponse{OK: true}
}
func failure(code, message string) sandbox.CapabilityResponse {
	return sandbox.CapabilityResponse{Code: code, Error: message}
}
func packed(message proto.Message) sandbox.CapabilityResponse {
	raw, err := protojson.Marshal(message)
	if err != nil {
		return failure("INTERNAL", "防火墙结果编码失败")
	}
	return sandbox.CapabilityResponse{OK: true, ResultJSON: raw}
}

// Restore 只由 root 启动入口调用：恢复既有授权策略，并重新核验当前管理端口。
func (s *Service) Restore(ctx context.Context) error {
	if s.State == nil || s.Guard == nil || s.Executor == nil {
		return errors.New("firewall: restore is not configured")
	}
	unlock, err := s.State.Lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	if _, exists, err := s.State.Read(); err != nil {
		return err
	} else if !exists {
		return nil
	}
	before, err := s.readSnapshot(ctx)
	if err != nil {
		return err
	}
	if !before.persistedExists {
		return nil
	}
	required, err := s.Guard.PreservedPorts(ctx)
	if err != nil {
		return err
	}
	_, oldPorts, err := snapshotDefinition(before.persisted, true)
	if err != nil {
		return err
	}
	desired, err := Normalize(before.persisted, required, mergePorts(required, oldPorts))
	if err != nil {
		return err
	}
	managers, err := s.Guard.Managers(ctx)
	if err != nil {
		return err
	}
	for _, manager := range managers {
		if manager.Active || manager.Uncertain {
			return errors.New("firewall: another manager blocks restore")
		}
	}
	response := s.apply(ctx, before, desired, required)
	if !response.OK {
		return errors.New("firewall: saved policy could not be restored")
	}
	return nil
}
