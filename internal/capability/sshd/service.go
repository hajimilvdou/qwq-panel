// SPDX-License-Identifier: AGPL-3.0-only

package sshd

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"regexp"
	"slices"
	"time"

	"github.com/qwq-panel/qwq/internal/capability/bridge"
	"github.com/qwq-panel/qwq/internal/capability/local"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/sandbox"
	sshdv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/sshd/v1"
)

var userPattern = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

// Match 仅用于只读来源查询；写操作的 Address 必须由宿主事实注入。
type Match struct {
	User    string `json:"match_user,omitempty"`
	Address string `json:"match_address,omitempty"`
}

// Snapshot 的 revision 覆盖完整 Include 图，ExternalRevision 排除唯一自有文件。
type Snapshot struct {
	Revision         string
	ExternalRevision string
	Content          []byte
	Exists           bool
	Writable         bool
	Ports            []uint32
	LivePorts        []uint32
	Settings         []*sshdv1.Setting
	graph            *configGraph
}

type Repository interface {
	Read(context.Context, Match) (Snapshot, error)
	Candidate(context.Context, Snapshot, []byte, Match) (Snapshot, error)
	Commit([]byte) error
}

// Runtime 查询标准 SSH 单元、TCP 占用、回环健康和真实防火墙入站状态。
type Runtime interface {
	Ports(context.Context) ([]uint32, error)
	ManagementPorts(context.Context) ([]uint32, error)
	Conflicts(context.Context, uint32) (bool, error)
	Reload(context.Context) error
	Verify(context.Context, uint32) (string, error)
	// RequireSSHPort 在共享 capability 资源锁内确认新端口不会被自有策略阻断。
	RequireSSHPort(context.Context, uint32) error
}

// RecoveryGuard 在收紧策略前证明指定用户仍有可用公钥登录路径。
type RecoveryGuard interface {
	Check(context.Context, string, string, Snapshot) error
}

type Service struct {
	Repository   Repository
	Runtime      Runtime
	Transactions local.State
	Recovery     RecoveryGuard
	Now          func() time.Time
}

func (s *Service) Run(ctx context.Context, request sandbox.CapabilityRequest) (sandbox.CapabilityResponse, error) {
	if s.Repository == nil || s.Runtime == nil || s.Transactions == nil {
		return bridge.Failure("UNAVAILABLE", "SSH 执行器未配置"), nil
	}
	if sandbox.ValidateCapabilityRequest(request) != nil || len(request.Secret) != 0 || request.Cursor != "" {
		return bridge.Failure("VALIDATION_FAILED", "SSH 请求无效"), nil
	}
	unlock, err := s.Transactions.Lock(ctx)
	if err != nil {
		return bridge.Failure("UNAVAILABLE", "SSH 资源锁不可用"), nil
	}
	defer unlock()
	params := request.ParamsJSON
	if len(params) == 0 {
		params = []byte("{}")
	}
	switch request.Op {
	case "sshd.get-effective":
		var match Match
		if decode(params, &match) != nil || !validMatch(match) {
			return bridge.Failure("VALIDATION_FAILED", "SSH 匹配条件无效"), nil
		}
		current, err := s.Repository.Read(ctx, match)
		if err != nil {
			return bridge.Failure("UNAVAILABLE", "有效 SSH 配置不可用"), nil
		}
		return bridge.Pack(&sshdv1.GetEffectiveConfigResponse{Settings: current.Settings, Revision: current.Revision}), nil
	case "sshd.get-dropin":
		var query struct {
			InstanceID string `json:"instance_id,omitempty"`
		}
		if decode(params, &query) != nil || query.InstanceID != "" && sandbox.ValidateID(query.InstanceID) != nil {
			return bridge.Failure("VALIDATION_FAILED", "读取参数无效"), nil
		}
		current, err := s.Repository.Read(ctx, Match{})
		if err != nil {
			return bridge.Failure("UNAVAILABLE", "SSH 配置不可用"), nil
		}
		response := &sshdv1.GetDropInResponse{Content: string(current.Content), Revision: current.Revision, Exists: current.Exists}
		record, _, err := s.transaction()
		if err != nil {
			return bridge.Failure("UNAVAILABLE", "SSH 事务记录不可用"), nil
		}
		if record != nil && record.Stage != "COMMITTED" {
			response.TransactionPending = true
			if record.PluginID == request.ID && record.InstanceID == query.InstanceID {
				response.TransactionRef, response.TransactionStage, response.TransactionOperationId = record.Reference, record.Stage, record.OperationID
				response.TransactionPort, response.TransactionKind = record.NewPort, record.Kind
			}
		}
		return bridge.Pack(response), nil
	case "sshd.verify-port":
		var query struct {
			Port uint32 `json:"port"`
		}
		if decode(params, &query) != nil || query.Port == 0 || query.Port > 65535 {
			return bridge.Failure("VALIDATION_FAILED", "验证端口无效"), nil
		}
		current, err := s.Repository.Read(ctx, Match{})
		if err != nil || !slices.Contains(current.Ports, query.Port) {
			return bridge.Failure("PRECONDITION_FAILED", "只能验证当前 SSH 配置中的端口"), nil
		}
		banner, err := s.verify(ctx, []uint32{query.Port})
		if err != nil {
			return bridge.Failure("PORT_VERIFY_FAILED", "SSH 端口未能验证"), nil
		}
		hasExternal := false
		if probe, ok := s.Runtime.(interface {
			HasExternalConnection(context.Context, uint32) bool
		}); ok {
			hasExternal = probe.HasExternalConnection(ctx, query.Port)
		}
		return bridge.Pack(&sshdv1.VerifyPortResponse{
			Reachable:             true,
			Banner:                banner,
			HasExternalConnection: hasExternal,
		}), nil
	case "sshd.write-dropin":
		var tag map[string]json.RawMessage
		var kind string
		if decode(params, &tag) != nil || json.Unmarshal(tag["kind"], &kind) != nil {
			return bridge.Failure("VALIDATION_FAILED", "SSH 变更类型无效"), nil
		}
		if kind == "port" {
			var mutation PortMutation
			if decode(params, &mutation) != nil {
				return bridge.Failure("VALIDATION_FAILED", "端口事务参数无效"), nil
			}
			return s.setPort(ctx, request.ID, mutation), nil
		}
		if kind == "login" {
			var mutation LoginMutation
			if decode(params, &mutation) != nil {
				return bridge.Failure("VALIDATION_FAILED", "登录策略参数无效"), nil
			}
			return s.setLogin(ctx, request.ID, mutation), nil
		}
		return bridge.Failure("VALIDATION_FAILED", "SSH 变更类型不受支持"), nil
	case "sshd.remove-dropin":
		var mutation RemoveMutation
		if decode(params, &mutation) != nil {
			return bridge.Failure("VALIDATION_FAILED", "移除参数无效"), nil
		}
		return s.remove(ctx, request.ID, mutation), nil
	case "sshd.recover-dropin":
		var mutation RecoveryMutation
		if decode(params, &mutation) != nil {
			return bridge.Failure("VALIDATION_FAILED", "恢复参数无效"), nil
		}
		return s.recoverDropIn(ctx, request.ID, mutation), nil
	default:
		return bridge.Failure("UNIMPLEMENTED", "SSH 原语未开放"), nil
	}
}

func decode(raw []byte, target any) error { return sandbox.DecodeHelperDocument(raw, target) }
func validRevision(revision string) bool {
	_, err := hex.DecodeString(revision)
	return len(revision) == 64 && err == nil
}

func validOperationID(operationID string) bool { return ids.Valid(operationID, ids.Operation) }
func validMatch(match Match) bool {
	if match.User != "" && !userPattern.MatchString(match.User) {
		return false
	}
	if match.Address != "" {
		address, err := netip.ParseAddr(match.Address)
		if err != nil || address.Zone() != "" {
			return false
		}
	}
	return true
}
func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) verify(ctx context.Context, ports []uint32) (string, error) {
	return s.verifyFor(ctx, ports, false)
}

func (s *Service) verifyAll(ctx context.Context, ports []uint32) (string, error) {
	return s.verifyFor(ctx, ports, true)
}

func (s *Service) verifyFor(ctx context.Context, ports []uint32, exact bool) (string, error) {
	if !validPorts(uniquePorts(ports)) {
		return "", errPortVerification
	}
	health, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var last error
	for attempt := range 5 {
		banner, err := s.verifyOnce(health, ports, exact)
		if err == nil {
			return banner, nil
		}
		last = err
		if attempt == 4 {
			break
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-health.Done():
			timer.Stop()
			return "", last
		case <-timer.C:
		}
	}
	return "", last
}

func (s *Service) verifyOnce(ctx context.Context, ports []uint32, exact bool) (string, error) {
	live, err := s.Runtime.Ports(ctx)
	if err != nil {
		return "", err
	}
	if exact && !slices.Equal(uniquePorts(live), uniquePorts(ports)) {
		return "", errPortVerification
	}
	var banner string
	for _, port := range uniquePorts(ports) {
		if !slices.Contains(live, port) {
			return "", errPortVerification
		}
		banner, err = s.Runtime.Verify(ctx, port)
		if err != nil {
			return "", err
		}
	}
	if banner == "" {
		return "", errPortVerification
	}
	return banner, nil
}

// replace 在预检后再次 CAS；失败恢复用独立短 deadline，且不覆盖外部改动。
func (s *Service) replace(ctx context.Context, before, candidate Snapshot, raw []byte) (Snapshot, string) {
	checked, err := s.Repository.Read(ctx, Match{})
	if err != nil {
		return Snapshot{}, "UNAVAILABLE"
	}
	if checked.Revision != before.Revision {
		return Snapshot{}, "PRECONDITION_FAILED"
	}
	live, err := s.Runtime.Ports(ctx)
	if err != nil || !validPorts(uniquePorts(live)) {
		return Snapshot{}, "UNAVAILABLE"
	}
	if len(before.LivePorts) == 0 {
		before.LivePorts = uniquePorts(live)
	} else if !slices.Equal(uniquePorts(live), before.LivePorts) {
		return Snapshot{}, "PRECONDITION_FAILED"
	}
	if ctx.Err() != nil {
		return Snapshot{}, "CANCELED"
	}
	if err := s.Repository.Commit(raw); err == nil {
		err = s.Runtime.Reload(ctx)
		if err == nil {
			after, readErr := s.Repository.Read(ctx, Match{})
			if readErr == nil && after.Revision == candidate.Revision {
				if _, verifyErr := s.verifyAll(ctx, candidate.Ports); verifyErr == nil {
					after.LivePorts = slices.Clone(candidate.Ports)
					return after, ""
				}
			}
		}
	}
	if !s.restore(ctx, before, candidate) {
		return Snapshot{}, "RECOVERY_REQUIRED"
	}
	return Snapshot{}, "UNAVAILABLE"
}

func (s *Service) restore(ctx context.Context, before, candidate Snapshot) bool {
	recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	current, err := s.Repository.Read(recovery, Match{})
	if err != nil || current.ExternalRevision != before.ExternalRevision || (!bytes.Equal(current.Content, before.Content) && !bytes.Equal(current.Content, candidate.Content)) {
		return false
	}
	if !bytes.Equal(current.Content, before.Content) {
		if _, err := s.Repository.Candidate(recovery, current, before.Content, Match{}); err != nil {
			return false
		}
		if err := s.Repository.Commit(before.Content); err != nil {
			return false
		}
	}
	if s.Runtime.Reload(recovery) != nil {
		return false
	}
	after, err := s.Repository.Read(recovery, Match{})
	if err != nil || after.Revision != before.Revision {
		return false
	}
	ports := before.LivePorts
	if len(ports) == 0 {
		ports = before.Ports
	}
	_, err = s.verifyAll(recovery, ports)
	return err == nil
}
