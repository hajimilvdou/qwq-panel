// SPDX-License-Identifier: AGPL-3.0-only

// Package traffic 实现 ADR-0023 H4 内核流量整形能力（tc HTB + 可选 ifb + 独立 table inet qwq_shape）。
// 隔离保证：仅接管保留段 fwmark 0x5100..0x51FF（20736..20991）；未打标（mark=0）的 SSH 与面板流量
// 始终经高优先级默认类 1:999 全速通行，永不被限速误伤。
package traffic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/capability/local"
	"github.com/qwq-panel/qwq/internal/sandbox"
)

// ======================== 保留 Mark 段与安全上限 ========================

const (
	MinTrafficMark   uint32 = 0x5100 // 20736
	MaxTrafficMark   uint32 = 0x51FF // 20991
	MaxClasses              = 256
	MaxLimitKbps     uint32 = 10_000_000 // 10 Gbps
	DefaultHTBClass         = 999
	UserHTBClassBase        = 100 // 100..355，与默认类 999 零冲突
	cmdTimeout              = 5 * time.Second
)

var ifaceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,31}$`)

// ClassSpec 描述单个用户的 fwmark 限速策略。
type ClassSpec struct {
	TrafficMark   uint32 `json:"traffic_mark"`
	DownLimitKbps uint32 `json:"down_limit_kbps"`
	UpLimitKbps   uint32 `json:"up_limit_kbps"`
}

// StatusPayload 是 traffic.status 的结构化输出。
type StatusPayload struct {
	Supported          bool        `json:"supported"`
	UplinkIFBSupported bool        `json:"uplink_ifb_supported"`
	DegradedReason     string      `json:"degraded_reason,omitempty"`
	EgressInterface    string      `json:"egress_interface,omitempty"`
	Classes            []ClassSpec `json:"classes"`
	Revision           string      `json:"revision"`
}

// ApplyInput 是 traffic.apply 的结构化输入。
type ApplyInput struct {
	Classes          []ClassSpec `json:"classes"`
	ExpectedRevision string      `json:"expected_revision,omitempty"`
}

// ApplyPayload 是 traffic.apply 的结构化输出。
type ApplyPayload struct {
	Revision       string `json:"revision"`
	DegradedUplink bool   `json:"degraded_uplink"`
}

// ClearInput 是 traffic.clear 的结构化输入。
type ClearInput struct {
	ExpectedRevision string `json:"expected_revision,omitempty"`
}

// ClearPayload 是 traffic.clear 的结构化输出。
type ClearPayload struct {
	Revision string `json:"revision"`
}

// Runner 抽象受控系统命令执行（便于纯 Go 单元测试注入 fake）。
type Runner interface {
	Run(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/sbin:/usr/bin:/bin"}
	if len(stdin) > 0 {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	return cmd.CombinedOutput()
}

const (
	defaultTrafficStateDir  = "/var/lib/qwq-capability"
	defaultTrafficStateFile = "traffic-state.json"
	defaultTrafficLockFile  = "traffic-state.lock"
)

type persistedTrafficState struct {
	EgressIf string      `json:"egress_if,omitempty"`
	Classes  []ClassSpec `json:"classes"`
	Revision string      `json:"revision"`
}

// Service 管理独立 table inet qwq_shape 与 tc HTB 整形规则。
type Service struct {
	runner Runner
	state  local.State

	mu       sync.Mutex
	classes  []ClassSpec
	egressIf string
	revision string
}

// NewService 创建默认使用受控本地执行器与持久化文件状态的 TrafficService。
func NewService() *Service {
	st := local.FileState{
		Directory:     defaultTrafficStateDir,
		Name:          defaultTrafficStateFile,
		LockDirectory: defaultTrafficStateDir,
		LockName:      defaultTrafficLockFile,
		Trust:         sandbox.TrustPolicy{UID: 0},
		Mode:          0o600,
	}
	return NewServiceWithState(execRunner{}, st)
}

// NewServiceWithRunner 使用自定义 Runner 创建纯内存 TrafficService（供单元测试）。
func NewServiceWithRunner(r Runner) *Service {
	return NewServiceWithState(r, nil)
}

// NewServiceWithState 使用自定义 Runner 与持久化 State 创建 TrafficService。
func NewServiceWithState(r Runner, state local.State) *Service {
	if r == nil {
		r = execRunner{}
	}
	s := &Service{runner: r, state: state}
	s.revision = computeRevision("", nil)
	return s
}

func (s *Service) loadPersistedLocked() {
	if s.state == nil {
		return
	}
	raw, exists, err := s.state.Read()
	if err != nil || !exists || len(bytes.TrimSpace(raw)) == 0 {
		return
	}
	var st persistedTrafficState
	if json.Unmarshal(raw, &st) != nil {
		return
	}
	s.egressIf = st.EgressIf
	s.classes = st.Classes
	if st.Revision != "" {
		s.revision = st.Revision
	} else {
		s.revision = computeRevision(st.EgressIf, st.Classes)
	}
}

func (s *Service) savePersistedLocked() error {
	if s.state == nil {
		return nil
	}
	raw, err := json.Marshal(persistedTrafficState{
		EgressIf: s.egressIf,
		Classes:  s.classes,
		Revision: s.revision,
	})
	if err != nil {
		return err
	}
	return s.state.Commit(raw)
}

// Run 分发 traffic.status / traffic.apply / traffic.clear 能力请求。
func (s *Service) Run(ctx context.Context, req sandbox.CapabilityRequest) (sandbox.CapabilityResponse, error) {
	switch req.Op {
	case "traffic.status":
		return s.handleStatus(ctx)
	case "traffic.apply":
		return s.handleApply(ctx, req.ParamsJSON)
	case "traffic.clear":
		return s.handleClear(ctx, req.ParamsJSON)
	default:
		return sandbox.CapabilityResponse{Code: "UNIMPLEMENTED", Error: "不支持的 traffic 操作"}, nil
	}
}

func (s *Service) handleStatus(ctx context.Context) (sandbox.CapabilityResponse, error) {
	egressIf, supported, ifbOK, reason := s.probeCapabilities(ctx)

	s.mu.Lock()
	s.loadPersistedLocked()
	if egressIf != "" {
		s.egressIf = egressIf
	}
	classesCopy := append([]ClassSpec(nil), s.classes...)
	rev := s.revision
	s.mu.Unlock()

	if classesCopy == nil {
		classesCopy = []ClassSpec{}
	}
	return okResponse(StatusPayload{
		Supported:          supported,
		UplinkIFBSupported: ifbOK,
		DegradedReason:     reason,
		EgressInterface:    egressIf,
		Classes:            classesCopy,
		Revision:           rev,
	})
}

func (s *Service) handleApply(ctx context.Context, payload []byte) (sandbox.CapabilityResponse, error) {
	var in ApplyInput
	if len(bytes.TrimSpace(payload)) > 0 {
		if err := sandbox.DecodeHelperDocument(payload, &in); err != nil {
			return sandbox.CapabilityResponse{Code: "VALIDATION_FAILED", Error: "traffic.apply 参数格式无效"}, nil
		}
	}
	normalized, err := normalizeClasses(in.Classes)
	if err != nil {
		return sandbox.CapabilityResponse{Code: "VALIDATION_FAILED", Error: err.Error()}, nil
	}

	egressIf, supported, ifbOK, reason := s.probeCapabilities(ctx)
	if !supported {
		return sandbox.CapabilityResponse{Code: "UNAVAILABLE", Error: reason}, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != nil {
		if unlock, lockErr := s.state.Lock(ctx); lockErr == nil {
			defer unlock()
		}
		s.loadPersistedLocked()
	}
	if in.ExpectedRevision != "" && in.ExpectedRevision != s.revision {
		return sandbox.CapabilityResponse{Code: "PRECONDITION_FAILED", Error: "流量整形 revision 不匹配，请刷新后重试"}, nil
	}

	degradedUplink := false
	if err := s.applyKernelRules(ctx, egressIf, normalized, ifbOK, &degradedUplink); err != nil {
		return sandbox.CapabilityResponse{Code: "UNAVAILABLE", Error: err.Error()}, nil
	}

	s.egressIf = egressIf
	s.classes = normalized
	s.revision = computeRevision(egressIf, normalized)
	_ = s.savePersistedLocked()
	return okResponse(ApplyPayload{
		Revision:       s.revision,
		DegradedUplink: degradedUplink,
	})
}

func (s *Service) handleClear(ctx context.Context, payload []byte) (sandbox.CapabilityResponse, error) {
	var in ClearInput
	if len(bytes.TrimSpace(payload)) > 0 {
		if err := sandbox.DecodeHelperDocument(payload, &in); err != nil {
			return sandbox.CapabilityResponse{Code: "VALIDATION_FAILED", Error: "traffic.clear 参数格式无效"}, nil
		}
	}

	egressIf, _, _, _ := s.probeCapabilities(ctx)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != nil {
		if unlock, lockErr := s.state.Lock(ctx); lockErr == nil {
			defer unlock()
		}
		s.loadPersistedLocked()
	}
	if in.ExpectedRevision != "" && in.ExpectedRevision != s.revision {
		return sandbox.CapabilityResponse{Code: "PRECONDITION_FAILED", Error: "流量整形 revision 不匹配，请刷新后重试"}, nil
	}
	if egressIf == "" {
		egressIf = s.egressIf
	}
	if egressIf != "" {
		_, _ = s.runner.Run(ctx, "tc", []string{"qdisc", "del", "dev", egressIf, "root"}, nil)
		_, _ = s.runner.Run(ctx, "tc", []string{"qdisc", "del", "dev", egressIf, "ingress"}, nil)
	}
	_, _ = s.runner.Run(ctx, "tc", []string{"qdisc", "del", "dev", "ifb0", "root"}, nil)
	_, _ = s.runner.Run(ctx, "nft", []string{"delete", "table", "inet", "qwq_shape"}, nil)

	s.classes = nil
	s.revision = computeRevision(egressIf, nil)
	_ = s.savePersistedLocked()
	return okResponse(ClearPayload{Revision: s.revision})
}

// ======================== 内核能力探测与受控 HTB 下发 ========================

func (s *Service) probeCapabilities(ctx context.Context) (egressIf string, supported bool, ifbSupported bool, degradedReason string) {
	egressIf, err := s.detectDefaultInterface(ctx)
	if err != nil || egressIf == "" {
		return "", false, false, "EGRESS_INTERFACE_UNAVAILABLE"
	}
	if _, err := s.runner.Run(ctx, "tc", []string{"qdisc", "show", "dev", egressIf}, nil); err != nil {
		return egressIf, false, false, "KERNEL_QDISC_UNAVAILABLE"
	}
	if _, err := s.runner.Run(ctx, "ip", []string{"link", "show", "dev", "ifb0"}, nil); err == nil {
		ifbSupported = true
	} else if _, err := s.runner.Run(ctx, "modprobe", []string{"ifb", "numifbs=1"}, nil); err == nil {
		ifbSupported = true
	}
	return egressIf, true, ifbSupported, ""
}

func (s *Service) detectDefaultInterface(ctx context.Context) (string, error) {
	out, err := s.runner.Run(ctx, "ip", []string{"-o", "route", "show", "default"}, nil)
	if err != nil {
		out, err = s.runner.Run(ctx, "ip", []string{"-6", "-o", "route", "show", "default"}, nil)
		if err != nil {
			return "", err
		}
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "dev" {
				dev := fields[i+1]
				if dev != "lo" && ifaceNamePattern.MatchString(dev) {
					return dev, nil
				}
			}
		}
	}
	return "", errors.New("未找到默认出站网卡")
}

func (s *Service) applyKernelRules(ctx context.Context, egressIf string, classes []ClassSpec, ifbOK bool, degradedUplink *bool) error {
	// 1. 建立独立 nftables 表 inet qwq_shape（与 firewall.v1 的 inet qwq 完全隔离），
	//    并将保留区 fwmark 同步写入 conntrack mark 供 ifb0 入向 connmark 恢复。
	nftDoc := "table inet qwq_shape {}\nflush table inet qwq_shape\ntable inet qwq_shape {\n  chain mark_preserve {\n    type filter hook postrouting priority mangle; policy accept;\n    meta mark >= 0x5100 meta mark <= 0x51ff ct mark set meta mark\n  }\n}\n"
	if out, err := s.runner.Run(ctx, "nft", []string{"-f", "-"}, []byte(nftDoc)); err != nil {
		return fmt.Errorf("初始化 inet qwq_shape 失败: %s", strings.TrimSpace(string(out)))
	}

	// 2. 重建出口 HTB 根队列，并确保未打标（mark=0）的 SSH/面板流量恒走 1:999 全速高优先级默认类
	_, _ = s.runner.Run(ctx, "tc", []string{"qdisc", "del", "dev", egressIf, "root"}, nil)
	if out, err := s.runner.Run(ctx, "tc", []string{"qdisc", "replace", "dev", egressIf, "root", "handle", "1:", "htb", "default", strconv.Itoa(DefaultHTBClass)}, nil); err != nil {
		return fmt.Errorf("KERNEL_QDISC_UNAVAILABLE: %s", strings.TrimSpace(string(out)))
	}
	if out, err := s.runner.Run(ctx, "tc", []string{"class", "replace", "dev", egressIf, "parent", "1:", "classid", "1:1", "htb", "rate", "10000mbit", "ceil", "10000mbit"}, nil); err != nil {
		return fmt.Errorf("创建 HTB 根类失败: %s", strings.TrimSpace(string(out)))
	}
	if out, err := s.runner.Run(ctx, "tc", []string{"class", "replace", "dev", egressIf, "parent", "1:1", "classid", fmt.Sprintf("1:%d", DefaultHTBClass), "htb", "rate", "10000mbit", "ceil", "10000mbit", "prio", "0"}, nil); err != nil {
		return fmt.Errorf("创建默认保底类 1:999 失败: %s", strings.TrimSpace(string(out)))
	}

	needsUplink := false
	for _, c := range classes {
		if c.UpLimitKbps > 0 {
			needsUplink = true
		}
		if c.DownLimitKbps == 0 {
			continue
		}
		classID := fmt.Sprintf("1:%d", UserHTBClassBase+int(c.TrafficMark-MinTrafficMark))
		rate := fmt.Sprintf("%dkbit", c.DownLimitKbps)
		if out, err := s.runner.Run(ctx, "tc", []string{"class", "replace", "dev", egressIf, "parent", "1:1", "classid", classID, "htb", "rate", rate, "ceil", rate, "prio", "2"}, nil); err != nil {
			return fmt.Errorf("创建用户整形类 %s 失败: %s", classID, strings.TrimSpace(string(out)))
		}
		markStr := strconv.FormatUint(uint64(c.TrafficMark), 10)
		for _, protoName := range []string{"ip", "ipv6"} {
			if out, err := s.runner.Run(ctx, "tc", []string{"filter", "replace", "dev", egressIf, "parent", "1:", "protocol", protoName, "prio", "1", "handle", markStr, "fw", "flowid", classID}, nil); err != nil {
				return fmt.Errorf("挂载 %s fwmark 过滤器失败: %s", protoName, strings.TrimSpace(string(out)))
			}
		}
	}

	// 3. 可选 ifb0 上行整形；若容器不支持 ifb 则诚实标记 degraded_uplink=true 而非失败中断
	if needsUplink {
		if !ifbOK {
			*degradedUplink = true
			return nil
		}
		if err := s.applyIFBUplink(ctx, egressIf, classes); err != nil {
			*degradedUplink = true
		}
	}
	return nil
}

func (s *Service) applyIFBUplink(ctx context.Context, egressIf string, classes []ClassSpec) (retErr error) {
	if _, err := s.runner.Run(ctx, "ip", []string{"link", "set", "dev", "ifb0", "up"}, nil); err != nil {
		return err
	}
	_, _ = s.runner.Run(ctx, "tc", []string{"qdisc", "del", "dev", egressIf, "ingress"}, nil)
	if _, err := s.runner.Run(ctx, "tc", []string{"qdisc", "add", "dev", egressIf, "handle", "ffff:", "ingress"}, nil); err != nil {
		return err
	}
	// If any subsequent ifb0 configuration step fails, clean up the ingress qdisc
	// immediately so half-configured redirection cannot blackhole inbound traffic.
	defer func() {
		if retErr != nil {
			_, _ = s.runner.Run(ctx, "tc", []string{"qdisc", "del", "dev", egressIf, "ingress"}, nil)
		}
	}()
	if _, err := s.runner.Run(ctx, "tc", []string{"filter", "add", "dev", egressIf, "parent", "ffff:", "protocol", "all", "u32", "match", "u32", "0", "0", "action", "connmark", "action", "mirred", "egress", "redirect", "dev", "ifb0"}, nil); err != nil {
		return err
	}
	_, _ = s.runner.Run(ctx, "tc", []string{"qdisc", "del", "dev", "ifb0", "root"}, nil)
	if _, err := s.runner.Run(ctx, "tc", []string{"qdisc", "replace", "dev", "ifb0", "root", "handle", "2:", "htb", "default", strconv.Itoa(DefaultHTBClass)}, nil); err != nil {
		return err
	}
	if _, err := s.runner.Run(ctx, "tc", []string{"class", "replace", "dev", "ifb0", "parent", "2:", "classid", fmt.Sprintf("2:%d", DefaultHTBClass), "htb", "rate", "10000mbit", "ceil", "10000mbit", "prio", "0"}, nil); err != nil {
		return err
	}
	for _, c := range classes {
		if c.UpLimitKbps == 0 {
			continue
		}
		classID := fmt.Sprintf("2:%d", UserHTBClassBase+int(c.TrafficMark-MinTrafficMark))
		rate := fmt.Sprintf("%dkbit", c.UpLimitKbps)
		if _, err := s.runner.Run(ctx, "tc", []string{"class", "replace", "dev", "ifb0", "parent", "2:", "classid", classID, "htb", "rate", rate, "ceil", rate, "prio", "2"}, nil); err != nil {
			return err
		}
		markStr := strconv.FormatUint(uint64(c.TrafficMark), 10)
		for _, protoName := range []string{"ip", "ipv6"} {
			if _, err := s.runner.Run(ctx, "tc", []string{"filter", "replace", "dev", "ifb0", "parent", "2:", "protocol", protoName, "prio", "1", "handle", markStr, "fw", "flowid", classID}, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func normalizeClasses(classes []ClassSpec) ([]ClassSpec, error) {
	if len(classes) > MaxClasses {
		return nil, fmt.Errorf("单节点限速规则不得超过 %d 条", MaxClasses)
	}
	seen := make(map[uint32]struct{}, len(classes))
	out := make([]ClassSpec, 0, len(classes))
	for _, c := range classes {
		if c.TrafficMark < MinTrafficMark || c.TrafficMark > MaxTrafficMark {
			return nil, fmt.Errorf("traffic_mark 0x%x 超出保留区间 0x5100..0x51FF", c.TrafficMark)
		}
		if _, dup := seen[c.TrafficMark]; dup {
			return nil, fmt.Errorf("traffic_mark 0x%x 重复", c.TrafficMark)
		}
		if c.DownLimitKbps > MaxLimitKbps || c.UpLimitKbps > MaxLimitKbps {
			return nil, fmt.Errorf("速率上限超出允许最大值 %d kbps", MaxLimitKbps)
		}
		seen[c.TrafficMark] = struct{}{}
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b ClassSpec) int {
		if a.TrafficMark < b.TrafficMark {
			return -1
		}
		if a.TrafficMark > b.TrafficMark {
			return 1
		}
		return 0
	})
	return out, nil
}

func computeRevision(egressIf string, classes []ClassSpec) string {
	h := sha256.New()
	_, _ = h.Write([]byte(egressIf + "\x00"))
	for _, c := range classes {
		_, _ = fmt.Fprintf(h, "%d:%d:%d;", c.TrafficMark, c.DownLimitKbps, c.UpLimitKbps)
	}
	return "trf_" + hex.EncodeToString(h.Sum(nil))[:16]
}

func okResponse(v any) (sandbox.CapabilityResponse, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return sandbox.CapabilityResponse{Code: "INTERNAL", Error: "序列化流量整形响应失败"}, nil
	}
	return sandbox.CapabilityResponse{OK: true, ResultJSON: raw}, nil
}
