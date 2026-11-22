// SPDX-License-Identifier: AGPL-3.0-only

// Package apply 协调核心快照、进程与宿主元数据的可补偿事务。
package apply

import (
	"context"
	"crypto/x509"
	"errors"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/coreproc"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/secretmap"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/state"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/xrayconfig"
	"github.com/qwq-panel/qwq/sdk/coreapi"
	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

const RunningKey = "running/current"

// Step 是固定进度点；每一步前都检查取消和可用生命周期。
type Step string

const (
	LoadDesired        Step = "LOAD_DESIRED"
	CheckPreconditions Step = "CHECK_PRECONDITIONS"
	RevealSecrets      Step = "REVEAL_SECRETS"
	RenderCandidate    Step = "RENDER_CANDIDATE"
	WriteWork          Step = "WRITE_WORK"
	NativeTest         Step = "XRAY_TEST"
	InstallGeneration  Step = "INSTALL_IMMUTABLE_GENERATION"
	SnapshotLastGood   Step = "SNAPSHOT_LAST_GOOD"
	StopOld            Step = "STOP_OLD"
	StartCandidate     Step = "START_CANDIDATE"
	WaitHealth         Step = "WAIT_API_AND_HEALTH"
	CommitState        Step = "COMMIT_STATE_JSON"
	CommitHost         Step = "CAS_HOST_RUNNING_METADATA"
	ReportChanges      Step = "REPORT_CHANGES"
	CleanWork          Step = "CLEAN_WORK"
)

// Steps 返回副本，调用方不能修改全局进度顺序。
func Steps() []Step {
	return []Step{LoadDesired, CheckPreconditions, RevealSecrets, RenderCandidate, WriteWork, NativeTest, InstallGeneration, SnapshotLastGood, StopOld, StartCandidate, WaitHealth, CommitState, CommitHost, ReportChanges, CleanWork}
}

// Host 只暴露当前操作所需的窄 SDK 接口。
type Host interface {
	GetConfig(context.Context, string) ([]byte, string, error)
	RevealSecret(context.Context, string, string) ([]byte, error)
	GetState(context.Context, string) ([]byte, string, bool, error)
	PutState(context.Context, string, []byte, pluginsdk.PutOption) (string, error)
	DeleteState(context.Context, string, string) error
	ReportChanges(context.Context, ...pluginsdk.ResourceChange) error
}

// Snapshots 的提交与恢复只有一个指针文件，配置安装独立且不可变。
type Snapshots interface {
	Committed(context.Context) (*state.Metadata, error)
	Stage(context.Context, string, uint32, []byte) (state.Work, error)
	Install(context.Context, state.Work) error
	Commit(context.Context, *state.Metadata) error
	Restore(context.Context, *state.Metadata) error
	GenerationPath(context.Context, string) (string, error)
	Prune(context.Context, *state.Metadata) error
	CleanWork(context.Context, string, uint32) error
	CleanAbandonedWork(context.Context) error
}

// Process 必须持有可回收的真实进程；单元测试可用显式 fake。
type Process interface {
	Start(context.Context, coreproc.StartSpec) error
	Stop(context.Context) error
	WaitHealthy(context.Context) error
	MarkCommitted() error
	Snapshot(context.Context) coreproc.Snapshot
}
type Binary interface {
	Preflight(context.Context, string) error
}

// ObfsManager 管理受控 simple-obfs 子进程组，与核心进程同事务启停与回滚。
type ObfsManager interface {
	StartAll(context.Context, []xrayconfig.ObfsPlan) error
	StopAll(time.Duration)
	Status() (healthy bool, errText string)
}

// Options 默认复用生产 Render；Before 只用于有界进度或故障注入。
type Options struct {
	Store                  Snapshots
	Process                Process
	Binary                 Binary
	Obfs                   ObfsManager
	OutboundPolicy         func() *xrayconfig.OutboundPolicy
	Socket                 string
	DataDir                string
	PermitTestCertificates bool
	Now                    func() time.Time
	Roots                  *x509.CertPool
	TLSLoader              secretmap.TLSLoader
	Before                 func(context.Context, Step) error
	Render                 func(*coreapi.Intent, xrayconfig.Secrets, xrayconfig.Options) ([]byte, error)
	RenderV2               func(*corev2.Intent, xrayconfig.V2Materials, xrayconfig.V2Options) ([]byte, error)
}

// Request 不含 Intent 或秘密；版本和上下文由宿主派发。
type Request struct {
	Host                    Host
	ConfigRevision          string
	ExpectedRunningRevision *string
	Preconditions           []pluginsdk.Precondition
	OperationID             string
	Attempt                 uint32
	Progress                func(Step) error
}

// Result 只提供非秘密事实，原生路径和引用不进入 API。
type Result struct {
	DesiredRevision   string   `json:"desired_revision"`
	RunningRevision   string   `json:"running_revision"`
	PreviousRevision  string   `json:"previous_revision,omitempty"`
	ConfigDigest      string   `json:"config_digest"`
	CoreVersion       string   `json:"core_version"`
	Enabled           bool     `json:"enabled"`
	ProcessState      string   `json:"process_state"`
	APIState          string   `json:"api_state"`
	ResetEpoch        string   `json:"reset_epoch,omitempty"`
	RestartRequired   bool     `json:"restart_required"`
	Restarted         bool     `json:"restarted"`
	Started           bool     `json:"started"`
	RollbackPerformed bool     `json:"rollback_performed"`
	Warnings          []string `json:"warnings"`
}

// Error 的原因只保留规范代码，错误诊断与秘密永不透传。
type Error struct {
	Code              string
	RollbackPerformed bool
	RunningRevision   string
	cause             error
}

func (e *Error) Error() string { return "core apply: " + e.Code }
func (e *Error) Unwrap() error { return e.cause }
func ErrorCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
func RolledBack(err error) bool { var e *Error; return errors.As(err, &e) && e.RollbackPerformed }

// Engine 的 gate 只串行本实例写事务；状态锁不会跨阻塞操作持有。
type Engine struct {
	options     Options
	gate        chan struct{}
	mu          sync.Mutex
	active      bool
	lifetime    context.Context
	cancel      context.CancelFunc
	failure     string
	busy        bool
	serial      uint64
	tlsBindings map[string]TLSBindingStatus
	obfsPlans   []xrayconfig.ObfsPlan
}

// Observation 供状态源检验读取期间是否发生过事务或生命周期切换。
type Observation struct {
	Serial  uint64
	Busy    bool
	Active  bool
	Failure string
}
