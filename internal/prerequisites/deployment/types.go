// SPDX-License-Identifier: AGPL-3.0-only

// Package deployment 实现宿主证书消费绑定的受控部署、对账、清理与引用保护账本。
package deployment

import (
	"context"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/consumerfiles"
	"github.com/qwq-panel/qwq/internal/prerequisites/hostauth"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 受控依赖接口与部署器定义 ========================

// Authorizer 负责在宿主侧确认消费绑定授权与精确解绑删除许可。
type Authorizer interface {
	ConfirmConsumerBinding(ctx context.Context, caller certificates.Caller, certificateID string, generation uint64, consumer certificates.Consumer) (certificates.HostBinding, error)
	AuthorizeConsumerRemoval(ctx context.Context, caller certificates.Caller, binding certificates.HostBinding) error
}

// MaterialLoader 仅向已确认消费绑定的部署器提供受控证书与私钥材料。
type MaterialLoader interface {
	LoadMaterial(ctx context.Context, caller certificates.Caller, certificateID string, reference certificates.MaterialRef) (tlsmgr.Material, error)
}

// FileBackend 负责将授权 generation 落盘到消费者隔离目录并原子切换或安全清理。
type FileBackend interface {
	Stage(ctx context.Context, binding certificates.HostBinding, material tlsmgr.Material) (consumerfiles.Proof, error)
	Activate(ctx context.Context, pluginID string, expected *consumerfiles.Proof, wanted consumerfiles.Proof) (*consumerfiles.Proof, error)
	Current(ctx context.Context, pluginID, bindingID string) (*consumerfiles.Proof, error)
	Remove(ctx context.Context, pluginID, bindingID string) (bool, error)
}

// RuntimeObservation 描述消费者运行时实际加载的证书代与监听端点事实。
type RuntimeObservation struct {
	Running          bool
	BindingID        string
	ActiveGeneration uint64
	PolicyRevision   string
	FullchainSHA256  string
	LeafFingerprint  string
	SNI              string
	Endpoint         string
}

// ConsumerRuntime 抽象宿主侧对消费者运行时的热加载、状态观测与占用检查。
type ConsumerRuntime interface {
	Apply(ctx context.Context, binding certificates.HostBinding, proof consumerfiles.Proof) error
	Inspect(ctx context.Context, consumer certificates.Consumer, bindingID string) (RuntimeObservation, error)
	InUse(ctx context.Context, binding certificates.HostBinding) (bool, error)
}

// HandshakeProbeResult 保存真实 TLS 握手探针观测到的对端叶证书与协商参数。
type HandshakeProbeResult struct {
	PeerLeafFingerprint string
	NegotiatedSNI       string
	NegotiatedProtocol  string
}

// HandshakeProber 执行真实 TLS 握手核验，确认运行时对外提供的是期望叶证书。
type HandshakeProber interface {
	Probe(ctx context.Context, consumer certificates.Consumer, observation RuntimeObservation, expectedLeafFingerprint string) (HandshakeProbeResult, error)
}

// Options 配置 Deployer 所需的全部宿主受控后端与上限。
type Options struct {
	Repository store.Repository
	Authority  Authorizer
	Materials  MaterialLoader
	Files      FileBackend
	Runtime    ConsumerRuntime
	Prober     HandshakeProber
	Clock      clock.Clock
	MaxRecords int // default 256, max 256
}

// Deployer 协调消费者证书落盘、运行时生效、真实握手校验与宿主引用账本。
type Deployer struct {
	repository store.Repository
	authority  Authorizer
	materials  MaterialLoader
	files      FileBackend
	runtime    ConsumerRuntime
	prober     HandshakeProber
	clock      clock.Clock
	maxRecords int

	// 严格锁序：removalGate -> ledgerMu，绝不反向加锁；References 仅取 ledgerMu 防止与 LockForRemoval 死锁。
	removalGate chan struct{} // buffered cap 1
	ledgerMu    sync.Mutex
}

// ======================== 私有部署账本持久化模型 ========================

type proofRecord struct {
	Proof           consumerfiles.Proof `json:"proof"`
	LeafFingerprint string              `json:"leaf_fingerprint"`
}

func (proofRecord) String() string   { return "deployment.proofRecord{[REDACTED]}" }
func (proofRecord) GoString() string { return "deployment.proofRecord{[REDACTED]}" }

type pendingDeployment struct {
	Target      certificates.HostBinding `json:"target"`
	TargetProof *proofRecord             `json:"target_proof,omitempty"`
	Expected    *proofRecord             `json:"expected,omitempty"`
	Phase       string                   `json:"phase"`
	UpdatedAt   time.Time                `json:"updated_at"`
}

type bindingRecord struct {
	ID       string             `json:"id"`
	Active   *proofRecord       `json:"active,omitempty"`
	Previous *proofRecord       `json:"previous,omitempty"`
	Pending  *pendingDeployment `json:"pending,omitempty"`
}

type deploymentLedger struct {
	Version int             `json:"version"`
	Records []bindingRecord `json:"records"`
}

var (
	_ Authorizer     = (*hostauth.Authority)(nil)
	_ MaterialLoader = (*certificates.Vault)(nil)
)
