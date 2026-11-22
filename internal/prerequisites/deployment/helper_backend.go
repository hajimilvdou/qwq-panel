// SPDX-License-Identifier: AGPL-3.0-only

package deployment

import (
	"context"
	"encoding/base64"
	"errors"

	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/consumerfiles"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 特权助手文件后端：通过受限 Unix 协议操作插件私有证书目录 ========================

// HelperFileBackend 通过 root 特权助手执行消费者证书的暂存、CAS 激活、查询与清理。
type HelperFileBackend struct {
	Client *sandbox.HelperClient
}

var _ FileBackend = (*HelperFileBackend)(nil)

// Stage 把证书链与私钥编码进有界暂存请求，并核对特权助手返回的证明与绑定完全一致。
func (b *HelperFileBackend) Stage(ctx context.Context, binding certificates.HostBinding, material tlsmgr.Material) (consumerfiles.Proof, error) {
	if b == nil || b.Client == nil {
		return consumerfiles.Proof{}, fault.New("BACKEND_REQUIRED", "消费者证书特权助手客户端未配置")
	}
	chain := material.CertificatePEM()
	defer clear(chain)
	key := material.PrivateKeyPEM()
	defer clear(key)
	if len(chain) == 0 || len(key) == 0 {
		return consumerfiles.Proof{}, fault.New("CERTIFICATE_INVALID", "消费者证书链或私钥材料为空")
	}
	req := sandbox.ConsumerCertStageRequest{
		Op:               sandbox.HelperOpConsumerCertStage,
		PluginID:         binding.Consumer.PluginID,
		Binding:          toSandboxBinding(binding),
		FullchainBase64:  base64.StdEncoding.EncodeToString(chain),
		PrivateKeyBase64: base64.StdEncoding.EncodeToString(key),
	}
	rawProof, err := b.Client.StageConsumerCert(ctx, req)
	if err != nil {
		return consumerfiles.Proof{}, mapHelperError(err)
	}
	proof := *fromSandboxProof(&rawProof)
	if proof.Binding != binding {
		return consumerfiles.Proof{}, fault.New("CONSUMER_FILES_CONFLICT", "特权助手返回的暂存证明与请求绑定不符")
	}
	return proof, nil
}

// Activate 请求特权助手执行 CAS 激活；发生不确定失败时同时保留回传的 Previous 证明与 Uncertain 标记。
func (b *HelperFileBackend) Activate(ctx context.Context, pluginID string, expected *consumerfiles.Proof, wanted consumerfiles.Proof) (*consumerfiles.Proof, error) {
	if b == nil || b.Client == nil {
		return nil, fault.New("BACKEND_REQUIRED", "消费者证书特权助手客户端未配置")
	}
	req := sandbox.ConsumerCertActivateRequest{
		Op:       sandbox.HelperOpConsumerCertActivate,
		PluginID: pluginID,
		Expected: toSandboxProof(expected),
		Wanted:   *toSandboxProof(&wanted),
	}
	prev, err := b.Client.ActivateConsumerCert(ctx, req)
	prevProof := fromSandboxProof(prev)
	if err != nil {
		return prevProof, mapHelperError(err)
	}
	return prevProof, nil
}

// Current 查询指定插件与绑定在磁盘上当前生效的消费者证书证明。
func (b *HelperFileBackend) Current(ctx context.Context, pluginID, bindingID string) (*consumerfiles.Proof, error) {
	if b == nil || b.Client == nil {
		return nil, fault.New("BACKEND_REQUIRED", "消费者证书特权助手客户端未配置")
	}
	cur, err := b.Client.CurrentConsumerCert(ctx, pluginID, bindingID)
	if err != nil {
		return nil, mapHelperError(err)
	}
	return fromSandboxProof(cur), nil
}

// Remove 请求特权助手幂等清理指定插件与绑定的消费者证书状态。
func (b *HelperFileBackend) Remove(ctx context.Context, pluginID, bindingID string) (bool, error) {
	if b == nil || b.Client == nil {
		return false, fault.New("BACKEND_REQUIRED", "消费者证书特权助手客户端未配置")
	}
	removed, err := b.Client.RemoveConsumerCert(ctx, pluginID, bindingID)
	if err != nil {
		return false, mapHelperError(err)
	}
	return removed, nil
}

func mapHelperError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(fault.New("CANCELLED", "消费者证书文件操作已取消"), err)
	}
	var ce *sandbox.ConsumerCertError
	if errors.As(err, &ce) {
		code := ce.Code
		if code == "" {
			code = "INTERNAL"
		}
		failure := fault.New(code, "特权助手拒绝或未能确认消费者证书文件操作")
		failure.Uncertain = ce.Uncertain
		return failure
	}
	return fault.New("CONSUMER_FILES_IO", "消费者证书特权通道调用失败")
}

// ======================== 直连文件后端：测试与直开 FD 场景复用 consumerfiles.Store ========================

// DirectFileBackend 直接打开插件对应的 consumerfiles.Store，适用于无需 root Unix socket 的测试与直连 FD 场景。
type DirectFileBackend struct {
	Open func(pluginID string) (*consumerfiles.Store, func(), error)
}

var _ FileBackend = (*DirectFileBackend)(nil)

func (b *DirectFileBackend) openStore(pluginID string) (*consumerfiles.Store, func(), error) {
	if b == nil || b.Open == nil {
		return nil, nil, fault.New("BACKEND_REQUIRED", "消费者证书直连存储后端未配置")
	}
	store, release, err := b.Open(pluginID)
	if err != nil {
		if release != nil {
			release()
		}
		return nil, nil, err
	}
	if store == nil {
		if release != nil {
			release()
		}
		return nil, nil, fault.New("BACKEND_REQUIRED", "消费者证书直连存储未就绪")
	}
	return store, release, nil
}

// Stage 直接调用目标插件的 consumerfiles.Store 暂存证书材料。
func (b *DirectFileBackend) Stage(ctx context.Context, binding certificates.HostBinding, material tlsmgr.Material) (consumerfiles.Proof, error) {
	store, release, err := b.openStore(binding.Consumer.PluginID)
	if err != nil {
		return consumerfiles.Proof{}, err
	}
	if release != nil {
		defer release()
	}
	return store.Stage(ctx, binding, material)
}

// Activate 直接调用目标插件的 consumerfiles.Store 执行 CAS 激活。
func (b *DirectFileBackend) Activate(ctx context.Context, pluginID string, expected *consumerfiles.Proof, wanted consumerfiles.Proof) (*consumerfiles.Proof, error) {
	store, release, err := b.openStore(pluginID)
	if err != nil {
		return nil, err
	}
	if release != nil {
		defer release()
	}
	return store.Activate(ctx, expected, wanted)
}

// Current 直接读取目标插件的 consumerfiles.Store 当前生效证明。
func (b *DirectFileBackend) Current(ctx context.Context, pluginID, bindingID string) (*consumerfiles.Proof, error) {
	store, release, err := b.openStore(pluginID)
	if err != nil {
		return nil, err
	}
	if release != nil {
		defer release()
	}
	return store.Current(ctx, bindingID)
}

// Remove 直接调用目标插件的 consumerfiles.Store 清理绑定目录与状态。
func (b *DirectFileBackend) Remove(ctx context.Context, pluginID, bindingID string) (bool, error) {
	store, release, err := b.openStore(pluginID)
	if err != nil {
		return false, err
	}
	if release != nil {
		defer release()
	}
	if err := store.Remove(ctx, bindingID); err != nil {
		return false, err
	}
	return true, nil
}

// ======================== 协议结构转换 ========================

func toSandboxBinding(binding certificates.HostBinding) sandbox.ConsumerCertBinding {
	return sandbox.ConsumerCertBinding{
		ID:            binding.ID,
		CertificateID: binding.CertificateID,
		Generation:    binding.Generation,
		Consumer: sandbox.ConsumerCertConsumer{
			PluginID:  binding.Consumer.PluginID,
			ProfileID: binding.Consumer.ProfileID,
			NodeID:    binding.Consumer.NodeID,
			SNI:       binding.Consumer.SNI,
			Purpose:   binding.Consumer.Purpose,
			Test:      binding.Consumer.Test,
		},
		PolicyRevision: binding.PolicyRevision,
	}
}

func fromSandboxBinding(binding sandbox.ConsumerCertBinding) certificates.HostBinding {
	return certificates.HostBinding{
		ID:            binding.ID,
		CertificateID: binding.CertificateID,
		Generation:    binding.Generation,
		Consumer: certificates.Consumer{
			PluginID:  binding.Consumer.PluginID,
			ProfileID: binding.Consumer.ProfileID,
			NodeID:    binding.Consumer.NodeID,
			SNI:       binding.Consumer.SNI,
			Purpose:   binding.Consumer.Purpose,
			Test:      binding.Consumer.Test,
		},
		PolicyRevision: binding.PolicyRevision,
	}
}

func toSandboxProof(proof *consumerfiles.Proof) *sandbox.ConsumerCertProof {
	if proof == nil {
		return nil
	}
	return &sandbox.ConsumerCertProof{
		Binding:          toSandboxBinding(proof.Binding),
		FullchainSHA256:  proof.FullchainSHA256,
		PrivateKeySHA256: proof.PrivateKeySHA256,
	}
}

func fromSandboxProof(proof *sandbox.ConsumerCertProof) *consumerfiles.Proof {
	if proof == nil {
		return nil
	}
	return &consumerfiles.Proof{
		Binding:          fromSandboxBinding(proof.Binding),
		FullchainSHA256:  proof.FullchainSHA256,
		PrivateKeySHA256: proof.PrivateKeySHA256,
	}
}
