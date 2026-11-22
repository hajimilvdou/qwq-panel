// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import "context"

// ======================== 消费者证书 helper 客户端：强制 root peer 与绑定一致性校验 ========================

// ConsumerCertError 表示 root helper 拒绝消费者证书操作，并保留 Uncertain 以便调用方对账。
type ConsumerCertError struct {
	Code      string
	Detail    string
	Uncertain bool
}

// Error 返回不泄露材料原文的业务错误摘要。
func (e *ConsumerCertError) Error() string {
	if e == nil {
		return "sandbox: consumer certificate helper error"
	}
	detail := e.Detail
	if detail == "" {
		detail = "The privileged helper refused the consumer certificate request."
	}
	if e.Code == "" {
		return detail
	}
	return e.Code + ": " + detail
}

func consumerCertRemoteError(status ConsumerCertResponseStatus) error {
	return &ConsumerCertError{
		Code:      status.Code,
		Detail:    status.Error,
		Uncertain: status.Uncertain,
	}
}

// StageConsumerCert 通过 root helper 暂存消费者证书，并确认返回证明与请求绑定完全一致。
func (client *HelperClient) StageConsumerCert(ctx context.Context, req ConsumerCertStageRequest) (ConsumerCertProof, error) {
	req.Op = HelperOpConsumerCertStage
	if err := req.Validate(); err != nil {
		return ConsumerCertProof{}, err
	}
	var resp ConsumerCertStageResponse
	if err := client.exchangeChecked(ctx, req, &resp, checkGenerationRootPeer); err != nil {
		return ConsumerCertProof{}, err
	}
	if !resp.OK {
		return ConsumerCertProof{}, consumerCertRemoteError(resp.ConsumerCertResponseStatus)
	}
	if resp.Proof == nil || resp.Proof.Validate() != nil || resp.Proof.Binding != req.Binding {
		return ConsumerCertProof{}, ErrConsumerCertDocument
	}
	return *resp.Proof, nil
}

// ActivateConsumerCert 请求 CAS 激活目标证明；即使失败且 Uncertain，也会把回传的 Previous 一并返回以便对账。
func (client *HelperClient) ActivateConsumerCert(ctx context.Context, req ConsumerCertActivateRequest) (*ConsumerCertProof, error) {
	req.Op = HelperOpConsumerCertActivate
	if err := req.Validate(); err != nil {
		return nil, err
	}
	var resp ConsumerCertActivateResponse
	if err := client.exchangeChecked(ctx, req, &resp, checkGenerationRootPeer); err != nil {
		return nil, err
	}
	if resp.Previous != nil {
		if resp.Previous.Validate() != nil ||
			resp.Previous.Binding.ID != req.Wanted.Binding.ID ||
			resp.Previous.Binding.Consumer.PluginID != req.PluginID {
			return nil, ErrConsumerCertDocument
		}
	}
	if !resp.OK {
		return resp.Previous, consumerCertRemoteError(resp.ConsumerCertResponseStatus)
	}
	return resp.Previous, nil
}

// CurrentConsumerCert 读取指定插件与绑定当前的生效证明；尚无记录时返回 nil, nil。
func (client *HelperClient) CurrentConsumerCert(ctx context.Context, pluginID, bindingID string) (*ConsumerCertProof, error) {
	req := ConsumerCertCurrentRequest{
		Op:        HelperOpConsumerCertCurrent,
		PluginID:  pluginID,
		BindingID: bindingID,
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	var resp ConsumerCertCurrentResponse
	if err := client.exchangeChecked(ctx, req, &resp, checkGenerationRootPeer); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, consumerCertRemoteError(resp.ConsumerCertResponseStatus)
	}
	if resp.Current != nil {
		if resp.Current.Validate() != nil ||
			resp.Current.Binding.ID != bindingID ||
			resp.Current.Binding.Consumer.PluginID != pluginID {
			return nil, ErrConsumerCertDocument
		}
	}
	return resp.Current, nil
}

// RemoveConsumerCert 请求 root helper 清理指定插件与绑定的消费者证书状态。
func (client *HelperClient) RemoveConsumerCert(ctx context.Context, pluginID, bindingID string) (bool, error) {
	req := ConsumerCertRemoveRequest{
		Op:        HelperOpConsumerCertRemove,
		PluginID:  pluginID,
		BindingID: bindingID,
	}
	if err := req.Validate(); err != nil {
		return false, err
	}
	var resp ConsumerCertRemoveResponse
	if err := client.exchangeChecked(ctx, req, &resp, checkGenerationRootPeer); err != nil {
		return false, err
	}
	if !resp.OK {
		return false, consumerCertRemoteError(resp.ConsumerCertResponseStatus)
	}
	return resp.Removed, nil
}
