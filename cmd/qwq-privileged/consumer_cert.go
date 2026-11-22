// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"syscall"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/consumerfiles"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

const consumerStateProfileDir = "default"

// ======================== 受限插件 StateDirectory FD 固定 ========================

// openConsumerStateRoot 按可信祖先链打开 <PrivateDataRoot>/<pluginID>/default。
// 绝不创建或改写目录属主与权限，也绝不按 ProfileID 推导物理目录路径。
func (s *helperServer) openConsumerStateRoot(pluginID string) (*os.Root, error) {
	if err := sandbox.ValidateID(pluginID); err != nil {
		return nil, fault.New("CONSUMER_FILES_INVALID", "插件 ID 无效")
	}
	if s.cfg.Trust.UID < 0 {
		return nil, fault.New("CONSUMER_FILES_UNSAFE", "可信目录属主策略无效")
	}
	privateRoot, err := s.cfg.Trust.Open(s.cfg.PrivateDataRoot)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fault.New("NOT_FOUND", "插件状态目录根不存在")
	}
	if err != nil {
		return nil, fault.New("CONSUMER_FILES_UNSAFE", "插件状态目录根未通过可信校验")
	}
	defer func() { _ = privateRoot.Close() }()

	privateStat, err := privateRoot.Stat(".")
	if err != nil {
		return nil, fault.New("CONSUMER_FILES_UNSAFE", "无法核验插件状态目录根")
	}
	privateRaw, ok := statUnix(privateStat)
	if !ok || privateRaw.Nlink == 0 {
		return nil, fault.New("CONSUMER_FILES_UNSAFE", "插件状态目录根元数据无效")
	}

	pluginInfo, err := privateRoot.Lstat(pluginID)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fault.New("NOT_FOUND", "插件状态目录不存在")
	}
	if err != nil {
		return nil, fault.New("CONSUMER_FILES_UNSAFE", "无法检查插件状态目录")
	}
	if !isSafePluginParentDir(pluginInfo) {
		return nil, fault.New("CONSUMER_FILES_UNSAFE", "插件状态目录不是安全的真实目录")
	}
	pluginRoot, err := privateRoot.OpenRoot(pluginID)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fault.New("NOT_FOUND", "插件状态目录不存在")
	}
	if err != nil {
		return nil, fault.New("CONSUMER_FILES_UNSAFE", "无法安全打开插件状态目录")
	}
	defer func() { _ = pluginRoot.Close() }()

	pluginStat, err := pluginRoot.Stat(".")
	if err != nil || !os.SameFile(pluginInfo, pluginStat) || !isSafePluginParentDir(pluginStat) {
		return nil, fault.New("CONSUMER_FILES_UNSAFE", "插件状态目录在打开期间变化或权限不安全")
	}
	pluginRaw, ok := statUnix(pluginStat)
	if !ok || pluginRaw.Nlink == 0 || pluginRaw.Dev != privateRaw.Dev {
		return nil, fault.New("CONSUMER_FILES_UNSAFE", "插件状态目录设备或链接无效")
	}

	// 只固定字面量 "default"，绝不按 ProfileID 推导或拼接目录路径。
	defaultInfo, err := pluginRoot.Lstat(consumerStateProfileDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fault.New("NOT_FOUND", "插件 default 状态目录不存在")
	}
	if err != nil {
		return nil, fault.New("CONSUMER_FILES_UNSAFE", "无法检查插件 default 状态目录")
	}
	if !isExactPrivateDir(defaultInfo) {
		return nil, fault.New("CONSUMER_FILES_UNSAFE", "插件 default 状态目录必须是 0700 真实目录")
	}
	defaultRoot, err := pluginRoot.OpenRoot(consumerStateProfileDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fault.New("NOT_FOUND", "插件 default 状态目录不存在")
	}
	if err != nil {
		return nil, fault.New("CONSUMER_FILES_UNSAFE", "无法安全打开插件 default 状态目录")
	}

	defaultStat, err := defaultRoot.Stat(".")
	if err != nil || !os.SameFile(defaultInfo, defaultStat) || !isExactPrivateDir(defaultStat) {
		_ = defaultRoot.Close()
		return nil, fault.New("CONSUMER_FILES_UNSAFE", "插件 default 状态目录在打开期间变化或权限不符")
	}
	defaultRaw, ok := statUnix(defaultStat)
	if !ok || defaultRaw.Nlink == 0 || defaultRaw.Dev != pluginRaw.Dev || defaultRaw.Mode&0o7777 != 0o700 {
		_ = defaultRoot.Close()
		return nil, fault.New("CONSUMER_FILES_UNSAFE", "插件 default 状态目录设备、权限或链接无效")
	}

	trustUID := uint32(s.cfg.Trust.UID)
	if pluginRaw.Uid != trustUID && pluginRaw.Uid != defaultRaw.Uid {
		_ = defaultRoot.Close()
		return nil, fault.New("CONSUMER_FILES_UNSAFE", "插件状态目录属主与可信根或 default 属主不符")
	}

	if s.cfg.Trust.UID == 0 && os.Geteuid() == 0 {
		if defaultRaw.Uid == 0 || defaultRaw.Gid == 0 {
			_ = defaultRoot.Close()
			return nil, fault.New("CONSUMER_FILES_UNSAFE", "生产插件 default 状态目录不得由 root 持有")
		}
		if s.lookupUID != nil {
			if agentUID, lookupErr := s.lookupUID(s.cfg.AgentUser); lookupErr == nil && agentUID >= 0 && defaultRaw.Uid == uint32(agentUID) {
				_ = defaultRoot.Close()
				return nil, fault.New("CONSUMER_FILES_UNSAFE", "生产插件 default 状态目录不得由控制面用户持有")
			}
		}
	}

	return defaultRoot, nil
}

func statUnix(info fs.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	raw, ok := info.Sys().(*syscall.Stat_t)
	return raw, ok && raw != nil
}

func isSafePluginParentDir(info fs.FileInfo) bool {
	if info == nil {
		return false
	}
	mode := info.Mode()
	return mode.IsDir() && mode&fs.ModeSymlink == 0 && mode.Perm()&0o022 == 0
}

func isExactPrivateDir(info fs.FileInfo) bool {
	if info == nil {
		return false
	}
	mode := info.Mode()
	return mode.IsDir() &&
		mode&fs.ModeSymlink == 0 &&
		mode.Perm() == 0o700 &&
		mode&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) == 0
}

// ======================== 消费者证书特权请求分发与脱敏错误 ========================

func (s *helperServer) handleConsumerCert(ctx context.Context, req sandbox.DecodedHelperRequest) (response any) {
	started := time.Now()
	uid := os.Geteuid()
	defer func() {
		if recover() != nil {
			status := sandbox.ConsumerCertResponseStatus{
				OK:    false,
				UID:   uid,
				Code:  "INTERNAL",
				Error: safeConsumerCertError("INTERNAL"),
			}
			response = consumerCertFailureResponse(req, status, nil)
			if s.logger != nil {
				s.logger.Error("privileged consumer-cert request panicked", "op", consumerCertOpName(req))
			}
		}
		if s.logger != nil {
			s.logger.Info("privileged consumer-cert request",
				"op", consumerCertOpName(req),
				"plugin_id", safeLogPluginID(consumerCertPluginID(req)),
				"ok", consumerCertResponseOK(response),
				"duration", time.Since(started).Round(time.Millisecond))
		}
	}()
	if ctx == nil || ctx.Err() != nil {
		return consumerCertErrorResponse(req, uid, fault.New("CANCELLED", "消费者证书请求已取消"), nil)
	}
	switch {
	case req.ConsumerStage != nil:
		return s.handleConsumerCertStage(ctx, uid, *req.ConsumerStage)
	case req.ConsumerActivate != nil:
		return s.handleConsumerCertActivate(ctx, uid, *req.ConsumerActivate)
	case req.ConsumerCurrent != nil:
		return s.handleConsumerCertCurrent(ctx, uid, *req.ConsumerCurrent)
	case req.ConsumerRemove != nil:
		return s.handleConsumerCertRemove(ctx, uid, *req.ConsumerRemove)
	default:
		return consumerCertErrorResponse(req, uid, fault.New("INTERNAL", "未知的消费者证书操作"), nil)
	}
}

func (s *helperServer) handleConsumerCertStage(ctx context.Context, uid int, req sandbox.ConsumerCertStageRequest) sandbox.ConsumerCertStageResponse {
	if err := req.Validate(); err != nil || req.Binding.Consumer.PluginID != req.PluginID {
		return sandbox.ConsumerCertStageResponse{
			ConsumerCertResponseStatus: consumerCertStatusFromError(uid, fault.New("CONSUMER_FILES_INVALID", "消费者证书暂存请求无效")),
		}
	}
	if req.FullchainBase64 == "" || len(req.FullchainBase64) > base64.StdEncoding.EncodedLen(tlsmgr.MaxCertificatePEM) {
		return sandbox.ConsumerCertStageResponse{
			ConsumerCertResponseStatus: consumerCertStatusFromError(uid, fault.New("CERTIFICATE_INVALID", "证书链长度无效")),
		}
	}
	if req.PrivateKeyBase64 == "" || len(req.PrivateKeyBase64) > base64.StdEncoding.EncodedLen(tlsmgr.MaxPrivateKeyPEM) {
		return sandbox.ConsumerCertStageResponse{
			ConsumerCertResponseStatus: consumerCertStatusFromError(uid, fault.New("PRIVATE_KEY_INVALID", "私钥长度无效")),
		}
	}
	chain, err := base64.StdEncoding.DecodeString(req.FullchainBase64)
	defer clear(chain)
	if err != nil || len(chain) == 0 || len(chain) > tlsmgr.MaxCertificatePEM {
		return sandbox.ConsumerCertStageResponse{
			ConsumerCertResponseStatus: consumerCertStatusFromError(uid, fault.New("CERTIFICATE_INVALID", "证书链解码失败或超限")),
		}
	}
	key, err := base64.StdEncoding.DecodeString(req.PrivateKeyBase64)
	defer clear(key)
	if err != nil || len(key) == 0 || len(key) > tlsmgr.MaxPrivateKeyPEM {
		return sandbox.ConsumerCertStageResponse{
			ConsumerCertResponseStatus: consumerCertStatusFromError(uid, fault.New("PRIVATE_KEY_INVALID", "私钥解码失败或超限")),
		}
	}
	material, err := tlsmgr.NewMaterial(chain, key)
	if err != nil {
		return sandbox.ConsumerCertStageResponse{
			ConsumerCertResponseStatus: consumerCertStatusFromError(uid, err),
		}
	}
	defer material.Clear()

	defaultRoot, err := s.openConsumerStateRoot(req.PluginID)
	if err != nil {
		return sandbox.ConsumerCertStageResponse{
			ConsumerCertResponseStatus: consumerCertStatusFromError(uid, err),
		}
	}
	defer func() { _ = defaultRoot.Close() }()

	store, err := consumerfiles.New(defaultRoot)
	if err != nil {
		return sandbox.ConsumerCertStageResponse{
			ConsumerCertResponseStatus: consumerCertStatusFromError(uid, err),
		}
	}
	defer func() { _ = store.Close() }()

	proof, err := store.Stage(ctx, toHostBinding(req.Binding), material)
	if err != nil {
		return sandbox.ConsumerCertStageResponse{
			ConsumerCertResponseStatus: consumerCertStatusFromError(uid, err),
		}
	}
	return sandbox.ConsumerCertStageResponse{
		ConsumerCertResponseStatus: sandbox.ConsumerCertResponseStatus{OK: true, UID: uid},
		Proof:                      fromConsumerProof(&proof),
	}
}

func (s *helperServer) handleConsumerCertActivate(ctx context.Context, uid int, req sandbox.ConsumerCertActivateRequest) sandbox.ConsumerCertActivateResponse {
	if err := req.Validate(); err != nil || req.Wanted.Binding.Consumer.PluginID != req.PluginID {
		return sandbox.ConsumerCertActivateResponse{
			ConsumerCertResponseStatus: consumerCertStatusFromError(uid, fault.New("CONSUMER_FILES_INVALID", "消费者证书激活请求无效")),
		}
	}
	var expected *consumerfiles.Proof
	if req.Expected != nil {
		if req.Expected.Binding.Consumer.PluginID != req.PluginID {
			return sandbox.ConsumerCertActivateResponse{
				ConsumerCertResponseStatus: consumerCertStatusFromError(uid, fault.New("CONSUMER_FILES_INVALID", "消费者证书 CAS 前代与目标插件不符")),
			}
		}
		exp := toConsumerProof(*req.Expected)
		expected = &exp
	}
	wanted := toConsumerProof(req.Wanted)

	defaultRoot, err := s.openConsumerStateRoot(req.PluginID)
	if err != nil {
		return sandbox.ConsumerCertActivateResponse{
			ConsumerCertResponseStatus: consumerCertStatusFromError(uid, err),
		}
	}
	defer func() { _ = defaultRoot.Close() }()

	store, err := consumerfiles.New(defaultRoot)
	if err != nil {
		return sandbox.ConsumerCertActivateResponse{
			ConsumerCertResponseStatus: consumerCertStatusFromError(uid, err),
		}
	}
	defer func() { _ = store.Close() }()

	prev, err := store.Activate(ctx, expected, wanted)
	if err != nil {
		var prevOut *sandbox.ConsumerCertProof
		var fe *fault.Error
		if errors.As(err, &fe) && fe.Uncertain && prev != nil {
			prevOut = fromConsumerProof(prev)
		}
		return sandbox.ConsumerCertActivateResponse{
			ConsumerCertResponseStatus: consumerCertStatusFromError(uid, err),
			Previous:                   prevOut,
		}
	}
	return sandbox.ConsumerCertActivateResponse{
		ConsumerCertResponseStatus: sandbox.ConsumerCertResponseStatus{OK: true, UID: uid},
		Previous:                   fromConsumerProof(prev),
	}
}

func (s *helperServer) handleConsumerCertCurrent(ctx context.Context, uid int, req sandbox.ConsumerCertCurrentRequest) sandbox.ConsumerCertCurrentResponse {
	if err := req.Validate(); err != nil {
		return sandbox.ConsumerCertCurrentResponse{
			ConsumerCertResponseStatus: consumerCertStatusFromError(uid, fault.New("CONSUMER_FILES_INVALID", "消费者证书查询请求无效")),
		}
	}
	defaultRoot, err := s.openConsumerStateRoot(req.PluginID)
	if err != nil {
		return sandbox.ConsumerCertCurrentResponse{
			ConsumerCertResponseStatus: consumerCertStatusFromError(uid, err),
		}
	}
	defer func() { _ = defaultRoot.Close() }()

	store, err := consumerfiles.New(defaultRoot)
	if err != nil {
		return sandbox.ConsumerCertCurrentResponse{
			ConsumerCertResponseStatus: consumerCertStatusFromError(uid, err),
		}
	}
	defer func() { _ = store.Close() }()

	current, err := store.Current(ctx, req.BindingID)
	if err != nil {
		return sandbox.ConsumerCertCurrentResponse{
			ConsumerCertResponseStatus: consumerCertStatusFromError(uid, err),
		}
	}
	return sandbox.ConsumerCertCurrentResponse{
		ConsumerCertResponseStatus: sandbox.ConsumerCertResponseStatus{OK: true, UID: uid},
		Current:                    fromConsumerProof(current),
	}
}

func (s *helperServer) handleConsumerCertRemove(ctx context.Context, uid int, req sandbox.ConsumerCertRemoveRequest) sandbox.ConsumerCertRemoveResponse {
	if err := req.Validate(); err != nil {
		return sandbox.ConsumerCertRemoveResponse{
			ConsumerCertResponseStatus: consumerCertStatusFromError(uid, fault.New("CONSUMER_FILES_INVALID", "消费者证书删除请求无效")),
		}
	}
	defaultRoot, err := s.openConsumerStateRoot(req.PluginID)
	if err != nil {
		if fault.Code(err) == "NOT_FOUND" {
			return sandbox.ConsumerCertRemoveResponse{
				ConsumerCertResponseStatus: sandbox.ConsumerCertResponseStatus{OK: true, UID: uid},
				Removed:                    false,
			}
		}
		return sandbox.ConsumerCertRemoveResponse{
			ConsumerCertResponseStatus: consumerCertStatusFromError(uid, err),
		}
	}
	defer func() { _ = defaultRoot.Close() }()

	store, err := consumerfiles.New(defaultRoot)
	if err != nil {
		return sandbox.ConsumerCertRemoveResponse{
			ConsumerCertResponseStatus: consumerCertStatusFromError(uid, err),
		}
	}
	defer func() { _ = store.Close() }()

	if err := store.Remove(ctx, req.BindingID); err != nil {
		return sandbox.ConsumerCertRemoveResponse{
			ConsumerCertResponseStatus: consumerCertStatusFromError(uid, err),
		}
	}
	return sandbox.ConsumerCertRemoveResponse{
		ConsumerCertResponseStatus: sandbox.ConsumerCertResponseStatus{OK: true, UID: uid},
		Removed:                    true,
	}
}

// ======================== 类型转换与静态脱敏错误映射 ========================

func toHostBinding(b sandbox.ConsumerCertBinding) certificates.HostBinding {
	return certificates.HostBinding{
		ID:            b.ID,
		CertificateID: b.CertificateID,
		Generation:    b.Generation,
		Consumer: certificates.Consumer{
			PluginID:  b.Consumer.PluginID,
			ProfileID: b.Consumer.ProfileID,
			NodeID:    b.Consumer.NodeID,
			SNI:       b.Consumer.SNI,
			Purpose:   b.Consumer.Purpose,
			Test:      b.Consumer.Test,
		},
		PolicyRevision: b.PolicyRevision,
	}
}

func fromHostBinding(b certificates.HostBinding) sandbox.ConsumerCertBinding {
	return sandbox.ConsumerCertBinding{
		ID:            b.ID,
		CertificateID: b.CertificateID,
		Generation:    b.Generation,
		Consumer: sandbox.ConsumerCertConsumer{
			PluginID:  b.Consumer.PluginID,
			ProfileID: b.Consumer.ProfileID,
			NodeID:    b.Consumer.NodeID,
			SNI:       b.Consumer.SNI,
			Purpose:   b.Consumer.Purpose,
			Test:      b.Consumer.Test,
		},
		PolicyRevision: b.PolicyRevision,
	}
}

func toConsumerProof(p sandbox.ConsumerCertProof) consumerfiles.Proof {
	return consumerfiles.Proof{
		Binding:          toHostBinding(p.Binding),
		FullchainSHA256:  p.FullchainSHA256,
		PrivateKeySHA256: p.PrivateKeySHA256,
	}
}

func fromConsumerProof(p *consumerfiles.Proof) *sandbox.ConsumerCertProof {
	if p == nil {
		return nil
	}
	return &sandbox.ConsumerCertProof{
		Binding:          fromHostBinding(p.Binding),
		FullchainSHA256:  p.FullchainSHA256,
		PrivateKeySHA256: p.PrivateKeySHA256,
	}
}

func consumerCertStatusFromError(uid int, err error) sandbox.ConsumerCertResponseStatus {
	code := fault.Code(err)
	if code == "" {
		code = "INTERNAL"
	}
	uncertain := false
	var fe *fault.Error
	if errors.As(err, &fe) {
		uncertain = fe.Uncertain
	}
	return sandbox.ConsumerCertResponseStatus{
		OK:        false,
		UID:       uid,
		Code:      code,
		Error:     safeConsumerCertError(code),
		Uncertain: uncertain,
	}
}

func safeConsumerCertError(code string) string {
	switch code {
	case "NOT_FOUND":
		return "The requested consumer certificate state or material was not found."
	case "CONSUMER_FILES_INVALID", "CONSUMER_INVALID":
		return "The consumer certificate request or stored metadata is invalid."
	case "CONSUMER_FILES_UNSAFE":
		return "The consumer certificate state directory failed safety verification."
	case "CONSUMER_FILES_CONFLICT":
		return "The consumer certificate state conflicted with the expected proof."
	case "CONSUMER_FILES_IO":
		return "The consumer certificate file operation failed."
	case "CONSUMER_FILES_CLOSED":
		return "The consumer certificate file store is closed."
	case "CERTIFICATE_INVALID":
		return "The consumer certificate PEM is invalid."
	case "PRIVATE_KEY_INVALID":
		return "The consumer private key PEM is invalid."
	case "PRIVATE_KEY_MISMATCH":
		return "The consumer certificate and private key do not match."
	case "SAN_MISMATCH":
		return "The consumer certificate does not cover the requested SNI."
	case "CANCELLED":
		return "The consumer certificate request was cancelled."
	case "BACKEND_REQUIRED":
		return "The consumer certificate backend is unavailable on this host."
	default:
		return "The privileged helper could not complete the consumer certificate operation."
	}
}

func consumerCertErrorResponse(req sandbox.DecodedHelperRequest, uid int, err error, previous *sandbox.ConsumerCertProof) any {
	return consumerCertFailureResponse(req, consumerCertStatusFromError(uid, err), previous)
}

func consumerCertFailureResponse(req sandbox.DecodedHelperRequest, status sandbox.ConsumerCertResponseStatus, previous *sandbox.ConsumerCertProof) any {
	switch {
	case req.ConsumerStage != nil:
		return sandbox.ConsumerCertStageResponse{ConsumerCertResponseStatus: status}
	case req.ConsumerActivate != nil:
		return sandbox.ConsumerCertActivateResponse{ConsumerCertResponseStatus: status, Previous: previous}
	case req.ConsumerRemove != nil:
		return sandbox.ConsumerCertRemoveResponse{ConsumerCertResponseStatus: status}
	default:
		return sandbox.ConsumerCertCurrentResponse{ConsumerCertResponseStatus: status}
	}
}

func consumerCertOpName(req sandbox.DecodedHelperRequest) string {
	switch {
	case req.ConsumerStage != nil:
		return "consumer-cert-stage"
	case req.ConsumerActivate != nil:
		return "consumer-cert-activate"
	case req.ConsumerCurrent != nil:
		return "consumer-cert-current"
	case req.ConsumerRemove != nil:
		return "consumer-cert-remove"
	default:
		return "consumer-cert-unknown"
	}
}

func consumerCertPluginID(req sandbox.DecodedHelperRequest) string {
	switch {
	case req.ConsumerStage != nil:
		return req.ConsumerStage.PluginID
	case req.ConsumerActivate != nil:
		return req.ConsumerActivate.PluginID
	case req.ConsumerCurrent != nil:
		return req.ConsumerCurrent.PluginID
	case req.ConsumerRemove != nil:
		return req.ConsumerRemove.PluginID
	default:
		return ""
	}
}

func safeLogPluginID(id string) string {
	if sandbox.ValidateID(id) != nil {
		return ""
	}
	return id
}

func consumerCertResponseOK(resp any) bool {
	switch typed := resp.(type) {
	case sandbox.ConsumerCertStageResponse:
		return typed.OK
	case sandbox.ConsumerCertActivateResponse:
		return typed.OK
	case sandbox.ConsumerCertCurrentResponse:
		return typed.OK
	case sandbox.ConsumerCertRemoveResponse:
		return typed.OK
	default:
		return false
	}
}
