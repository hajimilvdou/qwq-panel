// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/apply"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ======================== 宿主驱动的 TLS 绑定热重载与观测 ========================

func decodeTLSReloadInput(payload []byte) (apply.TLSReloadRequest, error) {
	invalid := pluginsdk.Errorf("INVALID_REQUEST", "TLS 热重载请求字段无效")
	if len(payload) == 0 || len(payload) > 4096 {
		return apply.TLSReloadRequest{}, invalid
	}
	var fields map[string]json.RawMessage
	if sandbox.DecodeHelperDocument(payload, &fields) != nil || len(fields) != 7 {
		return apply.TLSReloadRequest{}, invalid
	}
	var req apply.TLSReloadRequest
	for name, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return apply.TLSReloadRequest{}, invalid
		}
		switch name {
		case "binding_ref":
			if json.Unmarshal(value, &req.BindingRef) != nil || req.BindingRef == "" {
				return apply.TLSReloadRequest{}, invalid
			}
		case "profile_id":
			if json.Unmarshal(value, &req.ProfileID) != nil || req.ProfileID == "" {
				return apply.TLSReloadRequest{}, invalid
			}
		case "generation":
			if json.Unmarshal(value, &req.Generation) != nil || req.Generation == 0 {
				return apply.TLSReloadRequest{}, invalid
			}
		case "policy_revision":
			if json.Unmarshal(value, &req.PolicyRevision) != nil || req.PolicyRevision == "" {
				return apply.TLSReloadRequest{}, invalid
			}
		case "fullchain_sha256":
			if json.Unmarshal(value, &req.FullchainSHA256) != nil || len(req.FullchainSHA256) != 64 {
				return apply.TLSReloadRequest{}, invalid
			}
		case "private_key_sha256":
			if json.Unmarshal(value, &req.PrivateKeySHA256) != nil || len(req.PrivateKeySHA256) != 64 {
				return apply.TLSReloadRequest{}, invalid
			}
		case "sni":
			if json.Unmarshal(value, &req.SNI) != nil || req.SNI == "" {
				return apply.TLSReloadRequest{}, invalid
			}
		default:
			return apply.TLSReloadRequest{}, invalid
		}
	}
	return req, nil
}

func decodeTLSInspectInput(payload []byte) (bindingRef, profileID string, err error) {
	invalid := pluginsdk.Errorf("INVALID_REQUEST", "TLS 状态查询请求字段无效")
	if len(payload) == 0 || len(payload) > 1024 {
		return "", "", invalid
	}
	var fields map[string]json.RawMessage
	if sandbox.DecodeHelperDocument(payload, &fields) != nil || len(fields) != 2 {
		return "", "", invalid
	}
	for name, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return "", "", invalid
		}
		switch name {
		case "binding_ref":
			if json.Unmarshal(value, &bindingRef) != nil || bindingRef == "" {
				return "", "", invalid
			}
		case "profile_id":
			if json.Unmarshal(value, &profileID) != nil || profileID == "" {
				return "", "", invalid
			}
		default:
			return "", "", invalid
		}
	}
	return bindingRef, profileID, nil
}

func (i *instance) tlsReload(ctx context.Context, request pluginsdk.Request) (pluginsdk.Response, error) {
	req, err := decodeTLSReloadInput(request.Payload)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	if i.driver == nil {
		return pluginsdk.Response{}, skeletonError()
	}
	status, err := i.driver.controller.ReloadTLS(ctx, req)
	if err != nil {
		return pluginsdk.Response{}, mapApplyError(err)
	}
	return readResponse(status)
}

func (i *instance) tlsInspect(ctx context.Context, request pluginsdk.Request) (pluginsdk.Response, error) {
	bindingRef, profileID, err := decodeTLSInspectInput(request.Payload)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	if i.driver == nil {
		return readResponse(apply.TLSBindingStatus{BindingRef: bindingRef})
	}
	status, err := i.driver.controller.InspectTLS(ctx, bindingRef, profileID)
	if err != nil {
		return pluginsdk.Response{}, mapApplyError(err)
	}
	return readResponse(status)
}
