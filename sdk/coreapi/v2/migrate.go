// SPDX-License-Identifier: Apache-2.0

package coreapi

import (
	"slices"

	v1 "github.com/qwq-panel/qwq/sdk/coreapi"
)

// FromV1 显式生成一个 v2 迁移候选，不改变源快照或 desired/running 状态。
// 保留原入站、用户与 secret 身份；新 profile.enabled=true，顶层 enabled 保持原值。
// 所有指针与切片均独立，调用方可预演并编辑候选后再走宿主确认流程。
func FromV1(source *v1.Intent) (*Intent, error) {
	if err := v1.Validate(source); err != nil {
		return nil, err
	}
	in := source.Inbound
	reality := *in.Security
	reality.ServerNames = slices.Clone(in.Security.ServerNames)
	reality.ShortIDs = slices.Clone(in.Security.ShortIDs)
	users := make([]User, len(in.Users))
	for index, user := range in.Users {
		ref := user.UUID
		users[index] = User{ID: user.ID, UUID: &ref}
	}
	enabled := *source.Enabled
	profileEnabled := true
	out := &Intent{
		SchemaVersion: "2",
		Enabled:       &enabled,
		Profiles: []Profile{{
			ID:       in.ID,
			Enabled:  &profileEnabled,
			Listen:   in.Listen,
			Port:     in.Port,
			Protocol: ProtocolVLESS,
			Users:    users,
			VLESS:    &VLESS{Transport: in.Transport, Flow: in.Flow, Security: &reality},
		}},
		Outbound: &Outbound{Type: source.Outbound.Type},
	}
	if err := Validate(out); err != nil {
		return nil, err
	}
	return out, nil
}
