// SPDX-License-Identifier: Apache-2.0

package coreapi

import (
	"net/netip"
	"strconv"

	v1 "github.com/qwq-panel/qwq/sdk/coreapi"
	"github.com/qwq-panel/qwq/sdk/internal/strictjson"
)

// Validate 确定性检查完整快照，不修改输入、不揭示材料或探测监听。
// 停用 profile 仍须完整有效；顶层停用不掩盖其已启用 profiles 的端口冲突。
func Validate(intent *Intent) error {
	if intent == nil {
		return invalid("", "REQUIRED", "必须提供完整配置")
	}
	v := validator{}
	v.require(intent.SchemaVersion == "2", "/schema_version", "VERSION", "契约版本必须为 2")
	v.require(intent.Enabled != nil, "/enabled", "REQUIRED", "必须显式声明 enabled")
	v.require(len(intent.Profiles) >= 1 && len(intent.Profiles) <= MaxProfiles, "/profiles", "SIZE", "profile 数量必须在 1 至 8 之间")
	if intent.Outbound == nil {
		v.require(false, "/outbound", "REQUIRED", "必须提供出站")
	} else {
		v.require(intent.Outbound.Type == "direct", "/outbound/type", "ENUM", "首版只支持 direct 出站")
	}
	seenProfiles := make(map[string]bool, min(len(intent.Profiles), MaxProfiles))
	seenUsers := make(map[string]bool)
	seenMarks := make(map[uint32]string)
	totalUsers := 0
	for index := range min(len(intent.Profiles), MaxProfiles) {
		profile := &intent.Profiles[index]
		path := strictjson.Pointer("/profiles", strconv.Itoa(index))
		v.require(v1.ValidID(profile.ID), path+"/id", "ID", "profile ID 必须是 1 至 32 位的小写稳定标识")
		v.require(!seenProfiles[profile.ID], path+"/id", "DUPLICATE", "profile ID 不能重复")
		seenProfiles[profile.ID] = true
		v.require(profile.Enabled != nil, path+"/enabled", "REQUIRED", "必须显式声明 profile enabled")
		_, listenOK := validListen(profile.Listen)
		v.require(listenOK, path+"/listen", "IP", "监听地址必须是无 zone 的 IPv4 或 IPv6")
		v.require(profile.Port >= 1024 && profile.Port <= 65535, path+"/port", "RANGE", "入站端口必须在 1024 至 65535 之间")
		v.protocol(profile, path)
		v.require(len(profile.Users) >= 1 && len(profile.Users) <= MaxUsers, path+"/users", "SIZE", "每个 profile 必须有 1 至 256 个用户")
		totalUsers += len(profile.Users)
		for userIndex := range min(len(profile.Users), MaxUsers) {
			user := &profile.Users[userIndex]
			userPath := strictjson.Pointer(path+"/users", strconv.Itoa(userIndex))
			v.require(v1.ValidID(user.ID), userPath+"/id", "ID", "用户 ID 必须是小写稳定标识")
			v.require(!seenUsers[user.ID], userPath+"/id", "DUPLICATE", "用户 ID 在完整快照内不能重复")
			seenUsers[user.ID] = true
			if user.TrafficMark != 0 {
				v.require(user.TrafficMark >= MinTrafficMark && user.TrafficMark <= MaxTrafficMark, userPath+"/traffic_mark", "RANGE", "traffic_mark 必须为 0 或位于 0x5100..0x51FF 保留段内")
				if prevUser, dup := seenMarks[user.TrafficMark]; dup && prevUser != user.ID {
					v.require(false, userPath+"/traffic_mark", "DUPLICATE", "traffic_mark 在完整快照内不能被多个用户共用")
				} else if user.TrafficMark >= MinTrafficMark && user.TrafficMark <= MaxTrafficMark {
					seenMarks[user.TrafficMark] = user.ID
				}
			}
			v.credentials(user, profile.Protocol, userPath)
		}
		v.claim(profile, path)
	}
	v.require(totalUsers <= MaxUsers, "/profiles", "SIZE", "节点总用户数不得超过 256")
	if len(v.violations) != 0 {
		return &Error{Code: "INVALID_INTENT", Violations: v.violations}
	}
	return nil
}

type validator struct {
	violations []Violation
	ports      []listenerClaim
}

func (v *validator) require(ok bool, path, code, message string) {
	if !ok {
		v.violations = append(v.violations, Violation{Pointer: path, Code: code, Message: message})
	}
}

func (v *validator) secret(ref *SecretRef, path string) {
	if ref == nil {
		v.require(false, path, "REQUIRED", "必须提供对应协议的秘密引用")
		return
	}
	v.require(v1.ValidSecretRef(*ref), path+"/$secret", "SECRET_REF", "必须使用宿主生成的有效 secret 引用")
}

func validListen(listen string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(listen)
	return addr, err == nil && addr.Zone() == ""
}
