// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// ======================== 宿主私有强身份与严格 loaded profile；不接触 helper 权限 ========================

var (
	ErrGenerationUnsupported = errors.New("sandbox: fixed generation control is unsupported")
	ErrGenerationIdentity    = errors.New("sandbox: the original process identity is unavailable")
	ErrGenerationProfile     = errors.New("sandbox: the loaded service profile is unsafe for generation control")
	ErrGenerationUnconfirmed = errors.New("sandbox: the original cgroup exit is unconfirmed")
)

// ProcessProof 由固定 proc/cgroup FD 与实际 systemd 读取产生，不能把 FD 数字当持久身份。
type ProcessProof struct {
	Version          uint32 `json:"version"`
	Unit             string `json:"unit"`
	PID              int    `json:"pid"`
	KernelStartTicks uint64 `json:"kernel_start_ticks"`
	BootID           string `json:"boot_id"`
	InvocationID     string `json:"invocation_id"`
	UID              uint32 `json:"uid"`
	Cgroup           string `json:"cgroup"`
	CgroupDevice     uint64 `json:"cgroup_device"`
	CgroupInode      uint64 `json:"cgroup_inode"`
}

// Validate 核完整插件/内核身份；零值不能授权停止，也不放行 PID1/root。
func (proof ProcessProof) Validate(pluginID string) error {
	unit, _, err := UnitNames(pluginID)
	if err != nil || proof.Version != 1 || proof.Unit != unit || proof.PID <= 1 || proof.PID > math.MaxInt32 || proof.UID == 0 ||
		proof.KernelStartTicks == 0 || !validGenerationID(proof.BootID) || !validGenerationID(proof.InvocationID) ||
		!validGenerationCgroupPath(proof.Cgroup) || CgroupUnit("0::"+proof.Cgroup) != unit || proof.CgroupInode == 0 {
		return ErrGenerationIdentity
	}
	return nil
}

func validGenerationID(value string) bool {
	if len(value) != 32 || value != strings.ToLower(value) || value == strings.Repeat("0", 32) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// StopObservation 原主退出与原组清空缺一不可，未来 helper/回执共用同一完成判断。
type StopObservation struct {
	Proof               ProcessProof `json:"proof"`
	OriginalExited      bool         `json:"original_exited"`
	OriginalCgroupEmpty bool         `json:"original_cgroup_empty"`
}

// ValidateCompleted 只接受当次固定对象的完整完成，不从新 MainPID 推断旧组。
func (observation StopObservation) ValidateCompleted(pluginID string, expected ProcessProof) error {
	if expected.Validate(pluginID) != nil || observation.Proof != expected || !observation.OriginalExited || !observation.OriginalCgroupEmpty {
		return ErrGenerationUnconfirmed
	}
	return nil
}

// LoadedGenerationProfile 只能由严格 parser 产生；presence 不通过公开字段或安全默认伪造。
type LoadedGenerationProfile struct {
	Unit            string
	SystemdVersion  uint32
	MainPID         int
	ControlGroup    string
	Type            string
	DynamicUser     bool
	KillMode        string
	RemainAfterExit bool
	SendSIGKILL     bool
	InvocationID    string
	ExitType        string
	present         bool
}

// ParseGenerationProfile 读取实际 loaded 属性；旧 systemd 没有 ExitType 时按已核版本能力处理。
func ParseGenerationProfile(pluginID string, systemdVersion uint32, output string) (LoadedGenerationProfile, error) {
	unit, _, err := UnitNames(pluginID)
	if err != nil || systemdVersion < 247 {
		return LoadedGenerationProfile{}, ErrGenerationProfile
	}
	values := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSuffix(line, "\r"), "=")
		if !ok {
			if strings.TrimSpace(line) != "" {
				return LoadedGenerationProfile{}, ErrGenerationProfile
			}
			continue
		}
		if _, exists := values[key]; exists {
			return LoadedGenerationProfile{}, ErrGenerationProfile
		}
		values[key] = value
	}
	for _, required := range []string{"MainPID", "ControlGroup", "Type", "DynamicUser", "KillMode", "RemainAfterExit", "SendSIGKILL", "InvocationID"} {
		if _, exists := values[required]; !exists {
			return LoadedGenerationProfile{}, fmt.Errorf("%w: missing %s", ErrGenerationProfile, required)
		}
	}
	parseBool := func(key string) (bool, error) {
		switch values[key] {
		case "yes":
			return true, nil
		case "no":
			return false, nil
		default:
			return false, ErrGenerationProfile
		}
	}
	pid, err := strconv.ParseInt(values["MainPID"], 10, 32)
	if err != nil || pid <= 1 {
		return LoadedGenerationProfile{}, ErrGenerationProfile
	}
	dynamic, err := parseBool("DynamicUser")
	if err != nil {
		return LoadedGenerationProfile{}, err
	}
	remain, err := parseBool("RemainAfterExit")
	if err != nil {
		return LoadedGenerationProfile{}, err
	}
	kill, err := parseBool("SendSIGKILL")
	if err != nil {
		return LoadedGenerationProfile{}, err
	}
	exitType, exists := values["ExitType"]
	if !exists {
		if systemdVersion >= 250 {
			return LoadedGenerationProfile{}, ErrGenerationProfile
		}
		exitType = "main"
	}
	profile := LoadedGenerationProfile{Unit: unit, SystemdVersion: systemdVersion, MainPID: int(pid),
		ControlGroup: values["ControlGroup"], Type: values["Type"], DynamicUser: dynamic,
		KillMode: values["KillMode"], RemainAfterExit: remain, SendSIGKILL: kill,
		InvocationID: values["InvocationID"], ExitType: exitType, present: true}
	if err := profile.Validate(pluginID); err != nil {
		return LoadedGenerationProfile{}, err
	}
	return profile, nil
}

// Validate 拒绝未解析结构、弱 loaded 配置与非原插件控制组。
func (profile LoadedGenerationProfile) Validate(pluginID string) error {
	unit, _, err := UnitNames(pluginID)
	if err != nil || !profile.present || profile.SystemdVersion < 247 || profile.Unit != unit ||
		profile.MainPID <= 1 || profile.Type != "exec" || !profile.DynamicUser || profile.KillMode != "control-group" ||
		profile.RemainAfterExit || !profile.SendSIGKILL || profile.ExitType != "main" ||
		!validGenerationID(profile.InvocationID) || !validGenerationCgroupPath(profile.ControlGroup) ||
		CgroupUnit("0::"+profile.ControlGroup) != unit {
		return ErrGenerationProfile
	}
	return nil
}
