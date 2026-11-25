// SPDX-License-Identifier: AGPL-3.0-only

// Package state 保存核心的无秘密运行元数据，运行快照由摘要指向。
package state

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

const (
	MaxMetadataBytes = 64 << 10
	CoreVersion      = "26.11.9"
)

var ErrCorrupt = errors.New("core state: committed snapshot is corrupt")

// Generation 描述一个不可变配置；不记录路径、秘密或原生命令行。
type Generation struct {
	Digest    string           `json:"config_digest"`
	Revision  string           `json:"running_revision"`
	Version   string           `json:"core_version"`
	Enabled   bool             `json:"enabled"`
	Summary   *IntentSummary   `json:"intent_summary,omitempty"`
	SummaryV2 *V2IntentSummary `json:"intent_summary_v2,omitempty"`
}

// Metadata 的 current/previous 由同一个 state.json 原子提交。
type Metadata struct {
	SchemaVersion string      `json:"schema_version"`
	Current       *Generation `json:"current"`
	Previous      *Generation `json:"previous,omitempty"`
	State         string      `json:"state"`
	ResetEpoch    string      `json:"reset_epoch,omitempty"`
	LastError     string      `json:"last_error,omitempty"`
}

// Validate 检查持久字段的规范形态，避免元数据透传任意路径或诊断文本。
func (m Metadata) Validate() error {
	if m.SchemaVersion != "1" || m.Current == nil {
		return ErrCorrupt
	}
	for _, generation := range []*Generation{m.Current, m.Previous} {
		if generation == nil {
			continue
		}
		if !ValidDigest(generation.Digest) || !ValidRevision(generation.Revision) || generation.Version != CoreVersion {
			return ErrCorrupt
		}
		if generation.Summary != nil && generation.Summary.Validate() != nil {
			return ErrCorrupt
		}
		if generation.SummaryV2 != nil && generation.SummaryV2.Validate() != nil {
			return ErrCorrupt
		}
	}
	switch m.State {
	case "RUNNING", "STOPPED", "FAILED":
	default:
		return ErrCorrupt
	}
	if m.State == "RUNNING" && !m.Current.Enabled || len(m.ResetEpoch) > 64 || !safeToken(m.ResetEpoch) {
		return ErrCorrupt
	}
	switch m.LastError {
	case "", "CORE_START_FAILED", "CORE_EXITED", "CORE_API_UNAVAILABLE", "RECOVERY_FAILED", "STATE_COMMIT_FAILED":
	default:
		return ErrCorrupt
	}
	return nil
}

// ValidDigest 只接受小写 SHA-256；目录名由调用方固定推导。
func ValidDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}

// ValidRevision 与宿主正数十进制 revision 保持一致，拒绝前导零与溢出。
func ValidRevision(value string) bool {
	revision, err := strconv.ParseInt(value, 10, 64)
	return err == nil && revision > 0 && strconv.FormatInt(revision, 10) == value
}

func safeToken(value string) bool {
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}
