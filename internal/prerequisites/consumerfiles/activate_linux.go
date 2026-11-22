// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package consumerfiles

import (
	"context"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

// ======================== 唯一 current 元数据的 CAS 与前代保留 ========================

// Activate 返回切换前的完整 Proof；首次切换返回 nil，重复请求返回保存的同一前代。
// expected=nil 只用于此前没有 current 的 CAS；已生效请求仅允许保存前代/当前代重试。
// 本方法不触发运行时重载，也不返回健康结果；发布后的错误必须按 Uncertain 对账。
func (s *Store) Activate(ctx context.Context, expected *Proof, wanted Proof) (previous *Proof, failure error) {
	if err := validateProof(wanted); err != nil {
		return nil, err
	}
	if expected != nil {
		if err := validateProof(*expected); err != nil {
			return nil, err
		}
		if expected.Binding.ID != wanted.Binding.ID {
			return nil, fault.New("CONSUMER_FILES_CONFLICT", "CAS 前代与目标代属于不同绑定")
		}
	}
	path, err := s.openBinding(ctx, wanted.Binding.ID, false)
	if err != nil {
		return nil, err
	}
	defer path.close()
	bindingDirectory := path.last()
	if err := lockBinding(ctx, bindingDirectory); err != nil {
		return nil, err
	}
	if err := path.check(ctx); err != nil {
		return nil, err
	}
	if _, err := path.child(ctx, "generations", false); err != nil {
		return nil, err
	}
	generation, err := path.child(ctx, generationName(wanted.Binding.Generation), false)
	if err != nil {
		return nil, err
	}
	// CAS 前必须验证所有新材料；即便只是重复请求，也不能接受被改写的 generation。
	material, err := s.readMaterial(ctx, generation, wanted)
	if err != nil {
		return nil, err
	}
	material.Clear()
	current, err := s.readCurrent(ctx, bindingDirectory, wanted.Binding.ID)
	if err != nil {
		return nil, err
	}
	var active *Proof
	if current != nil {
		active = &current.Active
		if current.Active == wanted {
			if !sameProof(expected, active) && !sameProof(expected, current.Previous) {
				return nil, fault.New("CONSUMER_FILES_CONFLICT", "重复 CAS 的前代与已保存事实不符")
			}
			if err := path.check(ctx); err != nil {
				return nil, err
			}
			// 重复请求也补齐目录 fsync，涵盖上次 rename 成功但持久化结果不确定的情况。
			if err := syncFile(bindingDirectory, true); err != nil {
				return copyProof(current.Previous), err
			}
			return copyProof(current.Previous), nil
		}
	}
	if !sameProof(expected, active) {
		return nil, fault.New("CONSUMER_FILES_CONFLICT", "消费者 current 已变化，CAS 前代不符")
	}
	previous = copyProof(active)
	raw, err := encodeMetadata(currentMetadata{Version: metadataVersion, Active: wanted, Previous: previous})
	if err != nil {
		return nil, err
	}
	committed, err := s.publishMetadata(ctx, bindingDirectory, currentName, raw, true, path.check)
	if err != nil {
		if committed {
			return previous, err
		}
		return nil, err
	}
	return previous, nil
}
