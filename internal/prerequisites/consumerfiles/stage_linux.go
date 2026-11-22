// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package consumerfiles

import (
	"context"
	"errors"

	"golang.org/x/sys/unix"

	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 材料代与独立完整许可快照的发布 ========================

// Stage 首次完整落下同一代材料与首个许可，再以 NOREPLACE 发布固定 gN。
// 同代新许可只新增完整快照；相同材料范围与摘要始终不能被替换。
func (s *Store) Stage(ctx context.Context, binding certificates.HostBinding, material tlsmgr.Material) (out Proof, failure error) {
	if err := validateBinding(binding); err != nil {
		return Proof{}, err
	}
	chain, key := material.CertificatePEM(), material.PrivateKeyPEM()
	defer clear(key)
	if err := validatePair(binding, chain, key); err != nil {
		return Proof{}, err
	}
	wanted := Proof{Binding: binding, FullchainSHA256: digest(chain), PrivateKeySHA256: digest(key)}
	path, err := s.openBinding(ctx, binding.ID, true)
	if err != nil {
		return Proof{}, err
	}
	defer path.close()
	bindingDirectory := path.last()
	if err := lockBinding(ctx, bindingDirectory); err != nil {
		return Proof{}, err
	}
	if err := path.check(ctx); err != nil {
		return Proof{}, err
	}
	generations, err := path.child(ctx, "generations", true)
	if err != nil {
		return Proof{}, err
	}
	name := generationName(binding.Generation)
	if existing, err := path.child(ctx, name, false); err == nil {
		loaded, err := s.readGenerationMaterial(ctx, existing, wanted)
		if err != nil {
			return Proof{}, err
		}
		loaded.Clear()
		if err := path.check(ctx); err != nil {
			return Proof{}, err
		}
		if err := syncFile(existing, false); err != nil {
			return Proof{}, err
		}
		if err := syncFile(generations, false); err != nil {
			return Proof{}, err
		}
		if _, err := path.child(ctx, proofsName, true); err != nil {
			return Proof{}, err
		}
		if err := s.ensureProof(ctx, path, wanted); err != nil {
			return Proof{}, err
		}
		return wanted, nil
	} else if fault.Code(err) != "NOT_FOUND" {
		return Proof{}, err
	}
	metadata, err := encodeMetadata(generationDescriptor(wanted))
	if err != nil {
		return Proof{}, err
	}
	temporaryName, err := randomName(".stage-" + name + "-")
	if err != nil {
		return Proof{}, err
	}
	temporary, err := s.newStageDirectory(generations, temporaryName)
	if err != nil {
		return Proof{}, err
	}
	defer temporary.Close()
	published := false
	defer func() {
		if !published {
			if err := s.cleanupStage(generations, temporaryName, temporary, proofSnapshotName(wanted)); err != nil {
				failure = errors.Join(failure, err)
				out = Proof{}
			}
		}
	}()
	for _, item := range []struct {
		name string
		raw  []byte
	}{{chainName, chain}, {keyName, key}, {materialName, metadata}} {
		if err := s.writeStageFile(ctx, temporary, item.name, item.raw); err != nil {
			return Proof{}, err
		}
	}
	if err := s.writeInitialProof(ctx, temporary, wanted); err != nil {
		return Proof{}, err
	}
	if err := s.finishNewOwner(temporary, true); err != nil {
		return Proof{}, err
	}
	loaded, err := s.readMaterial(ctx, temporary, wanted)
	if err != nil {
		return Proof{}, err
	}
	loaded.Clear()
	if err := path.check(ctx); err != nil {
		return Proof{}, err
	}
	if err := s.directoryLink(generations, temporaryName, temporary); err != nil {
		return Proof{}, err
	}
	if err := checkContext(ctx); err != nil {
		return Proof{}, err
	}
	if err := unix.Renameat2(int(generations.Fd()), temporaryName, int(generations.Fd()), name, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return Proof{}, fault.New("CONSUMER_FILES_CONFLICT", "消费者 generation 已被并发占用")
		}
		return Proof{}, fileFailure("CONSUMER_FILES_IO", "消费者 generation 发布失败", false)
	}
	published = true
	// 发布以后即使 context 取消，也完成持久化围栏；失败必须交给宿主对账。
	if err := syncFile(generations, true); err != nil {
		return Proof{}, err
	}
	if err := s.directoryLink(generations, name, temporary); err != nil {
		return Proof{}, fileFailure("CONSUMER_FILES_UNSAFE", "已发布 generation 的目录关联变化，需要对账", true)
	}
	if err := path.check(context.WithoutCancel(ctx)); err != nil {
		return Proof{}, fileFailure("CONSUMER_FILES_UNSAFE", "已发布 generation 的父目录关联变化，需要对账", true)
	}
	return wanted, nil
}
