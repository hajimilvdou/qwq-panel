// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"slices"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
)

// ======================== 不可静默扩大的证书 SAN 与用途登记 ========================

type certificateRegistration struct {
	Version     uint32            `json:"version"`
	OwnerID     string            `json:"owner_id"`
	NodeID      string            `json:"node_id"`
	ID          string            `json:"id"`
	Spec        certificates.Spec `json:"spec"`
	CreatedBy   actor.Actor       `json:"created_by"`
	OperationID string            `json:"operation_id"`
	ArgsDigest  string            `json:"args_digest"`
}

func (certificateRegistration) String() string { return "hostauth.certificateRegistration{[REDACTED]}" }
func (certificateRegistration) GoString() string {
	return "hostauth.certificateRegistration{[REDACTED]}"
}

func sameCertificateSpec(one, two certificates.Spec) bool {
	return one.Purpose == two.Purpose && slices.Equal(one.SANs, two.SANs)
}

func (a *Authority) certificateKey(id string) (string, error) {
	return registryKey("certificate", a.ownerID, a.nodeID, id)
}

func (a *Authority) loadCertificate(ctx context.Context, id string) (certificateRegistration, string, bool, error) {
	key, err := a.certificateKey(id)
	if err != nil {
		return certificateRegistration{}, "", false, err
	}
	var state certificateRegistration
	revision, found, err := loadPrivate(ctx, a, key, &state)
	if err != nil || !found {
		return state, revision, found, err
	}
	spec, specErr := certificates.CanonicalSpec(state.Spec)
	validResource := state.Version == 1 && state.OwnerID == a.ownerID && state.NodeID == a.nodeID && state.ID == id
	validIntent := validInitiator(state.CreatedBy) && ids.Valid(state.OperationID, ids.Operation) && operations.ValidArgumentDigest(state.ArgsDigest)
	if !validResource || !validIntent || specErr != nil || !sameCertificateSpec(spec, state.Spec) {
		return certificateRegistration{}, "", false, fault.New("STATE_INVALID", "证书宿主登记的作用域、原意图或 SAN 无效")
	}
	return state, revision, true, nil
}

func (a *Authority) registerCertificate(ctx context.Context, value *execution, id, expected string, spec certificates.Spec) (certificateRegistration, string, error) {
	state, revision, found, err := a.loadCertificate(ctx, id)
	if err != nil {
		return certificateRegistration{}, "", err
	}
	if found {
		if !sameCertificateSpec(state.Spec, spec) {
			return certificateRegistration{}, "", fault.New("SAN_MISMATCH", "既有证书的 SAN 和用途不能在原 ID 上扩大或替换")
		}
		return state, revision, nil
	}
	if expected != certificates.MissingRevision {
		return certificateRegistration{}, "", fault.New("REVISION_CONFLICT", "证书宿主登记不存在，请重新预演")
	}
	if _, err := a.current(ctx); err != nil {
		return certificateRegistration{}, "", err
	}
	state = certificateRegistration{Version: 1, OwnerID: a.ownerID, NodeID: a.nodeID, ID: id, Spec: cloneCertificateSpec(spec),
		CreatedBy: value.snapshot.Actor, OperationID: value.invocation.OperationID, ArgsDigest: value.snapshot.ArgsDigest}
	key, err := a.certificateKey(id)
	if err != nil {
		return certificateRegistration{}, "", err
	}
	revision, err = store.Save(ctx, a.repository, key, "", state)
	if err != nil {
		return certificateRegistration{}, "", err
	}
	if _, err := a.current(ctx); err != nil {
		return certificateRegistration{}, "", err
	}
	return state, revision, nil
}
