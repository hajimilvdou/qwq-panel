// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"net/url"
	"strings"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/prerequisites/acme"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
)

// ======================== 固定 CA 条款的原确认与私有证据 ========================

type certificateTermsRegistration struct {
	Version       uint32          `json:"version"`
	OwnerID       string          `json:"owner_id"`
	NodeID        string          `json:"node_id"`
	CertificateID string          `json:"certificate_id"`
	CA            certificates.CA `json:"ca"`
	URL           string          `json:"url"`
	InitiatedBy   actor.Actor     `json:"initiated_by"`
	ConfirmedBy   actor.Actor     `json:"confirmed_by"`
	OperationID   string          `json:"operation_id"`
	ArgsDigest    string          `json:"args_digest"`
}

func (certificateTermsRegistration) String() string {
	return "hostauth.certificateTermsRegistration{[REDACTED]}"
}
func (certificateTermsRegistration) GoString() string {
	return "hostauth.certificateTermsRegistration{[REDACTED]}"
}

func controlledTermsURL(value string) bool {
	if len(value) > 512 {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host == "letsencrypt.org" && parsed.User == nil &&
		parsed.Fragment == "" && parsed.RawQuery == "" && parsed.RawPath == "" &&
		strings.HasPrefix(parsed.Path, "/documents/") && strings.HasSuffix(parsed.Path, ".pdf") &&
		!strings.Contains(parsed.Path, "/../") && !strings.Contains(parsed.Path, "/./")
}

// CertificateTerms 只能确认原 issue 意图选择的 CA，不能代替续期策略的人类确认。
type CertificateTerms struct{ Authority *Authority }

func (p CertificateTerms) Accept(ctx context.Context, caller certificates.Caller, ca certificates.CA, termsURL string) error {
	if p.Authority == nil {
		return fault.New("BACKEND_REQUIRED", "CA 条款需要真实宿主确认后端")
	}
	a := p.Authority
	grant, err := a.certificateGrant(ctx, caller)
	if err != nil {
		return err
	}
	if grant.access != certificates.Issue || grant.issuance == nil || !grant.acceptTerms || grant.issuance.CA != ca || !controlledTermsURL(termsURL) {
		return fault.New("TERMS_REQUIRED", "CA 条款或原接受范围无效")
	}
	key, err := registryKey("terms", a.ownerID, a.nodeID, grant.certificateID, string(ca))
	if err != nil {
		return err
	}
	var previous certificateTermsRegistration
	revision, found, err := loadPrivate(ctx, a, key, &previous)
	if err != nil {
		return err
	}
	if found && (previous.Version != 1 || previous.OwnerID != a.ownerID || previous.NodeID != a.nodeID ||
		previous.CertificateID != grant.certificateID || previous.CA != ca || !controlledTermsURL(previous.URL) ||
		!validInitiator(previous.InitiatedBy) || !ids.Valid(previous.OperationID, ids.Operation) || !operations.ValidArgumentDigest(previous.ArgsDigest)) {
		return fault.New("STATE_INVALID", "CA 条款私有确认记录无效")
	}
	if found && previous.ConfirmedBy != (actor.Actor{}) && (previous.ConfirmedBy.Kind != actor.Human || !validInitiator(previous.ConfirmedBy)) {
		return fault.New("STATE_INVALID", "CA条款的实际人类确认来源无效")
	}
	value, err := a.current(ctx)
	if err != nil {
		return err
	}
	if permission, ok := ctx.Value(renewalExecutionKey{}).(*renewalExecution); ok && permission != nil {
		humanConfirmed := previous.InitiatedBy.Kind == actor.Human || previous.ConfirmedBy.Kind == actor.Human
		if !found || previous.URL != termsURL || previous.CA != ca || !humanConfirmed ||
			value.snapshot.Actor.Kind != actor.Service || value.snapshot.Actor.ID == "" {
			return fault.New("TERMS_REQUIRED", "service续期只能复用原人类同CA条款确认")
		}
		_, err := a.certificateGrant(ctx, caller)
		return err
	}
	confirmed := value.snapshot.ConfirmationActor
	if confirmed.Kind != actor.Human && value.snapshot.Actor.IsHumanSession() {
		confirmed = value.snapshot.Actor
	}
	if confirmed.Kind != actor.Human {
		confirmed = actor.Actor{}
	}
	state := certificateTermsRegistration{Version: 1, OwnerID: a.ownerID, NodeID: a.nodeID, CertificateID: grant.certificateID,
		CA: ca, URL: termsURL, InitiatedBy: value.snapshot.Actor, ConfirmedBy: confirmed, OperationID: value.invocation.OperationID, ArgsDigest: value.snapshot.ArgsDigest}
	if !found || state != previous {
		if _, err := store.Save(ctx, a.repository, key, revision, state); err != nil {
			return err
		}
	}
	_, err = a.certificateGrant(ctx, caller)
	return err
}

var _ acme.TermsAcceptance = CertificateTerms{}
