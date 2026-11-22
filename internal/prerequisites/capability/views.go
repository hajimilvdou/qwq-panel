// SPDX-License-Identifier: AGPL-3.0-only

package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/hostauth"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	certificatesv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/certificates/v1"
	dnsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/dns/v1"
)

// ======================== 有界公开ID目录；目录不是授权账本 ========================

const (
	providerCatalog    = "prerequisites/dns/providers/"
	certificateCatalog = "prerequisites/certificates/resources/"
	maxCatalogEntries  = 128
)

type catalogState struct {
	Version uint32   `json:"version"`
	IDs     []string `json:"ids"`
}

func (f *Forwarder) loadCatalog(ctx context.Context, prefix string) (catalogState, string, bool, error) {
	if prefix != providerCatalog && prefix != certificateCatalog {
		return catalogState{}, "", false, fault.New("VALIDATION_FAILED", "公开目录类型无效")
	}
	key := prefix + "index"
	entry, found, err := f.views.Get(ctx, key)
	if err != nil {
		return catalogState{}, "", false, fault.New("STATE_UNAVAILABLE", "公开目录读取失败")
	}
	defer clear(entry.Value)
	if !found {
		return catalogState{Version: 1, IDs: []string{}}, "", false, nil
	}
	var state catalogState
	decoder := json.NewDecoder(bytes.NewReader(entry.Value))
	decoder.DisallowUnknownFields()
	if entry.Key != key || entry.Revision == "" || len(entry.Value) > 32*1024 || decoder.Decode(&state) != nil ||
		decoder.Decode(new(any)) != io.EOF || state.Version != 1 || state.IDs == nil || len(state.IDs) > maxCatalogEntries {
		return catalogState{}, "", false, fault.New("STATE_INVALID", "公开目录的格式或容量无效")
	}
	previous := ""
	for _, id := range state.IDs {
		if !names.ID(id) || id <= previous {
			return catalogState{}, "", false, fault.New("STATE_INVALID", "公开目录包含无效或重复资源ID")
		}
		previous = id
	}
	return state, entry.Revision, true, nil
}

func (f *Forwarder) catalogIDs(ctx context.Context, prefix string) ([]string, error) {
	state, _, _, err := f.loadCatalog(ctx, prefix)
	return state.IDs, err
}

func (f *Forwarder) publishCatalogID(ctx context.Context, prefix, id string) error {
	if !names.ID(id) || (prefix != providerCatalog && prefix != certificateCatalog) {
		return fault.New("VALIDATION_FAILED", "公开目录只能登记固定资源ID")
	}
	// 单键CAS同时约束持久数量；并发登记不能突破128个候选的上限。
	for attempt := 0; attempt < 3; attempt++ {
		state, revision, found, err := f.loadCatalog(ctx, prefix)
		if err != nil {
			return err
		}
		index, exists := slices.BinarySearch(state.IDs, id)
		if exists {
			return nil
		}
		if len(state.IDs) >= maxCatalogEntries {
			return fault.New("RESOURCE_EXHAUSTED", "公开目录已达128个候选的上限")
		}
		state.IDs = slices.Insert(state.IDs, index, id)
		raw, err := json.Marshal(state)
		if err != nil {
			return fault.New("STATE_INVALID", "公开目录ID无法编码")
		}
		_, err = f.views.Put(ctx, prefix+"index", raw, hostsvc.StateGuard{MustNotExist: !found, ExpectedRevision: revision})
		clear(raw)
		if errors.Is(err, hostsvc.ErrStateConflict) {
			continue
		}
		if err != nil {
			return fault.New("STATE_UNAVAILABLE", "公开目录登记失败")
		}
		return nil
	}
	return fault.New("REVISION_CONFLICT", "公开目录并发变化，请按原请求重读")
}

func publicTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func providerView(value hostauth.ProviderPublic) *dnsv1.ProviderView {
	return &dnsv1.ProviderView{Id: value.ID, Kind: value.Kind, Name: value.Name, Revision: value.Revision,
		Enabled: value.Enabled, ZoneCount: value.ZoneCount, LastError: value.LastError}
}

func zoneView(value hostauth.ZonePublic) *dnsv1.ZoneView {
	return &dnsv1.ZoneView{ProviderId: value.ProviderID, ZoneId: value.ZoneID, Name: value.Name, Revision: value.Revision, Authorized: value.Authorized}
}

func recordView(value dns.Record) *dnsv1.RecordView {
	return &dnsv1.RecordView{Id: value.ID, Type: string(value.Type), Name: value.Name, Value: value.Value, Ttl: value.TTL,
		Proxied: value.Proxied, Revision: value.Revision, ManagedChallenge: value.ManagedBy != ""}
}

func certificateView(value certificates.View) *certificatesv1.CertificateView {
	status := "not_ready"
	if value.Ready {
		status = "ready"
	}
	if value.Ready && !value.ConsumersReady {
		status = "issued_deployment_failed"
	}
	if value.Pending != "" {
		status = "pending_" + value.Pending
	}
	view := &certificatesv1.CertificateView{Id: value.ID, Revision: value.Revision, Sans: append([]string(nil), value.Spec.SANs...),
		Purpose: string(value.Spec.Purpose), Status: status, LatestGeneration: value.CurrentGeneration}
	for _, generation := range value.Generations {
		metadata := generation.Metadata
		view.Generations = append(view.Generations, &certificatesv1.GenerationView{Number: generation.Number,
			Fingerprint: metadata.Fingerprint, Issuer: metadata.Issuer, NotBefore: publicTime(metadata.NotBefore),
			NotAfter: publicTime(metadata.NotAfter), Trust: string(metadata.Trust)})
	}
	for _, binding := range value.Bindings {
		consumer := binding.Host.Consumer
		status := "not_verified"
		if binding.Verified {
			status = "deployed"
		}
		view.Bindings = append(view.Bindings, &certificatesv1.BindingView{BindingRef: binding.Host.ID, PluginId: consumer.PluginID,
			ProfileId: consumer.ProfileID, NodeId: consumer.NodeID, ServerName: consumer.SNI, Purpose: consumer.Purpose,
			Generation: binding.Host.Generation, RunningGeneration: binding.RunningGeneration, PolicyRevision: binding.Host.PolicyRevision,
			Status: status, PreviousGeneration: binding.PreviousGeneration})
	}
	return view
}

func renewalView(registration hostauth.RenewalPolicyView, runtime *certificates.RenewalView) *certificatesv1.RenewalView {
	view := &certificatesv1.RenewalView{Id: registration.ID, CertificateId: registration.CertificateID, Revision: registration.Revision,
		Status: registration.State, ExpiresAt: publicTime(registration.ExpiresAt)}
	if runtime != nil {
		view.Enabled, view.Status, view.NextAt = runtime.Enabled, runtime.Status, publicTime(runtime.NextAt)
		view.Attempts, view.LastError, view.Alert = uint32(runtime.Attempts), runtime.LastError, runtime.Alert
		if runtime.ExpiresAt.Before(registration.ExpiresAt) {
			view.ExpiresAt = publicTime(runtime.ExpiresAt)
		}
	}
	if registration.State != "active" {
		view.Enabled, view.Status, view.NextAt = false, registration.State, ""
	}
	return view
}
