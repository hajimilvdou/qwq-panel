// SPDX-License-Identifier: AGPL-3.0-only

package capability

import (
	"context"
	"errors"

	"google.golang.org/protobuf/proto"

	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/hostauth"
	dnsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/dns/v1"
)

// ======================== DNS RPC只选择原ID与版本，内容由原Args构造 ========================

func requestAs[T proto.Message](request proto.Message) (T, error) {
	value, found := request.(T)
	if !found || !value.ProtoReflect().IsValid() {
		var zero T
		return zero, fault.New("VALIDATION_FAILED", "RPC强类型请求不符")
	}
	return value, nil
}

func (f *Forwarder) requireCollection(ctx context.Context, plugin, operation, resource string) error {
	invocation, err := f.authority.CurrentInvocation(ctx)
	if err != nil {
		return err
	}
	if invocation.PluginID != plugin || invocation.Operation != operation || invocation.Subject != "plugins/"+plugin+"/resources/"+resource {
		return fault.New("PERMISSION_DENIED", "集合不属于原固定目标")
	}
	_, err = hostauth.DecodeArguments[hostauth.CollectionArgs](ctx, f.authority)
	return err
}

func (f *Forwarder) forwardDNS(ctx context.Context, method string, request proto.Message) (proto.Message, error) {
	switch method {
	case "RegisterProvider":
		response := new(dnsv1.RegisterProviderResponse)
		input, err := requestAs[*dnsv1.RegisterProviderRequest](request)
		if err != nil {
			return response, err
		}
		if _, _, err := f.authority.RegisterProvider(ctx, input.ProviderId, input.ExpectedRevision); err != nil {
			return response, err
		}
		if err := f.publishCatalogID(ctx, providerCatalog, input.ProviderId); err != nil {
			return response, err
		}
		provider, zones, err := f.authority.PublicProvider(ctx, input.ProviderId)
		if err != nil {
			return response, err
		}
		response.Provider = providerView(provider)
		for _, zone := range zones {
			response.Zones = append(response.Zones, zoneView(zone))
		}
		return response, nil
	case "ListProviders":
		response := new(dnsv1.ListProvidersResponse)
		if _, err := requestAs[*dnsv1.ListProvidersRequest](request); err != nil {
			return response, err
		}
		if err := f.requireCollection(ctx, "domain.dns", "providers.list", "providers"); err != nil {
			return response, err
		}
		ids, err := f.catalogIDs(ctx, providerCatalog)
		if err != nil {
			return response, err
		}
		for _, id := range ids {
			provider, _, err := f.authority.PublicProvider(ctx, id)
			if fault.Code(err) == "NOT_FOUND" || fault.Code(err) == "PERMISSION_DENIED" {
				continue
			}
			if err != nil {
				return response, err
			}
			response.Providers = append(response.Providers, providerView(provider))
		}
		return response, nil
	case "DiscoverZones":
		response := new(dnsv1.DiscoverZonesResponse)
		input, err := requestAs[*dnsv1.DiscoverZonesRequest](request)
		if err != nil {
			return response, err
		}
		_, zones, err := f.authority.PublicProvider(ctx, input.ProviderId)
		if err != nil {
			return response, err
		}
		for _, zone := range zones {
			response.Zones = append(response.Zones, zoneView(zone))
		}
		return response, nil
	case "RevokeProvider":
		response := new(dnsv1.RevokeProviderResponse)
		input, err := requestAs[*dnsv1.RevokeProviderRequest](request)
		if err != nil {
			return response, err
		}
		if _, err := f.authority.RevokeProvider(ctx, input.ProviderId, input.ExpectedRevision); err != nil {
			return response, err
		}
		provider, _, err := f.authority.PublicProvider(ctx, input.ProviderId)
		if err != nil {
			return response, err
		}
		response.Provider = providerView(provider)
		return response, nil
	case "AuthorizeZone":
		response := new(dnsv1.AuthorizeZoneResponse)
		input, err := requestAs[*dnsv1.AuthorizeZoneRequest](request)
		if err != nil {
			return response, err
		}
		if _, _, err := f.authority.AuthorizeZone(ctx, input.ProviderId, input.ZoneId, input.ExpectedRevision); err != nil {
			return response, err
		}
		zone, err := f.authority.PublicZone(ctx, input.ProviderId, input.ZoneId)
		if err != nil {
			return response, err
		}
		response.Zone = zoneView(zone)
		return response, nil
	case "RevokeZone":
		response := new(dnsv1.RevokeZoneResponse)
		input, err := requestAs[*dnsv1.RevokeZoneRequest](request)
		if err != nil {
			return response, err
		}
		if _, err := f.authority.RevokeZone(ctx, input.ProviderId, input.ZoneId, input.ExpectedRevision); err != nil {
			return response, err
		}
		zone, err := f.authority.PublicZone(ctx, input.ProviderId, input.ZoneId)
		if err != nil {
			return response, err
		}
		response.Zone = zoneView(zone)
		return response, nil
	case "ListRecords":
		response := new(dnsv1.ListRecordsResponse)
		input, err := requestAs[*dnsv1.ListRecordsRequest](request)
		if err != nil {
			return response, err
		}
		bound, caller, scope, err := f.authority.DNSContext(ctx, input.ProviderId, input.ZoneId)
		if err != nil {
			return response, err
		}
		snapshot, err := f.dns.List(bound, caller, scope)
		if err != nil {
			return response, err
		}
		response.Revision = snapshot.Revision
		for _, record := range snapshot.Records {
			response.Records = append(response.Records, recordView(record))
		}
		return response, nil
	case "ApplyRecord":
		response := new(dnsv1.ApplyRecordResponse)
		input, err := requestAs[*dnsv1.ApplyRecordRequest](request)
		if err != nil {
			return response, err
		}
		bound, _, _, err := f.authority.DNSContext(ctx, input.ProviderId, input.ZoneId)
		if err != nil {
			return response, err
		}
		accepted, err := f.authority.AcceptedDNSRequest(bound)
		if err != nil {
			return response, err
		}
		if input.AttemptId != accepted.AttemptID || input.ExpectedRevision != accepted.ExpectedRevision {
			return response, fault.New("PERMISSION_DENIED", "RPC替换了原DNS attempt或revision")
		}
		receipt, err := f.dns.Apply(bound, accepted)
		response.State = string(receipt.State)
		response.Revision, response.Record, err = f.recordResult(bound, accepted.Caller, accepted.Scope, receipt, err)
		return response, err
	case "ReconcileRecord":
		response := new(dnsv1.ReconcileRecordResponse)
		input, err := requestAs[*dnsv1.ReconcileRecordRequest](request)
		if err != nil {
			return response, err
		}
		bound, caller, scope, err := f.authority.DNSContext(ctx, input.ProviderId, input.ZoneId)
		if err != nil {
			return response, err
		}
		accepted, err := hostauth.DecodeArguments[hostauth.DNSArgs](bound, f.authority)
		if err != nil {
			return response, err
		}
		if input.AttemptId != accepted.AttemptID {
			return response, fault.New("PERMISSION_DENIED", "RPC对账替换了原DNS attempt")
		}
		receipt, err := f.dns.RecoverAttempt(bound, caller, scope, "", accepted.AttemptID)
		response.State = string(receipt.State)
		response.Revision, response.Record, err = f.recordResult(bound, caller, scope, receipt, err)
		return response, err
	case "CheckDns":
		response := new(dnsv1.CheckDnsResponse)
		input, err := requestAs[*dnsv1.CheckDnsRequest](request)
		if err != nil {
			return response, err
		}
		bound, caller, scope, err := f.authority.DNSContext(ctx, input.ProviderId, input.ZoneId)
		if err != nil {
			return response, err
		}
		record, err := f.authority.AcceptedDNSCheck(bound)
		if err != nil {
			return response, err
		}
		result, err := f.checker.Check(bound, dns.PropagationRequest{Caller: caller, Scope: scope, Record: record})
		response.Propagated = result.Ready
		for _, sample := range result.Observations {
			response.Observations = append(response.Observations, &dnsv1.ObservationView{Source: sample.Source,
				Kind: string(sample.Kind), Values: append([]string(nil), sample.Values...), CollectedAt: publicTime(sample.CollectedAt)})
		}
		return response, err
	}
	return nil, fault.New("PERMISSION_DENIED", "DNS方法不在固定表")
}

// recordResult以当前公开zone快照提供revision，原receipt状态不因查询失败丢失。
func (f *Forwarder) recordResult(ctx context.Context, caller dns.Caller, scope dns.Scope, receipt dns.Receipt, failure error) (string, *dnsv1.RecordView, error) {
	if failure != nil {
		return receipt.Revision, nil, failure
	}
	snapshot, err := f.dns.List(ctx, caller, scope)
	if err != nil {
		return receipt.Revision, nil, errors.Join(failure, fault.New("VIEW_UNAVAILABLE", "原DNS收据已保存，公开快照暂不可用"))
	}
	for _, record := range snapshot.Records {
		if record.ID == receipt.RecordID {
			return snapshot.Revision, recordView(record), nil
		}
	}
	return snapshot.Revision, nil, nil
}
