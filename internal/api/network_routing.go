// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/qwq-panel/qwq/internal/netfacts"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/routingrules"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== Track 05：双端双栈策略与中国分流规则 API ========================

const defaultRoutingProfileID = "default"

type networkPolicyDTO struct {
	NodeID            string                                `json:"node_id"`
	InboundFamilyMode netfacts.FamilyMode                   `json:"inbound_family_mode"`
	InboundCandidates []netfacts.EndpointCandidate          `json:"inbound_candidates"`
	OutboundFamily    netfacts.FamilyMode                   `json:"outbound_family_mode"`
	OutboundBindIPv4  string                                `json:"outbound_bind_ipv4,omitempty"`
	OutboundBindIPv6  string                                `json:"outbound_bind_ipv6,omitempty"`
	OutboundOverrides []routingrules.OutboundDomainOverride `json:"outbound_overrides"`
	EffectiveOutbound string                                `json:"effective_outbound_mode"`
	Warnings          []string                              `json:"warnings,omitempty"`
	Revision          string                                `json:"revision"`
	UpdatedAt         int64                                 `json:"updated_at"`
}

type putNetworkPolicyRequest struct {
	InboundFamilyMode netfacts.FamilyMode                   `json:"inbound_family_mode"`
	InboundCandidates []netfacts.EndpointCandidate          `json:"inbound_candidates"`
	OutboundFamily    netfacts.FamilyMode                   `json:"outbound_family_mode"`
	OutboundBindIPv4  string                                `json:"outbound_bind_ipv4,omitempty"`
	OutboundBindIPv6  string                                `json:"outbound_bind_ipv6,omitempty"`
	OutboundOverrides []routingrules.OutboundDomainOverride `json:"outbound_overrides"`
	ExpectedRevision  string                                `json:"expected_revision,omitempty"`
	SkipFactsGuard    bool                                  `json:"skip_facts_guard,omitempty"`
}

type routingProfileDTO struct {
	ID              string                    `json:"id"`
	Name            string                    `json:"name"`
	Mode            routingrules.ProfileMode  `json:"mode"`
	BlockAds        bool                      `json:"block_ads"`
	DNSAntiPoison   bool                      `json:"dns_anti_poison"`
	BundleVersion   string                    `json:"bundle_version"`
	BundleSHA256    string                    `json:"bundle_sha256"`
	BundleRuleCount int                       `json:"bundle_rule_count"`
	CustomRules     []routingrules.CustomRule `json:"custom_rules"`
	Revision        string                    `json:"revision"`
	UpdatedAt       int64                     `json:"updated_at"`
}

type putRoutingProfileRequest struct {
	Name             string                    `json:"name,omitempty"`
	Mode             routingrules.ProfileMode  `json:"mode"`
	BlockAds         bool                      `json:"block_ads"`
	DNSAntiPoison    bool                      `json:"dns_anti_poison"`
	CustomRules      []routingrules.CustomRule `json:"custom_rules"`
	ExpectedRevision string                    `json:"expected_revision,omitempty"`
}

type updateRoutingBundleRequest struct {
	Version        string `json:"version"`
	BundleText     string `json:"bundle_text"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
}

type updateRoutingBundleResponse struct {
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	RuleCount int    `json:"rule_count"`
}

type routingPreviewRequest struct {
	Target string `json:"target"`
}

func (a *api) collectFacts() (netfacts.HostNetworkFacts, error) {
	if a.netFactsFn != nil {
		return a.netFactsFn()
	}
	return netfacts.Collect("", "")
}

// getNetworkFacts 实现 GET /api/v1/network/facts。
func (a *api) getNetworkFacts(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.system:read", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	facts, err := a.collectFacts()
	if err != nil {
		a.fail(w, r, problem.New(problem.Unavailable, "Failed to collect host network facts."))
		return
	}
	if facts.Addresses == nil {
		facts.Addresses = []netfacts.AddressFact{}
	}
	a.writeResource(w, r, http.StatusOK, facts, nil)
}

func (a *api) loadNetworkPolicy(ctx context.Context) (networkPolicyDTO, error) {
	nodeID := a.d.NodeID
	dto := networkPolicyDTO{
		NodeID:            nodeID,
		InboundFamilyMode: netfacts.ModePreferIPv4,
		InboundCandidates: []netfacts.EndpointCandidate{},
		OutboundFamily:    netfacts.ModePreferIPv4,
		OutboundOverrides: []routingrules.OutboundDomainOverride{},
		Revision:          "0",
	}
	var candJSON, ovJSON string
	err := a.d.DB.View(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
SELECT inbound_family_mode, inbound_candidates_json, outbound_family_mode,
       outbound_bind_ipv4, outbound_bind_ipv6, outbound_overrides_json,
       revision, updated_at
FROM node_network_policies WHERE node_id = ?`, nodeID).Scan(
			&dto.InboundFamilyMode, &candJSON, &dto.OutboundFamily,
			&dto.OutboundBindIPv4, &dto.OutboundBindIPv6, &ovJSON,
			&dto.Revision, &dto.UpdatedAt,
		)
	})
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return dto, problem.Wrap(err)
	}
	if candJSON != "" {
		_ = json.Unmarshal([]byte(candJSON), &dto.InboundCandidates)
	}
	if ovJSON != "" {
		_ = json.Unmarshal([]byte(ovJSON), &dto.OutboundOverrides)
	}
	if dto.InboundCandidates == nil {
		dto.InboundCandidates = []netfacts.EndpointCandidate{}
	}
	if dto.OutboundOverrides == nil {
		dto.OutboundOverrides = []routingrules.OutboundDomainOverride{}
	}

	dto.EffectiveOutbound = string(dto.OutboundFamily)
	if facts, ferr := a.collectFacts(); ferr == nil {
		if dto.OutboundFamily == netfacts.ModePreferIPv6 && !facts.HasDefaultRouteV6 {
			dto.EffectiveOutbound = "ipv4_only (fallback: no_v6_route)"
			dto.Warnings = append(dto.Warnings, "本机缺少可用 IPv6 默认出站路由，已降级为 IPv4 出站")
		}
	}
	return dto, nil
}

// getNetworkPolicy 实现 GET /api/v1/network/policy。
func (a *api) getNetworkPolicy(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.system:read", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	dto, err := a.loadNetworkPolicy(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, dto, nil)
}

// putNetworkPolicy 实现 PUT /api/v1/network/policy。
func (a *api) putNetworkPolicy(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.system:write", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	var req putNetworkPolicyRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	if !netfacts.ValidFamilyMode(req.InboundFamilyMode) || !netfacts.ValidFamilyMode(req.OutboundFamily) {
		a.fail(w, r, problem.New(problem.ValidationFailed, "Invalid inbound or outbound family mode."))
		return
	}
	if len(req.InboundCandidates) > 32 || len(req.OutboundOverrides) > 128 {
		a.fail(w, r, problem.New(problem.ValidationFailed, "Too many inbound candidates or outbound overrides."))
		return
	}
	for _, c := range req.InboundCandidates {
		if strings.TrimSpace(c.ID) == "" || strings.TrimSpace(c.Host) == "" || c.Port < 1024 {
			a.fail(w, r, problem.New(problem.ValidationFailed, "Each inbound candidate requires id, host and port >= 1024."))
			return
		}
	}
	for _, ov := range req.OutboundOverrides {
		if strings.TrimSpace(ov.DomainSuffix) == "" || !netfacts.ValidFamilyMode(netfacts.FamilyMode(ov.Mode)) {
			a.fail(w, r, problem.New(problem.ValidationFailed, "Each outbound override requires domain_suffix and valid family mode."))
			return
		}
	}
	if !req.SkipFactsGuard {
		facts, ferr := a.collectFacts()
		if ferr == nil {
			if verr := netfacts.ValidateOutboundAgainstFacts(req.OutboundFamily, strings.TrimSpace(req.OutboundBindIPv4), strings.TrimSpace(req.OutboundBindIPv6), facts); verr != nil {
				if strings.Contains(verr.Error(), "PRECONDITION_FAILED") {
					a.fail(w, r, problem.New(problem.PreconditionFailed, "%s", verr.Error()))
				} else {
					a.fail(w, r, problem.New(problem.ValidationFailed, "%s", verr.Error()))
				}
				return
			}
		}
	}

	if req.InboundCandidates == nil {
		req.InboundCandidates = []netfacts.EndpointCandidate{}
	}
	if req.OutboundOverrides == nil {
		req.OutboundOverrides = []routingrules.OutboundDomainOverride{}
	}
	candBytes, _ := json.Marshal(req.InboundCandidates)
	ovBytes, _ := json.Marshal(req.OutboundOverrides)
	nowMs := a.d.Clock.Now().UTC().UnixMilli()
	newRev := makeNetworkRevision(candBytes, ovBytes, string(req.InboundFamilyMode), string(req.OutboundFamily), nowMs)

	err = a.d.DB.Update(r.Context(), func(tx *storage.Tx) error {
		var curRev string
		qerr := tx.QueryRowContext(r.Context(), `SELECT revision FROM node_network_policies WHERE node_id = ?`, a.d.NodeID).Scan(&curRev)
		if errors.Is(qerr, sql.ErrNoRows) {
			curRev = "0"
		} else if qerr != nil {
			return qerr
		}
		if req.ExpectedRevision != "" && req.ExpectedRevision != curRev {
			return problem.New(problem.RevisionConflict, "Network policy revision conflict.")
		}
		_, err := tx.ExecContext(r.Context(), `
INSERT INTO node_network_policies (
	node_id, inbound_family_mode, inbound_candidates_json, outbound_family_mode,
	outbound_bind_ipv4, outbound_bind_ipv6, outbound_overrides_json, revision, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(node_id) DO UPDATE SET
	inbound_family_mode = excluded.inbound_family_mode,
	inbound_candidates_json = excluded.inbound_candidates_json,
	outbound_family_mode = excluded.outbound_family_mode,
	outbound_bind_ipv4 = excluded.outbound_bind_ipv4,
	outbound_bind_ipv6 = excluded.outbound_bind_ipv6,
	outbound_overrides_json = excluded.outbound_overrides_json,
	revision = excluded.revision,
	updated_at = excluded.updated_at`,
			a.d.NodeID, string(req.InboundFamilyMode), string(candBytes), string(req.OutboundFamily),
			strings.TrimSpace(req.OutboundBindIPv4), strings.TrimSpace(req.OutboundBindIPv6),
			string(ovBytes), newRev, nowMs,
		)
		return err
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	dto, err := a.loadNetworkPolicy(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, dto, nil)
}

func (a *api) loadRoutingProfile(ctx context.Context) (routingProfileDTO, error) {
	ver, sum, count := a.routing.BundleInfo()
	dto := routingProfileDTO{
		ID:              defaultRoutingProfileID,
		Name:            "默认中国分流策略",
		Mode:            routingrules.ModeRuleCNSplit,
		BlockAds:        true,
		DNSAntiPoison:   true,
		BundleVersion:   ver,
		BundleSHA256:    sum,
		BundleRuleCount: count,
		CustomRules:     []routingrules.CustomRule{},
		Revision:        "0",
	}
	var blockAds, dnsAnti int
	var rulesJSON string
	err := a.d.DB.View(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
SELECT name, mode, block_ads, dns_anti_poison, bundle_version, bundle_sha256, custom_rules_json, revision, updated_at
FROM client_routing_profiles WHERE id = ?`, defaultRoutingProfileID).Scan(
			&dto.Name, &dto.Mode, &blockAds, &dnsAnti,
			&dto.BundleVersion, &dto.BundleSHA256, &rulesJSON, &dto.Revision, &dto.UpdatedAt,
		)
	})
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return dto, problem.Wrap(err)
	}
	if err == nil {
		dto.BlockAds = blockAds == 1
		dto.DNSAntiPoison = dnsAnti == 1
		if rulesJSON != "" {
			_ = json.Unmarshal([]byte(rulesJSON), &dto.CustomRules)
		}
	}
	if dto.CustomRules == nil {
		dto.CustomRules = []routingrules.CustomRule{}
	}
	dto.BundleRuleCount = count
	return dto, nil
}

// getRoutingProfile 实现 GET /api/v1/routing/profile。
func (a *api) getRoutingProfile(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.system:read", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	dto, err := a.loadRoutingProfile(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, dto, nil)
}

// putRoutingProfile 实现 PUT /api/v1/routing/profile。
func (a *api) putRoutingProfile(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.system:write", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	var req putRoutingProfileRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	if !routingrules.ValidProfileMode(req.Mode) {
		a.fail(w, r, problem.New(problem.ValidationFailed, "Invalid routing profile mode."))
		return
	}
	if err := routingrules.ValidateCustomRules(req.CustomRules); err != nil {
		a.fail(w, r, problem.New(problem.ValidationFailed, "%s", err.Error()))
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "默认中国分流策略"
	}
	if req.CustomRules == nil {
		req.CustomRules = []routingrules.CustomRule{}
	}
	rulesBytes, _ := json.Marshal(req.CustomRules)
	ver, sum, _ := a.routing.BundleInfo()
	nowMs := a.d.Clock.Now().UTC().UnixMilli()
	newRev := makeNetworkRevision(rulesBytes, []byte(name), string(req.Mode), ver, nowMs)

	blockAdsInt := 0
	if req.BlockAds {
		blockAdsInt = 1
	}
	dnsAntiInt := 0
	if req.DNSAntiPoison {
		dnsAntiInt = 1
	}

	err = a.d.DB.Update(r.Context(), func(tx *storage.Tx) error {
		var curRev string
		qerr := tx.QueryRowContext(r.Context(), `SELECT revision FROM client_routing_profiles WHERE id = ?`, defaultRoutingProfileID).Scan(&curRev)
		if errors.Is(qerr, sql.ErrNoRows) {
			curRev = "0"
		} else if qerr != nil {
			return qerr
		}
		if req.ExpectedRevision != "" && req.ExpectedRevision != curRev {
			return problem.New(problem.RevisionConflict, "Routing profile revision conflict.")
		}
		_, err := tx.ExecContext(r.Context(), `
INSERT INTO client_routing_profiles (
	id, name, mode, block_ads, dns_anti_poison, bundle_version, bundle_sha256, custom_rules_json, revision, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	name = excluded.name,
	mode = excluded.mode,
	block_ads = excluded.block_ads,
	dns_anti_poison = excluded.dns_anti_poison,
	bundle_version = excluded.bundle_version,
	bundle_sha256 = excluded.bundle_sha256,
	custom_rules_json = excluded.custom_rules_json,
	revision = excluded.revision,
	updated_at = excluded.updated_at`,
			defaultRoutingProfileID, name, string(req.Mode), blockAdsInt, dnsAntiInt,
			ver, sum, string(rulesBytes), newRev, nowMs,
		)
		return err
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	dto, err := a.loadRoutingProfile(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, dto, nil)
}

// postRoutingUpdateBundle 实现 POST /api/v1/routing/update-bundle。
func (a *api) postRoutingUpdateBundle(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.system:write", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	var req updateRoutingBundleRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	req.Version = strings.TrimSpace(req.Version)
	if req.Version == "" || len(req.BundleText) == 0 {
		a.fail(w, r, problem.New(problem.ValidationFailed, "version and bundle_text are required."))
		return
	}
	var bundlePath string
	if a.d.Config.DataDir != "" {
		bundlePath = filepath.Join(a.d.Config.DataDir, "qwq-cn-rules.bundle")
	}
	compiled, err := a.routing.AtomicSwapBundle(bundlePath, req.Version, []byte(req.BundleText), strings.TrimSpace(req.ExpectedSHA256))
	if err != nil {
		a.fail(w, r, problem.New(problem.ValidationFailed, "%s", err.Error()))
		return
	}
	_, _, count := a.routing.BundleInfo()
	nowMs := a.d.Clock.Now().UTC().UnixMilli()
	_ = a.d.DB.Update(r.Context(), func(tx *storage.Tx) error {
		_, uerr := tx.ExecContext(r.Context(),
			`UPDATE client_routing_profiles SET bundle_version = ?, bundle_sha256 = ?, updated_at = ? WHERE id = ?`,
			compiled.Version, compiled.SHA256, nowMs, defaultRoutingProfileID,
		)
		return uerr
	})
	a.writeResource(w, r, http.StatusOK, updateRoutingBundleResponse{
		Version:   compiled.Version,
		SHA256:    compiled.SHA256,
		RuleCount: count,
	}, nil)
}

// postRoutingPreview 实现 POST /api/v1/routing/preview（两跳全链路可视化预演器）。
func (a *api) postRoutingPreview(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.system:read", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	var req routingPreviewRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	req.Target = strings.TrimSpace(req.Target)
	if req.Target == "" || len(req.Target) > 300 {
		a.fail(w, r, problem.New(problem.ValidationFailed, "target is required and must be <= 300 characters."))
		return
	}

	profile, err := a.loadRoutingProfile(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	policy, err := a.loadNetworkPolicy(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}

	ordered := a.selector.PlanOrder(policy.InboundFamilyMode, policy.InboundCandidates, a.d.Clock.Now().UTC())
	endpoints := make([]string, 0, len(ordered))
	for _, c := range ordered {
		endpoints = append(endpoints, net.JoinHostPort(strings.Trim(c.Host, "[]"), strconv.Itoa(int(c.Port))))
	}

	preview := a.routing.PreviewTwoHop(
		req.Target,
		profile.Mode,
		profile.BlockAds,
		profile.CustomRules,
		string(policy.InboundFamilyMode),
		endpoints,
		string(policy.OutboundFamily),
		policy.OutboundBindIPv4,
		policy.OutboundBindIPv6,
		policy.OutboundOverrides,
	)
	a.writeResource(w, r, http.StatusOK, preview, nil)
}

func makeNetworkRevision(a, b []byte, s1, s2 string, tsMs int64) string {
	h := sha256.New()
	_, _ = h.Write(a)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(b)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(s1 + "\x00" + s2 + "\x00" + strconv.FormatInt(tsMs, 10)))
	return "net_" + hex.EncodeToString(h.Sum(nil))[:16]
}
