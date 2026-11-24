// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ContainerIngressLink 维护稳定容器名与 web.ingress 站点的双向持久化绑定。
type ContainerIngressLink struct {
	ID               string `json:"id"`
	ContainerName    string `json:"container_name"`
	StackName        string `json:"stack_name,omitempty"`
	ServiceName      string `json:"service_name,omitempty"`
	ContainerPort    uint16 `json:"container_port"`
	HostBindIP       string `json:"host_bind_ip"`
	HostPort         uint16 `json:"host_port"`
	UpstreamScheme   string `json:"upstream_scheme"`
	UpstreamInsecure bool   `json:"upstream_insecure"`
	IngressSiteID    string `json:"ingress_site_id"`
	Domain           string `json:"domain"`
	PathPrefix       string `json:"path_prefix"`
	TLSMode          string `json:"tls_mode"`
	CertID           string `json:"cert_id,omitempty"`
	MaxBodyMB        int    `json:"max_body_mb"`
	UpdatedAt        int64  `json:"updated_at"`
}

func normalizeContainerName(name string) string {
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(name), "/"))
}

func newDockerID(prefix string) string {
	var b [8]byte
	_, _ = io.ReadFull(rand.Reader, b[:])
	return prefix + "_" + hex.EncodeToString(b[:])
}

// pluginInvoker 抽象宿主跨插件调用（兼容 invoke 与 job 两种操作模式，便于单测注入）。
type pluginInvoker interface {
	Invoke(ctx context.Context, targetPlugin, operation, apiVersion string, payload []byte) ([]byte, error)
}

type hostPluginInvoker struct {
	host *pluginsdk.Host
}

func newHostPluginInvoker(host *pluginsdk.Host) pluginInvoker {
	if host == nil || host.Conn() == nil {
		return nil
	}
	return hostPluginInvoker{host: host}
}

func (h hostPluginInvoker) Invoke(ctx context.Context, targetPlugin, operation, apiVersion string, payload []byte) ([]byte, error) {
	if h.host == nil || h.host.Conn() == nil {
		return nil, errors.New("plugin unavailable: host connection not initialized")
	}
	if len(payload) == 0 {
		payload = []byte(`{}`)
	}
	resp, err := h.host.InvokePlugin(ctx, pluginsdk.InvokeRequest{
		TargetPluginID:   targetPlugin,
		TargetInstanceID: "default",
		Operation:        operation,
		APIVersion:       apiVersion,
		Payload:          payload,
	})
	if err != nil {
		return nil, err
	}
	if e := resp.GetError(); e != nil && e.GetCode() != "" {
		return nil, fmt.Errorf("%s: %s", e.GetCode(), e.GetMessage())
	}
	// 对 mode=job 的跨插件操作（例如 tls.certificates/certificates.list 或 certificates.issue），等待其进入终态。
	if opID := resp.GetOperationId(); opID != "" && len(resp.GetPayloadJson()) == 0 {
		switch resp.GetState() {
		case platformv1.OperationState_OPERATION_STATE_PENDING,
			platformv1.OperationState_OPERATION_STATE_APPROVED,
			platformv1.OperationState_OPERATION_STATE_RUNNING:
			final, werr := h.host.AwaitOperation(ctx, opID)
			if werr != nil {
				return nil, werr
			}
			switch final.GetState() {
			case platformv1.OperationState_OPERATION_STATE_SUCCEEDED:
				return final.GetResultJson(), nil
			case platformv1.OperationState_OPERATION_STATE_AWAITING_APPROVAL:
				return nil, errors.New("APPROVAL_REQUIRED: 目标插件操作等待审批确认")
			default:
				if fe := final.GetError(); fe != nil && fe.GetCode() != "" {
					return nil, fmt.Errorf("%s: %s", fe.GetCode(), fe.GetMessage())
				}
				return nil, fmt.Errorf("TARGET_OPERATION_FAILED: %s/%s 未成功完成", targetPlugin, operation)
			}
		case platformv1.OperationState_OPERATION_STATE_AWAITING_APPROVAL:
			return nil, errors.New("APPROVAL_REQUIRED: 目标插件操作等待审批确认")
		}
	}
	return resp.GetPayloadJson(), nil
}

// CertCandidate 描述可用于容器 HTTPS 反代复用的托管证书（含泛域名证书）。
type CertCandidate struct {
	CertID           string   `json:"cert_id"`
	Domains          []string `json:"domains"`
	Issuer           string   `json:"issuer"`
	ExpiresAt        string   `json:"expires_at"`
	IsWildcard       bool     `json:"is_wildcard"`
	LatestGeneration int      `json:"latest_generation,omitempty"`
}

// ProxyIntegrationReadiness 描述 web.ingress / tls.certificates / domain.dns 联动组件的就绪状态。
type ProxyIntegrationReadiness struct {
	IngressInstalled bool            `json:"ingress_installed"`
	IngressRunning   bool            `json:"ingress_running"`
	CertsInstalled   bool            `json:"certs_installed"`
	DNSInstalled     bool            `json:"dns_installed"`
	MissingPlugins   []string        `json:"missing_plugins"`
	AvailableCerts   []CertCandidate `json:"available_certs"`
}

// ProbeProxyIntegrationStatus 只读探测反代、证书与 DNS 组件安装状态并拉取可复用证书清单。
func ProbeProxyIntegrationStatus(ctx context.Context, host *pluginsdk.Host) ProxyIntegrationReadiness {
	return probeProxyIntegrationStatusWithInvoker(ctx, newHostPluginInvoker(host))
}

func probeProxyIntegrationStatusWithInvoker(ctx context.Context, inv pluginInvoker) ProxyIntegrationReadiness {
	res := ProxyIntegrationReadiness{
		MissingPlugins: make([]string, 0, 2),
		AvailableCerts: make([]CertCandidate, 0),
	}
	if inv == nil {
		res.MissingPlugins = []string{"web.ingress", "tls.certificates"}
		return res
	}

	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// 1. 探测 web.ingress (ingress.overview)
	if raw, err := inv.Invoke(probeCtx, "web.ingress", "ingress.overview", "v1", []byte(`{}`)); err == nil {
		res.IngressInstalled = true
		var ov struct {
			Running        *bool  `json:"running"`
			BoundAddr      string `json:"bound_addr"`
			HTTPSBoundAddr string `json:"https_bound_addr"`
		}
		_ = json.Unmarshal(raw, &ov)
		if ov.Running != nil {
			res.IngressRunning = *ov.Running
		} else {
			res.IngressRunning = ov.BoundAddr != "" || ov.HTTPSBoundAddr != ""
		}
	} else if !isPluginMissingErr(err) {
		res.IngressInstalled = true
	} else {
		res.MissingPlugins = append(res.MissingPlugins, "web.ingress")
	}

	// 2. 探测 tls.certificates (certificates.list，对齐真实 schemas/certificates.list.response.json)
	if raw, err := inv.Invoke(probeCtx, "tls.certificates", "certificates.list", "v1", []byte(`{}`)); err == nil {
		res.CertsInstalled = true
		var list struct {
			Certificates []struct {
				ID               string   `json:"id"`
				SANs             []string `json:"sans"`
				Domains          []string `json:"domains"`
				Issuer           string   `json:"issuer"`
				NotAfter         string   `json:"not_after"`
				Status           string   `json:"status"`
				LatestGeneration int      `json:"latest_generation"`
				Generations      []struct {
					Number   int    `json:"number"`
					Issuer   string `json:"issuer"`
					NotAfter string `json:"not_after"`
				} `json:"generations"`
				Bindings []struct {
					BindingRef string `json:"binding_ref"`
					PluginID   string `json:"plugin_id"`
				} `json:"bindings"`
			} `json:"certificates"`
		}
		if json.Unmarshal(raw, &list) == nil {
			for _, c := range list.Certificates {
				if c.ID == "" {
					continue
				}
				domains := c.SANs
				if len(domains) == 0 {
					domains = c.Domains
				}
				issuer := c.Issuer
				expiresAt := c.NotAfter
				if len(c.Generations) > 0 {
					chosen := c.Generations[len(c.Generations)-1]
					for _, g := range c.Generations {
						if g.Number == c.LatestGeneration {
							chosen = g
							break
						}
					}
					if chosen.Issuer != "" {
						issuer = chosen.Issuer
					}
					if chosen.NotAfter != "" {
						expiresAt = chosen.NotAfter
					}
				}
				certRef := c.ID
				for _, b := range c.Bindings {
					if b.PluginID == "web.ingress" && strings.TrimSpace(b.BindingRef) != "" {
						certRef = strings.TrimSpace(b.BindingRef)
						break
					}
				}
				wild := false
				for _, d := range domains {
					if strings.HasPrefix(d, "*.") {
						wild = true
						break
					}
				}
				res.AvailableCerts = append(res.AvailableCerts, CertCandidate{
					CertID:           certRef,
					Domains:          domains,
					Issuer:           issuer,
					ExpiresAt:        expiresAt,
					IsWildcard:       wild,
					LatestGeneration: c.LatestGeneration,
				})
			}
		}
	} else if !isPluginMissingErr(err) {
		res.CertsInstalled = true
	} else {
		res.MissingPlugins = append(res.MissingPlugins, "tls.certificates")
	}

	// 3. 探测 domain.dns (providers.status)
	if _, err := inv.Invoke(probeCtx, "domain.dns", "providers.status", "v1", []byte(`{}`)); err == nil {
		res.DNSInstalled = true
	} else if !isPluginMissingErr(err) {
		res.DNSInstalled = true
	}

	return res
}

func isPluginMissingErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") ||
		strings.Contains(msg, "not installed") ||
		strings.Contains(msg, "unknown plugin") ||
		strings.Contains(msg, "unavailable") ||
		strings.Contains(msg, "not active")
}

// FindMatchingExistingCert 匹配精确域名或一级泛域名（*.example.com 覆盖 app.example.com，但不覆盖 a.b.example.com）。
func FindMatchingExistingCert(certs []CertCandidate, domain string) (string, bool) {
	dom := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if dom == "" {
		return "", false
	}
	for _, c := range certs {
		for _, san := range c.Domains {
			if strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(san), "."), dom) {
				return c.CertID, true
			}
		}
	}
	if dot := strings.IndexByte(dom, '.'); dot > 0 {
		rest := dom[dot+1:]
		// 仅匹配至少包含一个点号的一级泛域名（例如 *.example.com）
		if strings.Contains(rest, ".") {
			wantWild := "*." + rest
			for _, c := range certs {
				for _, san := range c.Domains {
					if strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(san), "."), wantWild) {
						return c.CertID, true
					}
				}
			}
		}
	}
	return "", false
}

var certSlugCleanRe = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// EnsureCertForContainerDomain 根据 cert_strategy 复用现有证书（含泛域名）或在提供 DNS 托管域时自动签发新证书。
func EnsureCertForContainerDomain(
	ctx context.Context,
	inv pluginInvoker,
	domain string,
	certStrategy string,
	existingCertID string,
	dnsProviderID string,
	dnsZoneID string,
	availableCerts []CertCandidate,
) (tlsMode string, certID string, warnings []string, err error) {
	switch strings.TrimSpace(certStrategy) {
	case "http_only":
		return "off", "", nil, nil
	case "existing_cert":
		cid := strings.TrimSpace(existingCertID)
		if cid == "" {
			return "", "", nil, errors.New("cert_strategy=existing_cert 时必须提供 existing_cert_id")
		}
		return "managed", cid, nil, nil
	case "", "auto_acme":
		if matched, ok := FindMatchingExistingCert(availableCerts, domain); ok {
			return "managed", matched, nil, nil
		}
		prov := strings.TrimSpace(dnsProviderID)
		zone := strings.TrimSpace(dnsZoneID)
		if inv != nil && prov != "" && zone != "" {
			slug := certSlugCleanRe.ReplaceAllString(strings.ToLower(strings.TrimSpace(domain)), "-")
			slug = strings.Trim(slug, "-.")
			if len(slug) > 48 {
				slug = slug[:48]
			}
			certReqID := "docker-" + slug
			issuePayload, _ := json.Marshal(map[string]any{
				"certificate_id": certReqID,
				"attempt_id":     newDockerID("att"),
				"spec": map[string]any{
					"sans":    []string{strings.ToLower(strings.TrimSpace(domain))},
					"purpose": "tls_server",
				},
				"provider_id":  prov,
				"zone_id":      zone,
				"ca":           "letsencrypt",
				"accept_terms": true,
			})
			raw, ierr := inv.Invoke(ctx, "tls.certificates", "certificates.issue", "v1", issuePayload)
			if ierr != nil {
				return "", "", nil, fmt.Errorf("自动签发 HTTPS 证书失败: %w", ierr)
			}
			var taskResp struct {
				Task struct {
					CertificateID string `json:"certificate_id"`
					Status        string `json:"status"`
					ErrorCode     string `json:"error_code"`
				} `json:"task"`
				Certificate *struct {
					ID string `json:"id"`
				} `json:"certificate"`
			}
			if json.Unmarshal(raw, &taskResp) == nil {
				if taskResp.Task.Status != "" && taskResp.Task.Status != "succeeded" {
					return "", "", nil, fmt.Errorf("证书签发未完成 (status=%s code=%s)", taskResp.Task.Status, taskResp.Task.ErrorCode)
				}
				if taskResp.Certificate != nil && taskResp.Certificate.ID != "" {
					return "managed", taskResp.Certificate.ID, nil, nil
				}
				if taskResp.Task.CertificateID != "" {
					return "managed", taskResp.Task.CertificateID, nil, nil
				}
			}
			return "managed", certReqID, nil, nil
		}
		return "managed", "", []string{
			"未匹配到现成证书且未指定 DNS 托管域，已启用 web.ingress 托管 TLS 模式；如需自动签发请在「TLS 证书」页使用 HTTP-01（免 DNS Token）或 DNS-01 签发并绑定。",
		}, nil
	default:
		return "", "", nil, fmt.Errorf("不支持的 cert_strategy %q", certStrategy)
	}
}

// BindCertificateToWebIngress 在拿到尚未物化绑定到 web.ingress 的 certificate_id 后，
// 调用 tls.certificates/bindings.bind 将证书投递至 web.ingress 隔离目录并返回稳定的 binding_ref。
func BindCertificateToWebIngress(ctx context.Context, inv pluginInvoker, certificateID, siteProfileID string, generation int) (string, error) {
	certificateID = strings.TrimSpace(certificateID)
	siteProfileID = strings.TrimSpace(siteProfileID)
	if inv == nil || certificateID == "" {
		return "", errors.New("绑定证书至 web.ingress 参数不完整")
	}
	if strings.HasPrefix(certificateID, "certbind_") {
		return certificateID, nil
	}
	if generation <= 0 {
		generation = 1
	}
	bindingRef := siteProfileID
	if !strings.HasPrefix(bindingRef, "certbind_") {
		slug := certSlugCleanRe.ReplaceAllString(strings.ToLower(siteProfileID), "-")
		slug = strings.Trim(slug, "-.")
		if slug == "" {
			slug = certificateID
		}
		if len(slug) > 48 {
			slug = slug[:48]
		}
		bindingRef = "certbind_" + slug
	}
	reqBytes, err := json.Marshal(map[string]any{
		"certificate_id": certificateID,
		"binding_ref":    bindingRef,
		"attempt_id":     newDockerID("bind"),
		"generation":     generation,
	})
	if err != nil {
		return "", err
	}
	raw, err := inv.Invoke(ctx, "tls.certificates", "bindings.bind", "v1", reqBytes)
	if err != nil {
		return "", fmt.Errorf("将证书 %s 投递绑定至反向代理网关失败: %w", certificateID, err)
	}
	var resp struct {
		BindingRef string `json:"binding_ref"`
		Binding    *struct {
			BindingRef string `json:"binding_ref"`
			ID         string `json:"id"`
		} `json:"binding"`
		Certificate *struct {
			Bindings []struct {
				BindingRef string `json:"binding_ref"`
				PluginID   string `json:"plugin_id"`
			} `json:"bindings"`
		} `json:"certificate"`
	}
	if json.Unmarshal(raw, &resp) == nil {
		if ref := strings.TrimSpace(resp.BindingRef); ref != "" {
			return ref, nil
		}
		if resp.Binding != nil {
			if ref := strings.TrimSpace(resp.Binding.BindingRef); ref != "" {
				return ref, nil
			}
			if ref := strings.TrimSpace(resp.Binding.ID); ref != "" {
				return ref, nil
			}
		}
		if resp.Certificate != nil {
			for _, b := range resp.Certificate.Bindings {
				if b.PluginID == "web.ingress" && strings.TrimSpace(b.BindingRef) != "" {
					return strings.TrimSpace(b.BindingRef), nil
				}
			}
		}
	}
	return bindingRef, nil
}

// ContainerProxyUpsertRequest 是 docker.container.proxy.upsert 的结构化入参（严格对齐 container-drawer.js）。
type ContainerProxyUpsertRequest struct {
	ContainerID               string                `json:"container_id"`
	ContainerPort             uint16                `json:"container_port"`
	UpstreamPortStrategy      string                `json:"upstream_port_strategy"`
	ExistingHostPort          uint16                `json:"existing_host_port,omitempty"`
	AutoClosePublicPort       bool                  `json:"auto_close_public_port,omitempty"`
	CommitWritableLayer       bool                  `json:"commit_writable_layer,omitempty"`
	AllowDiscardWritableLayer bool                  `json:"allow_discard_writable_layer,omitempty"`
	Domain                    string                `json:"domain"`
	PathPrefix                string                `json:"path_prefix"`
	UpstreamScheme            string                `json:"upstream_scheme"`
	UpstreamInsecure          bool                  `json:"upstream_insecure"`
	WebSocket                 *bool                 `json:"websocket,omitempty"`
	MaxBodyMB                 int                   `json:"max_body_mb"`
	RateLimitRPS              int                   `json:"rate_limit_rps"`
	BasicAuthUser             string                `json:"basic_auth_user"`
	BasicAuthPass             pluginsdk.SecretField `json:"basic_auth_pass"`
	ClearBasicAuth            bool                  `json:"clear_basic_auth"`
	CertStrategy              string                `json:"cert_strategy"`
	ExistingCertID            string                `json:"existing_cert_id,omitempty"`
	DNSProviderID             string                `json:"dns_provider_id,omitempty"`
	DNSZoneID                 string                `json:"dns_zone_id,omitempty"`
}

type resolvedProxyTarget struct {
	ContainerName string
	StackName     string
	ServiceName   string
	ContainerPort uint16
	HostBindIP    string
	HostPort      uint16
}

// ======================== container_ingress_links SQLite CRUD ========================

func ListContainerIngressLinks(ctx context.Context, db *sql.DB, containerName string) ([]ContainerIngressLink, error) {
	cleanName := normalizeContainerName(containerName)
	rows, err := db.QueryContext(ctx, `
		SELECT id, container_name, stack_name, service_name, container_port, host_bind_ip, host_port,
		       upstream_scheme, upstream_insecure, ingress_site_id, domain, path_prefix, tls_mode, cert_id, max_body_mb, updated_at
		FROM container_ingress_links
		WHERE container_name = ?
		ORDER BY domain ASC, path_prefix ASC
	`, cleanName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ContainerIngressLink, 0)
	for rows.Next() {
		var l ContainerIngressLink
		var insec int
		if err := rows.Scan(
			&l.ID, &l.ContainerName, &l.StackName, &l.ServiceName, &l.ContainerPort, &l.HostBindIP, &l.HostPort,
			&l.UpstreamScheme, &insec, &l.IngressSiteID, &l.Domain, &l.PathPrefix, &l.TLSMode, &l.CertID, &l.MaxBodyMB, &l.UpdatedAt,
		); err != nil {
			return nil, err
		}
		l.UpstreamInsecure = insec == 1
		out = append(out, l)
	}
	return out, rows.Err()
}

func ListAllContainerIngressLinksByName(ctx context.Context, db *sql.DB) (map[string][]ContainerIngressLink, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, container_name, stack_name, service_name, container_port, host_bind_ip, host_port,
		       upstream_scheme, upstream_insecure, ingress_site_id, domain, path_prefix, tls_mode, cert_id, max_body_mb, updated_at
		FROM container_ingress_links
		ORDER BY container_name ASC, domain ASC, path_prefix ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string][]ContainerIngressLink)
	for rows.Next() {
		var l ContainerIngressLink
		var insec int
		if err := rows.Scan(
			&l.ID, &l.ContainerName, &l.StackName, &l.ServiceName, &l.ContainerPort, &l.HostBindIP, &l.HostPort,
			&l.UpstreamScheme, &insec, &l.IngressSiteID, &l.Domain, &l.PathPrefix, &l.TLSMode, &l.CertID, &l.MaxBodyMB, &l.UpdatedAt,
		); err != nil {
			return nil, err
		}
		l.UpstreamInsecure = insec == 1
		key := normalizeContainerName(l.ContainerName)
		out[key] = append(out[key], l)
	}
	return out, rows.Err()
}

func GetContainerIngressLinkByID(ctx context.Context, db *sql.DB, linkID string) (ContainerIngressLink, bool, error) {
	var l ContainerIngressLink
	var insec int
	err := db.QueryRowContext(ctx, `
		SELECT id, container_name, stack_name, service_name, container_port, host_bind_ip, host_port,
		       upstream_scheme, upstream_insecure, ingress_site_id, domain, path_prefix, tls_mode, cert_id, max_body_mb, updated_at
		FROM container_ingress_links
		WHERE id = ?
	`, strings.TrimSpace(linkID)).Scan(
		&l.ID, &l.ContainerName, &l.StackName, &l.ServiceName, &l.ContainerPort, &l.HostBindIP, &l.HostPort,
		&l.UpstreamScheme, &insec, &l.IngressSiteID, &l.Domain, &l.PathPrefix, &l.TLSMode, &l.CertID, &l.MaxBodyMB, &l.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ContainerIngressLink{}, false, nil
	}
	if err != nil {
		return ContainerIngressLink{}, false, err
	}
	l.UpstreamInsecure = insec == 1
	return l, true, nil
}

func SaveContainerIngressLink(ctx context.Context, db *sql.DB, l ContainerIngressLink) (ContainerIngressLink, error) {
	l.ContainerName = normalizeContainerName(l.ContainerName)
	l.Domain = strings.ToLower(strings.TrimSpace(l.Domain))
	if strings.TrimSpace(l.PathPrefix) == "" {
		l.PathPrefix = "/"
	}
	if l.UpstreamScheme == "" {
		l.UpstreamScheme = "http"
	}
	if l.HostBindIP == "" {
		l.HostBindIP = "127.0.0.1"
	}
	nowUnix := time.Now().Unix()
	l.UpdatedAt = nowUnix

	insecInt := 0
	if l.UpstreamInsecure {
		insecInt = 1
	}

	var existingID string
	_ = db.QueryRowContext(ctx, `SELECT id FROM container_ingress_links WHERE domain = ? AND path_prefix = ?`, l.Domain, l.PathPrefix).Scan(&existingID)
	if existingID != "" {
		l.ID = existingID
		_, err := db.ExecContext(ctx, `
			UPDATE container_ingress_links
			SET container_name = ?, stack_name = ?, service_name = ?, container_port = ?,
			    host_bind_ip = ?, host_port = ?, upstream_scheme = ?, upstream_insecure = ?,
			    ingress_site_id = ?, tls_mode = ?, cert_id = ?, max_body_mb = ?, updated_at = ?
			WHERE id = ?
		`, l.ContainerName, l.StackName, l.ServiceName, l.ContainerPort,
			l.HostBindIP, l.HostPort, l.UpstreamScheme, insecInt,
			l.IngressSiteID, l.TLSMode, l.CertID, l.MaxBodyMB, nowUnix, l.ID)
		return l, err
	}
	if l.ID == "" {
		l.ID = newDockerID("cil")
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO container_ingress_links
		(id, container_name, stack_name, service_name, container_port, host_bind_ip, host_port,
		 upstream_scheme, upstream_insecure, ingress_site_id, domain, path_prefix, tls_mode, cert_id, max_body_mb, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, l.ID, l.ContainerName, l.StackName, l.ServiceName, l.ContainerPort, l.HostBindIP, l.HostPort,
		l.UpstreamScheme, insecInt, l.IngressSiteID, l.Domain, l.PathPrefix, l.TLSMode, l.CertID, l.MaxBodyMB, nowUnix, nowUnix)
	return l, err
}

// UpsertContainerProxyAndCert 编排证书、写入 web.ingress 站点、热重载并落库 container_ingress_links。
func UpsertContainerProxyAndCert(
	ctx context.Context,
	db *sql.DB,
	inv pluginInvoker,
	host *pluginsdk.Host,
	req ContainerProxyUpsertRequest,
	target resolvedProxyTarget,
) (ContainerIngressLink, []string, error) {
	if inv == nil {
		return ContainerIngressLink{}, nil, errors.New("宿主跨插件调用不可用，无法配置 web.ingress 反向代理")
	}
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if domain == "" {
		return ContainerIngressLink{}, nil, errors.New("绑定域名 domain 不能为空")
	}
	pathPrefix := strings.TrimSpace(req.PathPrefix)
	if pathPrefix == "" {
		pathPrefix = "/"
	}
	scheme := strings.ToLower(strings.TrimSpace(req.UpstreamScheme))
	if scheme == "" {
		scheme = "http"
	}
	if scheme != "http" && scheme != "https" {
		return ContainerIngressLink{}, nil, errors.New("upstream_scheme 仅支持 http 或 https")
	}
	if req.MaxBodyMB < 0 || req.MaxBodyMB > 102400 {
		return ContainerIngressLink{}, nil, errors.New("max_body_mb 超出允许范围 (0..102400)")
	}
	if req.RateLimitRPS < 0 || req.RateLimitRPS > 10000 {
		return ContainerIngressLink{}, nil, errors.New("rate_limit_rps 超出允许范围 (0..10000)")
	}
	if target.HostPort == 0 || target.ContainerPort == 0 {
		return ContainerIngressLink{}, nil, errors.New("未能确定容器对应的宿主机转发端口")
	}

	readiness := probeProxyIntegrationStatusWithInvoker(ctx, inv)
	if !readiness.IngressInstalled {
		return ContainerIngressLink{}, nil, errors.New("WEB_INGRESS_NOT_INSTALLED: 尚未安装或启用 web.ingress 组件")
	}

	tlsMode, certID, warnings, err := EnsureCertForContainerDomain(
		ctx, inv, domain, req.CertStrategy, req.ExistingCertID, req.DNSProviderID, req.DNSZoneID, readiness.AvailableCerts,
	)
	if err != nil {
		return ContainerIngressLink{}, warnings, err
	}
	if tlsMode != "off" && certID != "" && !strings.HasPrefix(certID, "certbind_") {
		siteProfileID := "docker-" + normalizeContainerName(target.ContainerName)
		gen := 1
		for _, c := range readiness.AvailableCerts {
			if c.CertID == certID && c.LatestGeneration > 0 {
				gen = c.LatestGeneration
				break
			}
		}
		boundRef, berr := BindCertificateToWebIngress(ctx, inv, certID, siteProfileID, gen)
		if berr != nil {
			warnings = append(warnings, "证书已就绪，但自动绑定至 web.ingress 失败（"+berr.Error()+"）；站点已先以 HTTP 模式上线以防 HTTPS 不可访问，请在「TLS 证书 → 消费者部署绑定」完成绑定后再开启 HTTPS。")
			certID = ""
			tlsMode = "off"
		} else {
			certID = boundRef
		}
	}
	if !readiness.IngressRunning {
		warnings = append(warnings, "检测到 web.ingress 当前未成功监听 80/443 端口（可能存在端口冲突或未启用），请前往「反向代理」页检查监听状态。")
	}

	dialHost := strings.TrimSpace(target.HostBindIP)
	if dialHost == "" || dialHost == "0.0.0.0" || dialHost == "::" {
		dialHost = "127.0.0.1"
	}
	upstreamURL := fmt.Sprintf("%s://%s:%d", scheme, dialHost, target.HostPort)

	wsEnabled := true
	if req.WebSocket != nil {
		wsEnabled = *req.WebSocket
	}
	forceHTTPS := tlsMode != "off" && certID != ""

	var existingSiteID string
	_ = db.QueryRowContext(ctx,
		`SELECT ingress_site_id FROM container_ingress_links WHERE domain = ? AND path_prefix = ?`,
		domain, pathPrefix,
	).Scan(&existingSiteID)

	upsertBody := map[string]any{
		"domain":                domain,
		"enabled":               true,
		"upstream_url":          upstreamURL,
		"path_prefix":           pathPrefix,
		"websocket":             wsEnabled,
		"tls_mode":              tlsMode,
		"force_https":           forceHTTPS,
		"upstream_tls_insecure": req.UpstreamInsecure && scheme == "https",
		"max_body_mb":           req.MaxBodyMB,
		"rate_limit_rps":        req.RateLimitRPS,
		"notes":                 "docker:" + normalizeContainerName(target.ContainerName),
	}
	if existingSiteID != "" {
		upsertBody["id"] = existingSiteID
	}
	if certID != "" {
		upsertBody["cert_id"] = certID
	}
	if u := strings.TrimSpace(req.BasicAuthUser); u != "" {
		upsertBody["basic_auth_user"] = u
	}
	if req.ClearBasicAuth {
		upsertBody["clear_basic_auth"] = true
	} else if !req.BasicAuthPass.IsEmpty() {
		plainPass, keepExisting, rerr := req.BasicAuthPass.ResolveString(ctx, host, "docker.container.proxy.upsert")
		if rerr != nil {
			return ContainerIngressLink{}, warnings, fmt.Errorf("解析 basic_auth_pass 凭据失败: %w", rerr)
		}
		if !keepExisting && plainPass != "" {
			upsertBody["basic_auth_pass"] = plainPass
		}
	}

	payload, _ := json.Marshal(upsertBody)
	upsertRaw, err := inv.Invoke(ctx, "web.ingress", "ingress.site.upsert", "v1", payload)
	if err != nil {
		return ContainerIngressLink{}, warnings, fmt.Errorf("写入 web.ingress 反代站点失败: %w", err)
	}
	var upsertResp struct {
		Site struct {
			ID string `json:"id"`
		} `json:"site"`
	}
	if json.Unmarshal(upsertRaw, &upsertResp) != nil || upsertResp.Site.ID == "" {
		return ContainerIngressLink{}, warnings, errors.New("web.ingress 未返回有效的站点 ID")
	}

	if _, err := inv.Invoke(ctx, "web.ingress", "ingress.apply", "v1", []byte(`{}`)); err != nil {
		warnings = append(warnings, "站点已保存，但热重载 ingress.apply 告警: "+err.Error())
	}

	link, err := SaveContainerIngressLink(ctx, db, ContainerIngressLink{
		ContainerName:    target.ContainerName,
		StackName:        target.StackName,
		ServiceName:      target.ServiceName,
		ContainerPort:    target.ContainerPort,
		HostBindIP:       dialHost,
		HostPort:         target.HostPort,
		UpstreamScheme:   scheme,
		UpstreamInsecure: req.UpstreamInsecure && scheme == "https",
		IngressSiteID:    upsertResp.Site.ID,
		Domain:           domain,
		PathPrefix:       pathPrefix,
		TLSMode:          tlsMode,
		CertID:           certID,
		MaxBodyMB:        req.MaxBodyMB,
	})
	return link, warnings, err
}

// PortTarget 描述容器端口变更后对应的宿主机目标地址。
type PortTarget struct {
	BindIP   string
	HostPort uint16
}

// SyncContainerProxyAfterPortChange 在容器端口变更后自动同步更新关联 web.ingress 上游地址，避免出现 502。
func SyncContainerProxyAfterPortChange(
	ctx context.Context,
	db *sql.DB,
	inv pluginInvoker,
	containerName string,
	portMap map[uint16]PortTarget,
) (int, error) {
	links, err := ListContainerIngressLinks(ctx, db, containerName)
	if err != nil {
		return 0, err
	}
	if len(links) == 0 {
		return 0, nil
	}

	type existingIngressSite struct {
		ID             string            `json:"id"`
		Enabled        *bool             `json:"enabled"`
		WebSocket      *bool             `json:"websocket"`
		ForceHTTPS     *bool             `json:"force_https"`
		RateLimitRPS   int               `json:"rate_limit_rps"`
		RateLimitBurst int               `json:"rate_limit_burst"`
		ExtraHeaders   map[string]string `json:"extra_headers"`
	}
	existingSites := make(map[string]existingIngressSite)
	if inv != nil {
		if raw, oerr := inv.Invoke(ctx, "web.ingress", "ingress.overview", "v1", []byte(`{}`)); oerr == nil && len(raw) > 0 {
			var ov struct {
				Sites []existingIngressSite `json:"sites"`
			}
			if json.Unmarshal(raw, &ov) == nil {
				for _, s := range ov.Sites {
					if s.ID != "" {
						existingSites[s.ID] = s
					}
				}
			}
		}
	}

	updated := 0
	nowUnix := time.Now().Unix()
	for _, l := range links {
		nextTarget, exists := portMap[l.ContainerPort]
		if !exists || nextTarget.HostPort == 0 {
			continue
		}
		dialHost := strings.TrimSpace(nextTarget.BindIP)
		if dialHost == "" || dialHost == "0.0.0.0" || dialHost == "::" {
			dialHost = "127.0.0.1"
		}
		if dialHost == l.HostBindIP && nextTarget.HostPort == l.HostPort {
			continue
		}
		newUpstream := fmt.Sprintf("%s://%s:%d", l.UpstreamScheme, dialHost, nextTarget.HostPort)
		enabled := true
		websocket := true
		forceHTTPS := l.TLSMode != "off"
		prev, hasPrev := existingSites[l.IngressSiteID]
		if hasPrev {
			if prev.Enabled != nil {
				enabled = *prev.Enabled
			}
			if prev.WebSocket != nil {
				websocket = *prev.WebSocket
			}
			if prev.ForceHTTPS != nil {
				forceHTTPS = *prev.ForceHTTPS
			}
		}
		upsertBody := map[string]any{
			"id":                    l.IngressSiteID,
			"domain":                l.Domain,
			"enabled":               enabled,
			"path_prefix":           l.PathPrefix,
			"upstream_url":          newUpstream,
			"websocket":             websocket,
			"tls_mode":              l.TLSMode,
			"force_https":           forceHTTPS,
			"upstream_tls_insecure": l.UpstreamInsecure,
			"max_body_mb":           l.MaxBodyMB,
			"notes":                 "docker:" + l.ContainerName,
		}
		if l.CertID != "" {
			upsertBody["cert_id"] = l.CertID
		}
		if hasPrev {
			if prev.RateLimitRPS > 0 {
				upsertBody["rate_limit_rps"] = prev.RateLimitRPS
			}
			if prev.RateLimitBurst > 0 {
				upsertBody["rate_limit_burst"] = prev.RateLimitBurst
			}
			if len(prev.ExtraHeaders) > 0 {
				upsertBody["extra_headers"] = prev.ExtraHeaders
			}
		}
		upsertPayload, _ := json.Marshal(upsertBody)
		if inv != nil {
			if _, err := inv.Invoke(ctx, "web.ingress", "ingress.site.upsert", "v1", upsertPayload); err != nil {
				return updated, err
			}
		}
		if _, err := db.ExecContext(ctx,
			`UPDATE container_ingress_links SET host_bind_ip = ?, host_port = ?, updated_at = ? WHERE id = ?`,
			dialHost, nextTarget.HostPort, nowUnix, l.ID); err != nil {
			return updated, err
		}
		updated++
	}
	if updated > 0 && inv != nil {
		_, _ = inv.Invoke(ctx, "web.ingress", "ingress.apply", "v1", []byte(`{}`))
	}
	return updated, nil
}

// DeleteContainerProxy 解绑并删除单条容器反向代理关联及对应 web.ingress 站点。
func DeleteContainerProxy(ctx context.Context, db *sql.DB, inv pluginInvoker, linkID string) (bool, error) {
	link, found, err := GetContainerIngressLinkByID(ctx, db, linkID)
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	if inv != nil && link.IngressSiteID != "" {
		delPayload, _ := json.Marshal(map[string]string{"id": link.IngressSiteID})
		if _, err := inv.Invoke(ctx, "web.ingress", "ingress.site.delete", "v1", delPayload); err != nil && !isPluginMissingErr(err) {
			return false, fmt.Errorf("删除 web.ingress 站点失败: %w", err)
		}
		_, _ = inv.Invoke(ctx, "web.ingress", "ingress.apply", "v1", []byte(`{}`))
	}
	_, err = db.ExecContext(ctx, `DELETE FROM container_ingress_links WHERE id = ?`, link.ID)
	return err == nil, err
}

// CleanupProxiesForContainer 在删除容器时按开关同步清理关联的 web.ingress 站点，杜绝僵尸 502 规则。
func CleanupProxiesForContainer(ctx context.Context, db *sql.DB, inv pluginInvoker, containerName string) (int, error) {
	links, err := ListContainerIngressLinks(ctx, db, containerName)
	if err != nil {
		return 0, err
	}
	return cleanupProxyLinkSlice(ctx, db, inv, links)
}

// CleanupProxiesForStack 在删除 Compose 栈时同步清理归属该栈的全部关联反代站点。
func CleanupProxiesForStack(ctx context.Context, db *sql.DB, inv pluginInvoker, stackName string) (int, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, ingress_site_id
		FROM container_ingress_links
		WHERE stack_name = ?
	`, strings.TrimSpace(stackName))
	if err != nil {
		return 0, err
	}
	var links []ContainerIngressLink
	for rows.Next() {
		var l ContainerIngressLink
		if err := rows.Scan(&l.ID, &l.IngressSiteID); err == nil {
			links = append(links, l)
		}
	}
	_ = rows.Close()
	return cleanupProxyLinkSlice(ctx, db, inv, links)
}

func cleanupProxyLinkSlice(ctx context.Context, db *sql.DB, inv pluginInvoker, links []ContainerIngressLink) (int, error) {
	if len(links) == 0 {
		return 0, nil
	}
	removed := 0
	for _, l := range links {
		if inv != nil && l.IngressSiteID != "" {
			delPayload, _ := json.Marshal(map[string]string{"id": l.IngressSiteID})
			_, _ = inv.Invoke(ctx, "web.ingress", "ingress.site.delete", "v1", delPayload)
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM container_ingress_links WHERE id = ?`, l.ID); err != nil {
			return removed, err
		}
		removed++
	}
	if removed > 0 && inv != nil {
		_, _ = inv.Invoke(ctx, "web.ingress", "ingress.apply", "v1", []byte(`{}`))
	}
	return removed, nil
}

// ======================== 受管 Compose `ports:` 精准无损改写器 ========================

// FormatComposePortItems 将结构化端口规则格式化为标准 Docker Compose 短语法字符串。
func FormatComposePortItems(rules []PortMappingRule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		protos := []string{strings.ToLower(strings.TrimSpace(r.Protocol))}
		if protos[0] == "both" {
			protos = []string{"tcp", "udp"}
		} else if protos[0] == "" {
			protos = []string{"tcp"}
		}
		for _, p := range protos {
			switch r.BindMode {
			case "public":
				if r.HostPort > 0 {
					out = append(out, fmt.Sprintf(`"0.0.0.0:%d:%d/%s"`, r.HostPort, r.ContainerPort, p))
					if r.IncludeIPv6 {
						out = append(out, fmt.Sprintf(`"[::]:%d:%d/%s"`, r.HostPort, r.ContainerPort, p))
					}
				} else {
					out = append(out, fmt.Sprintf(`"%d/%s"`, r.ContainerPort, p))
				}
			case "specific_ip":
				ip := strings.TrimSpace(r.BindIP)
				if strings.Contains(ip, ":") && !strings.HasPrefix(ip, "[") {
					ip = "[" + ip + "]"
				}
				if r.HostPort > 0 {
					out = append(out, fmt.Sprintf(`"%s:%d:%d/%s"`, ip, r.HostPort, r.ContainerPort, p))
				} else {
					out = append(out, fmt.Sprintf(`"%s::%d/%s"`, ip, r.ContainerPort, p))
				}
			default: // loopback
				if r.HostPort > 0 {
					out = append(out, fmt.Sprintf(`"127.0.0.1:%d:%d/%s"`, r.HostPort, r.ContainerPort, p))
					if r.IncludeIPv6 {
						out = append(out, fmt.Sprintf(`"[::1]:%d:%d/%s"`, r.HostPort, r.ContainerPort, p))
					}
				} else {
					out = append(out, fmt.Sprintf(`"127.0.0.1::%d/%s"`, r.ContainerPort, p))
				}
			}
		}
	}
	return out
}

// RewriteComposeServicePorts 在不破坏 compose.yml 其余服务、挂载卷、环境变量与注释的前提下，
// 精准替换 services.<targetService>.ports 列表块（若原服务无 ports: 则自动插入在服务定义首行下方）。
func RewriteComposeServicePorts(rawYAML string, targetService string, formattedPortSpecs []string) (string, error) {
	if strings.TrimSpace(targetService) == "" {
		return "", errors.New("target compose service name is empty")
	}
	lines := strings.Split(strings.ReplaceAll(rawYAML, "\r\n", "\n"), "\n")

	inServices := false
	servicesIndent := -1
	inTargetSvc := false
	svcIndent := -1
	svcHeaderIdx := -1
	portsStartIdx := -1
	portsEndIdx := -1
	portsIndent := -1

	for idx, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		ind := len(ln) - len(strings.TrimLeft(ln, " "))

		if !inServices {
			if trimmed == "services:" || strings.HasPrefix(trimmed, "services:") {
				inServices = true
				servicesIndent = ind
			}
			continue
		}
		if ind <= servicesIndent && !strings.HasPrefix(trimmed, "-") {
			if inTargetSvc && portsStartIdx >= 0 && portsEndIdx < 0 {
				portsEndIdx = idx
			}
			inServices = false
			inTargetSvc = false
			continue
		}

		if !inTargetSvc {
			if strings.HasSuffix(trimmed, ":") && trimmed == targetService+":" {
				inTargetSvc = true
				svcIndent = ind
				svcHeaderIdx = idx
			}
			continue
		}

		if ind <= svcIndent && !strings.HasPrefix(trimmed, "-") {
			if portsStartIdx >= 0 && portsEndIdx < 0 {
				portsEndIdx = idx
			}
			inTargetSvc = false
			continue
		}

		if portsStartIdx < 0 {
			if trimmed == "ports:" || strings.HasPrefix(trimmed, "ports:") {
				portsStartIdx = idx
				portsIndent = ind
				rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "ports:"))
				if rest != "" && !strings.HasPrefix(rest, "#") {
					portsEndIdx = idx + 1
				}
			}
		} else if portsEndIdx < 0 {
			if ind <= portsIndent && !strings.HasPrefix(trimmed, "-") {
				portsEndIdx = idx
			}
		}
	}

	if svcHeaderIdx < 0 {
		return "", fmt.Errorf("SERVICE_NOT_FOUND_IN_COMPOSE: 未在 compose.yml 中找到服务 %q", targetService)
	}
	if portsStartIdx >= 0 && portsEndIdx < 0 {
		portsEndIdx = len(lines)
	}

	propIndent := svcIndent + 2
	if portsIndent > svcIndent {
		propIndent = portsIndent
	}
	padProp := strings.Repeat(" ", propIndent)
	padItem := strings.Repeat(" ", propIndent+2)

	var newPortsBlock []string
	if len(formattedPortSpecs) > 0 {
		newPortsBlock = append(newPortsBlock, padProp+"ports:")
		for _, sp := range formattedPortSpecs {
			newPortsBlock = append(newPortsBlock, padItem+"- "+sp)
		}
	}

	var result []string
	if portsStartIdx >= 0 {
		result = append(result, lines[:portsStartIdx]...)
		result = append(result, newPortsBlock...)
		result = append(result, lines[portsEndIdx:]...)
	} else {
		insertAt := svcHeaderIdx + 1
		result = append(result, lines[:insertAt]...)
		result = append(result, newPortsBlock...)
		result = append(result, lines[insertAt:]...)
	}
	cleaned := slices.DeleteFunc(result, func(string) bool { return false })
	return strings.Join(cleaned, "\n"), nil
}
