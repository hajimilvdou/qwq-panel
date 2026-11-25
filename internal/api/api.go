// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/agentsession"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/catalog"
	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/netfacts"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/panelaccess"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/trust"
	"github.com/qwq-panel/qwq/internal/privateexport"
	"github.com/qwq-panel/qwq/internal/routingrules"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// Deps are the host services the handlers use. internal/controller passes the
// values it already assembled; nothing is constructed here.
type Deps struct {
	Config   config.Config
	DB       *storage.DB
	Clock    clock.Clock
	IDs      *ids.Generator
	Logger   *slog.Logger
	Identity *identity.Service
	Authz    *authz.Authorizer
	Ops      *operations.Service
	Catalog  *catalog.Catalog
	Secrets  *secrets.Store
	TLS      *tlsmgr.Manager
	// PrivateExports 只给原人类会话交付一次生成材料；不经普通 operation JSON 返回。
	PrivateExports *privateexport.Service
	// AgentSessions is the native agent session backend. The host (cmd/qwq)
	// builds it on the controller and passes it here so tool calls run through
	// operations. When it is nil, Register builds a minimal service for tests
	// and hosts without the operation wiring: it can chat, but every tool call
	// answers UNAVAILABLE because there is no runner.
	AgentSessions *agentsession.Service
	// Plugins is the optional plugin package lifecycle (install, update,
	// rollback, configuration and the version list). The production adapter
	// wraps internal/pluginhost/updater. A nil value is a host without an
	// updater: those routes answer 503 PLUGIN_UNAVAILABLE, while the list stays
	// empty and one plugin is NOT_FOUND.
	Plugins PluginManager
	// PluginUploads stages package uploads until they are installed. It is
	// required for the upload, install and update routes; nil disables them
	// with 503.
	PluginUploads *PluginUploads
	// PluginTrust manages official + custom trusted publisher Ed25519 keys.
	// Nil disables mutating trust-key routes with 503 while GET returns an empty list.
	PluginTrust *trust.CompositeTrustStore
	// PackageFetchTransport optionally overrides the HTTP transport used by
	// POST /api/v1/plugin-packages/fetch (tests only). Nil uses the production
	// SSRF-blocking HTTPS transport.
	PackageFetchTransport http.RoundTripper
	// NodeID is the node this host manages; a standalone installation uses
	// "local".
	NodeID string
	// NetFacts optionally overrides host network fact collection (used in tests).
	NetFacts func() (netfacts.HostNetworkFacts, error)
	// NodeRevoker optionally notifies the live cluster server to disconnect a revoked node.
	NodeRevoker func(nodeID string)
	// ClusterCAHash optionally provides the cluster root CA SPKI SHA-256 pin for enrollment tokens.
	ClusterCAHash func() string
	// Access manages the live panel listening port, secret entry path, disguise,
	// and reverse-proxy domain auto-disable policy.
	Access *panelaccess.Manager
	// ConfigPath is the path to qwq.json used by backup/support-bundle endpoints.
	ConfigPath string
	// PrivilegedSocket is the path to qwq-privileged's Unix socket used by backup staging.
	PrivilegedSocket string
	// OnPluginCatalogFunc optionally receives the live official plugin catalog
	// provider function so host AI read tools share the HTTP catalog cache.
	OnPluginCatalogFunc func(func(ctx context.Context, refresh bool) (any, error))
}

// withDefaults validates the required services and fills the optional ones.
func (d *Deps) withDefaults() error {
	switch {
	case d == nil:
		return errors.New("api: nil deps")
	case d.DB == nil:
		return errors.New("api: nil database")
	case d.Identity == nil:
		return errors.New("api: nil identity service")
	case d.Authz == nil:
		return errors.New("api: nil authorizer")
	case d.Ops == nil:
		return errors.New("api: nil operation manager")
	case d.Catalog == nil:
		return errors.New("api: nil action catalog")
	}
	if d.Clock == nil {
		d.Clock = clock.System{}
	}
	if d.IDs == nil {
		d.IDs = ids.New(d.Clock.Now)
	}
	if d.Logger == nil {
		d.Logger = slog.New(slog.DiscardHandler)
	}
	if d.NodeID == "" {
		d.NodeID = "local"
	}
	if d.PrivateExports == nil && d.Secrets != nil {
		service, err := privateexport.New(privateexport.Options{DB: d.DB, Secrets: d.Secrets, Clock: d.Clock, IDs: d.IDs, NodeID: d.NodeID, Authorize: privateexport.CatalogAuthorization(d.Catalog, d.Authz)})
		if err != nil {
			return err
		}
		d.PrivateExports = service
	}
	if d.AgentSessions == nil {
		// The default service keeps the routes usable (a native session can
		// chat) without a runner or a catalog: tool calls answer UNAVAILABLE
		// until the host wires them.
		idSvc := d.Identity
		azSvc := d.Authz
		svc, err := agentsession.New(agentsession.Options{
			DB: d.DB, Clock: d.Clock, IDs: d.IDs, Logger: d.Logger, Secrets: d.Secrets, DataDir: d.Config.DataDir,
			RoleResolver: func(rctx context.Context, owner actor.Actor) (string, error) {
				switch owner.Kind {
				case actor.System:
					return string(authz.RoleAdmin), nil
				case actor.Human:
					role, disabled, rerr := idSvc.PrincipalRole(rctx, owner.ID)
					if rerr != nil {
						return "", problem.From(rerr)
					}
					if disabled {
						return "", problem.New(problem.PermissionDenied, "The user account is disabled.")
					}
					return role, nil
				case actor.Service:
					sa, rerr := azSvc.ServiceAccount(rctx, owner.ID)
					if rerr != nil {
						return "", problem.From(rerr)
					}
					if sa.Disabled {
						return "", problem.New(problem.PermissionDenied, "The service account is disabled.")
					}
					return string(sa.Role), nil
				default:
					return "", problem.New(problem.PermissionDenied, "Unsupported session owner.")
				}
			},
		})
		if err != nil {
			return err
		}
		d.AgentSessions = svc
	}
	if d.Access == nil {
		boot := d.Config.HTTP
		if boot.Listen == "" {
			boot = config.Default().HTTP
		}
		mgr, err := panelaccess.NewManager(context.Background(), panelaccess.Options{
			DB:        d.DB,
			Clock:     d.Clock,
			Bootstrap: boot,
		})
		if err != nil {
			return err
		}
		d.Access = mgr
	}
	return nil
}

// api is the handler set bound to one gateway.
type api struct {
	g  *gateway.Gateway
	d  Deps
	id *replayCache
	// inspections caches package inspections per upload id until the upload
	// expires (GAPS gap 4).
	inspections *inspectionCache
	// widgets holds the refresh floor and the in-flight reservation of every
	// widget read (GAPS gap 7).
	widgets *widgetReads
	// catalogCache caches the official GitHub Release plugins-index.json for 5 minutes.
	catalogCache cachedPluginCatalog
	// startedAt stands in for the node's created_at: a standalone node is the
	// host process (see nodes.go).
	startedAt      time.Time
	routing        *routingrules.Engine
	selector       *netfacts.CandidateSelector
	netFactsFn     func() (netfacts.HostNetworkFacts, error)
	trustedProxies []netip.Prefix
	totpRebindMu   sync.Mutex
	totpRebinds    map[string]time.Time
	backupMu       sync.Mutex
}

// Register adds every route of the public API to g and registers the host
// actions of the catalog on the operation manager. It must be called once,
// before the gateway serves.
func Register(g *gateway.Gateway, d Deps) error {
	if g == nil {
		return errors.New("api: nil gateway")
	}
	if err := d.withDefaults(); err != nil {
		return err
	}
	a := &api{g: g, d: d, id: newReplayCache(d.Clock), inspections: newInspectionCache(d.Clock),
		widgets: newWidgetReads(), startedAt: d.Clock.Now().UTC(),
		routing: routingrules.NewEngine(nil), selector: netfacts.NewCandidateSelector(),
		netFactsFn:     d.NetFacts,
		trustedProxies: panelaccess.ParseTrustedProxies(d.Config.HTTP.TrustedProxies),
		totpRebinds:    make(map[string]time.Time)}
	a.registerHostActions()
	if d.OnPluginCatalogFunc != nil {
		d.OnPluginCatalogFunc(a.pluginCatalogSnapshot)
	}
	for _, rt := range a.routes() {
		if err := g.Handle(rt); err != nil {
			return fmt.Errorf("api: %w", err)
		}
	}
	return nil
}

// routes is the method+path table of the OpenAPI document, minus /healthz,
// /readyz, GET /api/v1/events (owned by the gateway) and /api/v1/agent/* (P1-T8).
func (a *api) routes() []gateway.Route {
	sessionOrService := gateway.AccessSessionOrService
	return []gateway.Route{
		// setup
		{Method: http.MethodGet, Pattern: "/api/v1/setup", Access: gateway.AccessPublic, Handler: http.HandlerFunc(a.getSetup)},
		{Method: http.MethodPost, Pattern: "/api/v1/setup", Access: gateway.AccessPublic, Body: gateway.BodyJSON, Handler: http.HandlerFunc(a.postSetup)},
		// sessions
		{Method: http.MethodPost, Pattern: "/api/v1/sessions", Access: gateway.AccessPublic, Body: gateway.BodyJSON, Handler: http.HandlerFunc(a.createSession)},
		{Method: http.MethodPost, Pattern: "/api/v1/sessions/mfa", Access: gateway.AccessPublic, Body: gateway.BodyJSON, Handler: http.HandlerFunc(a.verifySessionMFA)},
		{Method: http.MethodGet, Pattern: "/api/v1/sessions/current", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.currentSession)},
		{Method: http.MethodDelete, Pattern: "/api/v1/sessions/current", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.deleteSession)},
		// account self-service (AUTH-07)
		{Method: http.MethodPost, Pattern: "/api/v1/sessions/current/mfa/totp", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.beginTOTP)},
		{Method: http.MethodPost, Pattern: "/api/v1/sessions/current/mfa/totp/confirm", Access: gateway.AccessSession, Body: gateway.BodyJSON, Handler: http.HandlerFunc(a.confirmTOTP)},
		{Method: http.MethodPost, Pattern: "/api/v1/sessions/current/mfa/totp/disable", Access: gateway.AccessSession, Body: gateway.BodyJSON, Handler: http.HandlerFunc(a.disableTOTP)},
		{Method: http.MethodPatch, Pattern: "/api/v1/sessions/current/profile", Access: gateway.AccessSession, Body: gateway.BodyJSON, RequireIdempotency: true, Handler: http.HandlerFunc(a.updateProfile)},
		{Method: http.MethodPut, Pattern: "/api/v1/sessions/current/password", Access: gateway.AccessSession, Body: gateway.BodyJSON, Handler: http.HandlerFunc(a.changePassword)},
		{Method: http.MethodPost, Pattern: "/api/v1/enrollments", Access: gateway.AccessPublic, Body: gateway.BodyJSON, Handler: http.HandlerFunc(a.redeemEnrollment)},
		// 私密材料准备/交付属于人类会话凭据流程；每步审计，消耗不做响应重放。
		{Method: http.MethodPost, Pattern: "/api/v1/private-exports", Access: gateway.AccessSession, Body: gateway.BodyJSON, Handler: http.HandlerFunc(a.preparePrivateExport)},
		{Method: http.MethodPost, Pattern: "/api/v1/private-exports/{export_id}/consume", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.consumePrivateExport)},
		{Method: http.MethodDelete, Pattern: "/api/v1/private-exports/{export_id}", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.cancelPrivateExport)},
		// users
		{Method: http.MethodGet, Pattern: "/api/v1/users", Access: sessionOrService, Handler: http.HandlerFunc(a.listUsers)},
		{Method: http.MethodPost, Pattern: "/api/v1/users", Access: sessionOrService, Body: gateway.BodyJSON, RequireIdempotency: true, Handler: http.HandlerFunc(a.createUser)},
		{Method: http.MethodGet, Pattern: "/api/v1/users/{user_id}", Access: sessionOrService, Handler: http.HandlerFunc(a.getUser)},
		{Method: http.MethodPatch, Pattern: "/api/v1/users/{user_id}", Access: sessionOrService, Body: gateway.BodyJSON, RequireIdempotency: true, Handler: http.HandlerFunc(a.updateUser)},
		{Method: http.MethodDelete, Pattern: "/api/v1/users/{user_id}", Access: sessionOrService, RequireIdempotency: true, Handler: http.HandlerFunc(a.deleteUser)},
		{Method: http.MethodPost, Pattern: "/api/v1/users/{user_id}/enrollment-token", Access: gateway.AccessSession, Body: gateway.BodyJSON, RequireIdempotency: true, Handler: http.HandlerFunc(a.issueEnrollmentToken)},
		// service accounts (Track 06 general CRUD + renewal bootstrap)
		{Method: http.MethodGet, Pattern: "/api/v1/service-accounts", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.listServiceAccounts)},
		{Method: http.MethodPost, Pattern: "/api/v1/service-accounts", Access: gateway.AccessSession, Body: gateway.BodyJSON, RequireIdempotency: true, Handler: http.HandlerFunc(a.createServiceAccount)},
		{Method: http.MethodDelete, Pattern: "/api/v1/service-accounts/{service_id}", Access: gateway.AccessSession, RequireIdempotency: true, Handler: http.HandlerFunc(a.deleteServiceAccount)},
		// 续期账号创建沿统一高风险 operation，执行时复核当前真人。
		{Method: http.MethodPost, Pattern: "/api/v1/service-accounts/renewal-bootstrap", Access: gateway.AccessSession, Body: gateway.BodyJSON, RequireIdempotency: true, Handler: http.HandlerFunc(a.bootstrapRenewalService)},
		// delegations
		{Method: http.MethodGet, Pattern: "/api/v1/delegations", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.listDelegations)},
		{Method: http.MethodPost, Pattern: "/api/v1/delegations", Access: gateway.AccessSession, Body: gateway.BodyJSON, RequireIdempotency: true, Handler: http.HandlerFunc(a.createDelegation)},
		{Method: http.MethodGet, Pattern: "/api/v1/delegations/{delegation_id}", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.getDelegation)},
		{Method: http.MethodPatch, Pattern: "/api/v1/delegations/{delegation_id}", Access: gateway.AccessSession, Body: gateway.BodyJSON, RequireIdempotency: true, Handler: http.HandlerFunc(a.updateDelegation)},
		{Method: http.MethodDelete, Pattern: "/api/v1/delegations/{delegation_id}", Access: gateway.AccessSession, RequireIdempotency: true, Handler: http.HandlerFunc(a.deleteDelegation)},
		// nodes (standalone local + P4 multi-node cluster enrollment & revocation)
		{Method: http.MethodGet, Pattern: "/api/v1/nodes", Access: sessionOrService, Handler: http.HandlerFunc(a.listNodes)},
		{Method: http.MethodPost, Pattern: "/api/v1/nodes/enrollment-tokens", Access: gateway.AccessSession, Body: gateway.BodyJSON, RequireIdempotency: true, Handler: http.HandlerFunc(a.createNodeEnrollmentToken)},
		{Method: http.MethodGet, Pattern: "/api/v1/nodes/{node_id}", Access: sessionOrService, Handler: http.HandlerFunc(a.getNode)},
		{Method: http.MethodPost, Pattern: "/api/v1/nodes/{node_id}/revoke", Access: gateway.AccessSession, RequireIdempotency: true, Handler: http.HandlerFunc(a.revokeNode)},
		// plugins
		{Method: http.MethodGet, Pattern: "/api/v1/plugins", Access: sessionOrService, Handler: http.HandlerFunc(a.listPlugins)},
		{Method: http.MethodPost, Pattern: "/api/v1/plugins", Access: sessionOrService, Body: gateway.BodyJSON, RequireIdempotency: true, Handler: http.HandlerFunc(a.installPlugin)},
		{Method: http.MethodGet, Pattern: "/api/v1/plugins/{plugin_id}", Access: sessionOrService, Handler: http.HandlerFunc(a.getPlugin)},
		{Method: http.MethodDelete, Pattern: "/api/v1/plugins/{plugin_id}", Access: sessionOrService, RequireIdempotency: true, Handler: http.HandlerFunc(a.uninstallPlugin)},
		{Method: http.MethodPost, Pattern: "/api/v1/plugins/{plugin_id}/update", Access: sessionOrService, Body: gateway.BodyJSON, RequireIdempotency: true, Handler: http.HandlerFunc(a.updatePlugin)},
		{Method: http.MethodPost, Pattern: "/api/v1/plugins/{plugin_id}/rollback", Access: sessionOrService, RequireIdempotency: true, Handler: http.HandlerFunc(a.rollbackPlugin)},
		{Method: http.MethodPost, Pattern: "/api/v1/plugins/{plugin_id}/restart", Access: sessionOrService, RequireIdempotency: true, Handler: http.HandlerFunc(a.restartPlugin)},
		{Method: http.MethodPost, Pattern: "/api/v1/plugins/{plugin_id}/enable", Access: sessionOrService, RequireIdempotency: true, Handler: http.HandlerFunc(a.enablePlugin)},
		{Method: http.MethodPost, Pattern: "/api/v1/plugins/{plugin_id}/disable", Access: sessionOrService, RequireIdempotency: true, Handler: http.HandlerFunc(a.disablePlugin)},
		{Method: http.MethodGet, Pattern: "/api/v1/plugins/{plugin_id}/config", Access: sessionOrService, Handler: http.HandlerFunc(a.getPluginConfig)},
		{Method: http.MethodPut, Pattern: "/api/v1/plugins/{plugin_id}/config", Access: sessionOrService, Body: gateway.BodyJSON, RequireIdempotency: true, Handler: http.HandlerFunc(a.putPluginConfig)},
		{Method: http.MethodGet, Pattern: "/api/v1/plugins/{plugin_id}/config-schema", Access: sessionOrService, Handler: http.HandlerFunc(a.getPluginConfigSchema)},
		{Method: http.MethodGet, Pattern: "/api/v1/plugins/{plugin_id}/logs", Access: sessionOrService, Handler: http.HandlerFunc(a.getPluginLogs)},
		{Method: http.MethodPost, Pattern: "/api/v1/plugin-packages", Access: sessionOrService, Body: gateway.BodyPackage, Handler: http.HandlerFunc(a.uploadPluginPackage)},
		{Method: http.MethodPost, Pattern: "/api/v1/plugin-packages/fetch", Access: sessionOrService, Body: gateway.BodyJSON, Handler: http.HandlerFunc(a.fetchPluginPackage)},
		{Method: http.MethodGet, Pattern: "/api/v1/plugin-packages/{upload_id}", Access: sessionOrService, Handler: http.HandlerFunc(a.inspectPluginPackage)},
		{Method: http.MethodDelete, Pattern: "/api/v1/plugin-packages/{upload_id}", Access: sessionOrService, Handler: http.HandlerFunc(a.deletePluginPackage)},
		{Method: http.MethodGet, Pattern: "/api/v1/plugin-catalog", Access: sessionOrService, Handler: http.HandlerFunc(a.getPluginCatalog)},
		{Method: http.MethodGet, Pattern: "/api/v1/plugin-trust-keys", Access: sessionOrService, Handler: http.HandlerFunc(a.listPluginTrustKeys)},
		{Method: http.MethodPost, Pattern: "/api/v1/plugin-trust-keys", Access: gateway.AccessSession, Body: gateway.BodyJSON, Handler: http.HandlerFunc(a.addPluginTrustKey)},
		{Method: http.MethodDelete, Pattern: "/api/v1/plugin-trust-keys/{key_id}", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.deletePluginTrustKey)},
		{Method: http.MethodPost, Pattern: "/api/v1/plugins/{plugin_id}/operations/{operation}", Access: sessionOrService, Body: gateway.BodyPluginJSON, Handler: http.HandlerFunc(a.invokeControllerPlugin)},
		{Method: http.MethodPost, Pattern: "/api/v1/nodes/{node_id}/plugins/{plugin_id}/instances/{instance_id}/operations/{operation}", Access: sessionOrService, Body: gateway.BodyPluginJSON, Handler: http.HandlerFunc(a.invokeNodePlugin)},
		// operations
		{Method: http.MethodGet, Pattern: "/api/v1/operations", Access: sessionOrService, Handler: http.HandlerFunc(a.listOperations)},
		{Method: http.MethodGet, Pattern: "/api/v1/operations/{operation_id}", Access: sessionOrService, Handler: http.HandlerFunc(a.getOperation)},
		{Method: http.MethodPost, Pattern: "/api/v1/operations/{operation_id}/cancel", Access: sessionOrService, RequireIdempotency: true, Handler: http.HandlerFunc(a.cancelOperation)},
		// plans
		{Method: http.MethodPost, Pattern: "/api/v1/plans", Access: sessionOrService, Body: gateway.BodyPluginJSON, Handler: http.HandlerFunc(a.createPlan)},
		{Method: http.MethodGet, Pattern: "/api/v1/plans/{plan_id}", Access: sessionOrService, Handler: http.HandlerFunc(a.getPlan)},
		{Method: http.MethodPost, Pattern: "/api/v1/plans/{plan_id}/execute", Access: sessionOrService, RequireIdempotency: true, Handler: http.HandlerFunc(a.executePlan)},
		// approvals
		{Method: http.MethodGet, Pattern: "/api/v1/approvals", Access: sessionOrService, Handler: http.HandlerFunc(a.listApprovals)},
		{Method: http.MethodGet, Pattern: "/api/v1/approvals/{approval_id}", Access: sessionOrService, Handler: http.HandlerFunc(a.getApproval)},
		{Method: http.MethodPost, Pattern: "/api/v1/approvals/{approval_id}/decision", Access: gateway.AccessSession, Body: gateway.BodyJSON, RequireIdempotency: true, Handler: http.HandlerFunc(a.decideApproval)},
		// action catalog for people (GAP-5)
		{Method: http.MethodGet, Pattern: "/api/v1/actions", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.listActions)},
		{Method: http.MethodGet, Pattern: "/api/v1/actions/{action_id}", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.getAction)},
		// audit log (GAP-7)
		{Method: http.MethodGet, Pattern: "/api/v1/audit", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.listAudit)},
		// system overview (GAP-7), live panel access / stealth disguise & backup/support-bundle
		{Method: http.MethodGet, Pattern: "/api/v1/system", Access: sessionOrService, Handler: http.HandlerFunc(a.getSystem)},
		{Method: http.MethodGet, Pattern: "/api/v1/system/access", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.getSystemAccess)},
		{Method: http.MethodPut, Pattern: "/api/v1/system/access", Access: gateway.AccessSession, Body: gateway.BodyJSON, Handler: http.HandlerFunc(a.putSystemAccess)},
		{Method: http.MethodGet, Pattern: "/api/v1/system/backups", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.listSystemBackups)},
		{Method: http.MethodPost, Pattern: "/api/v1/system/backups", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.createSystemBackup)},
		{Method: http.MethodGet, Pattern: "/api/v1/system/backups/{filename}", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.downloadSystemBackup)},
		{Method: http.MethodPost, Pattern: "/api/v1/system/support-bundle", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.createSystemSupportBundle)},
		// dual-stack network policy and MIT China routing rules (Track 05, ADR-0027)
		{Method: http.MethodGet, Pattern: "/api/v1/network/facts", Access: sessionOrService, Handler: http.HandlerFunc(a.getNetworkFacts)},
		{Method: http.MethodGet, Pattern: "/api/v1/network/policy", Access: sessionOrService, Handler: http.HandlerFunc(a.getNetworkPolicy)},
		{Method: http.MethodPut, Pattern: "/api/v1/network/policy", Access: sessionOrService, Body: gateway.BodyJSON, Handler: http.HandlerFunc(a.putNetworkPolicy)},
		{Method: http.MethodGet, Pattern: "/api/v1/routing/profile", Access: sessionOrService, Handler: http.HandlerFunc(a.getRoutingProfile)},
		{Method: http.MethodPut, Pattern: "/api/v1/routing/profile", Access: sessionOrService, Body: gateway.BodyJSON, Handler: http.HandlerFunc(a.putRoutingProfile)},
		{Method: http.MethodPost, Pattern: "/api/v1/routing/update-bundle", Access: sessionOrService, Body: gateway.BodyJSON, Handler: http.HandlerFunc(a.postRoutingUpdateBundle)},
		{Method: http.MethodPost, Pattern: "/api/v1/routing/preview", Access: sessionOrService, Body: gateway.BodyJSON, Handler: http.HandlerFunc(a.postRoutingPreview)},
		// agent sessions (ADR-0010 A2)
		{Method: http.MethodGet, Pattern: "/api/v1/agent-sessions", Access: sessionOrService, Handler: a.agentSessionRoute(a.listAgentSessions)},
		{Method: http.MethodPost, Pattern: "/api/v1/agent-sessions", Access: sessionOrService, Body: gateway.BodyJSON, Handler: a.agentSessionRoute(a.createAgentSession)},
		{Method: http.MethodGet, Pattern: "/api/v1/agent-sessions/{session_id}", Access: sessionOrService, Handler: a.agentSessionRoute(a.getAgentSession)},
		{Method: http.MethodPatch, Pattern: "/api/v1/agent-sessions/{session_id}", Access: sessionOrService, Body: gateway.BodyJSON, Handler: a.agentSessionRoute(a.updateAgentSession)},
		{Method: http.MethodDelete, Pattern: "/api/v1/agent-sessions/{session_id}", Access: sessionOrService, Handler: a.agentSessionRoute(a.deleteAgentSession)},
		{Method: http.MethodPut, Pattern: "/api/v1/agent-sessions/{session_id}/api-key", Access: sessionOrService, Body: gateway.BodyJSON, Handler: a.agentSessionRoute(a.putAgentSessionAPIKey)},
		{Method: http.MethodDelete, Pattern: "/api/v1/agent-sessions/{session_id}/api-key", Access: sessionOrService, Handler: a.agentSessionRoute(a.deleteAgentSessionAPIKey)},
		{Method: http.MethodPost, Pattern: "/api/v1/agent-sessions/{session_id}/messages", Access: sessionOrService, Body: gateway.BodyJSON, Handler: a.agentSessionRoute(a.sendAgentMessage)},
		{Method: http.MethodGet, Pattern: "/api/v1/agent-sessions/{session_id}/messages", Access: sessionOrService, Handler: a.agentSessionRoute(a.listAgentMessages)},
		{Method: http.MethodGet, Pattern: "/api/v1/agent-sessions/{session_id}/export", Access: sessionOrService, Handler: a.agentSessionRoute(a.exportAgentSession)},
		{Method: http.MethodPost, Pattern: "/api/v1/agent-sessions/{session_id}/cancel", Access: sessionOrService, Handler: a.agentSessionRoute(a.cancelAgentSession)},
		{Method: http.MethodGet, Pattern: "/api/v1/agent-sessions/{session_id}/events", Access: sessionOrService, Handler: a.agentSessionRoute(a.streamAgentSession)},
		{Method: http.MethodGet, Pattern: "/api/v1/agent-sessions/{session_id}/approvals", Access: sessionOrService, Handler: a.agentSessionRoute(a.listAgentApprovals)},
		// agent interactive file exchange folder
		{Method: http.MethodGet, Pattern: "/api/v1/agent-exchange/entries", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.listAgentExchangeEntries)},
		{Method: http.MethodPost, Pattern: "/api/v1/agent-exchange/mkdir", Access: gateway.AccessSession, Body: gateway.BodyJSON, Handler: http.HandlerFunc(a.mkdirAgentExchange)},
		{Method: http.MethodPost, Pattern: "/api/v1/agent-exchange/upload", Access: gateway.AccessSession, Body: gateway.BodyPackage, Handler: http.HandlerFunc(a.uploadAgentExchange)},
		{Method: http.MethodGet, Pattern: "/api/v1/agent-exchange/download", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.downloadAgentExchange)},
		{Method: http.MethodGet, Pattern: "/api/v1/agent-exchange/preview", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.previewAgentExchange)},
		{Method: http.MethodPut, Pattern: "/api/v1/agent-exchange/file", Access: gateway.AccessSession, Body: gateway.BodyPluginJSON, Handler: http.HandlerFunc(a.putAgentExchangeFile)},
		{Method: http.MethodPost, Pattern: "/api/v1/agent-exchange/rename", Access: gateway.AccessSession, Body: gateway.BodyJSON, Handler: http.HandlerFunc(a.renameAgentExchange)},
		{Method: http.MethodDelete, Pattern: "/api/v1/agent-exchange/entry", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.deleteAgentExchangeEntry)},
		// AI providers & external CLI auth (GAP-2, ADR-0017, ADR-0028)
		{Method: http.MethodGet, Pattern: "/api/v1/agent-cores", Access: sessionOrService, Handler: http.HandlerFunc(a.listAgentCores)},
		{Method: http.MethodGet, Pattern: "/api/v1/agent-cores/auth", Access: sessionOrService, Handler: http.HandlerFunc(a.listAgentCoreAuth)},
		{Method: http.MethodPost, Pattern: "/api/v1/agent-cores/{core}/login", Access: gateway.AccessSession, Body: gateway.BodyJSON, Handler: http.HandlerFunc(a.startAgentCoreLogin)},
		{Method: http.MethodDelete, Pattern: "/api/v1/agent-cores/{core}/login", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.logoutAgentCore)},
		{Method: http.MethodGet, Pattern: "/api/v1/agent-workspace/files", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.listAgentWorkspaceFiles)},
		{Method: http.MethodGet, Pattern: "/api/v1/agent-workspace/file", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.getAgentWorkspaceFile)},
		{Method: http.MethodPut, Pattern: "/api/v1/agent-workspace/file", Access: gateway.AccessSession, Body: gateway.BodyPluginJSON, Handler: http.HandlerFunc(a.putAgentWorkspaceFile)},
		{Method: http.MethodDelete, Pattern: "/api/v1/agent-workspace/file", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.deleteAgentWorkspaceFile)},
		{Method: http.MethodGet, Pattern: "/api/v1/agent-registry", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.searchAgentRegistry)},
		{Method: http.MethodPost, Pattern: "/api/v1/agent-registry/install", Access: gateway.AccessSession, Body: gateway.BodyJSON, Handler: http.HandlerFunc(a.installAgentRegistryItem)},
		{Method: http.MethodGet, Pattern: "/api/v1/ai/providers", Access: sessionOrService, Handler: http.HandlerFunc(a.listAIProviders)},
		{Method: http.MethodPost, Pattern: "/api/v1/ai/providers", Access: gateway.AccessSession, Body: gateway.BodyJSON, RequireIdempotency: true, Handler: http.HandlerFunc(a.createAIProvider)},
		{Method: http.MethodPost, Pattern: "/api/v1/ai/providers/fetch-models", Access: gateway.AccessSession, Body: gateway.BodyJSON, Handler: http.HandlerFunc(a.fetchAIProviderModels)},
		{Method: http.MethodPatch, Pattern: "/api/v1/ai/providers/{provider_id}", Access: gateway.AccessSession, Body: gateway.BodyJSON, RequireIdempotency: true, Handler: http.HandlerFunc(a.updateAIProvider)},
		{Method: http.MethodDelete, Pattern: "/api/v1/ai/providers/{provider_id}", Access: gateway.AccessSession, RequireIdempotency: true, Handler: http.HandlerFunc(a.deleteAIProvider)},
		{Method: http.MethodPut, Pattern: "/api/v1/ai/providers/{provider_id}/api-key", Access: gateway.AccessSession, Body: gateway.BodyJSON, Handler: http.HandlerFunc(a.setAIProviderAPIKey)},
		{Method: http.MethodDelete, Pattern: "/api/v1/ai/providers/{provider_id}/api-key", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.clearAIProviderAPIKey)},
		{Method: http.MethodPost, Pattern: "/api/v1/ai/providers/{provider_id}/test", Access: gateway.AccessSession, Handler: http.HandlerFunc(a.testAIProvider)},
	}
}

// requestID returns the gateway-assigned request ID of r.
func requestID(r *http.Request) string { return gateway.RequestID(r.Context()) }

// traceID returns the W3C trace ID of r.
func traceID(r *http.Request) string { return gateway.TraceID(r.Context()) }

// principal returns the authenticated caller of r.
func principal(r *http.Request) (gateway.Principal, error) {
	p, ok := gateway.PrincipalFrom(r.Context())
	if !ok || p.Actor.ID == "" {
		return gateway.Principal{}, problem.New(problem.Unauthenticated, "The request has no credentials.")
	}
	return p, nil
}

// caller returns the actor of r.
func (a *api) caller(r *http.Request) (actor.Actor, error) {
	p, err := principal(r)
	if err != nil {
		return actor.Actor{}, err
	}
	return p.Actor, nil
}

// authorize enforces the RBAC permission of a route. nodeID scopes the check to
// a managed node and is empty for host-wide resources.
func (a *api) authorize(ctx context.Context, act actor.Actor, permission, nodeID string) error {
	perm, err := authz.ParsePermission(permission)
	if err != nil {
		return err
	}
	return a.d.Authz.Authorize(ctx, act, string(perm), authz.Resource{Name: string(perm.Resource()), NodeID: nodeID})
}

// requireAdmin reports whether the caller has the administrator role. It backs
// the `owner=all` filter of the delegation list and admin-only workspace routes.
func (a *api) requireAdmin(ctx context.Context, act actor.Actor) error {
	if act.Kind != actor.Human {
		return problem.New(problem.PermissionDenied, "The administrator role is required for this request.")
	}
	role, disabled, err := a.d.Identity.PrincipalRole(ctx, act.ID)
	if err != nil {
		return problem.From(err)
	}
	if disabled || authz.Role(role) != authz.RoleAdmin {
		return problem.New(problem.PermissionDenied, "The administrator role is required for this request.")
	}
	return nil
}

// sessionToken returns the raw session cookie value of r ("" when absent).
func sessionToken(r *http.Request) string {
	c, err := r.Cookie(gateway.SessionCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// sessionTTL is the cookie lifetime: the absolute deadline of the session. The
// idle limit is enforced by the server on every request; the cookie is never
// re-issued, so binding it to the idle deadline would log an active user out.
func (a *api) sessionTTL(s identity.Session) time.Duration {
	if ttl := s.ExpiresAt.Sub(a.d.Clock.Now().UTC()); ttl > 0 {
		return ttl
	}
	return 0
}

// writeOperationResponse renders the HTTP-shaped result of an operation call.
// The body is the JSON operations produced, so an idempotent replay returns the
// original bytes; a 202 carries the Location of the operation.
func (a *api) writeOperationResponse(w http.ResponseWriter, resp *operations.Response) {
	if resp == nil {
		err := problem.Wrap(errors.New("api: nil operation response"))
		problem.Write(w, err, "", "")
		return
	}
	if resp.Replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	if resp.Status == http.StatusAccepted && resp.OperationID != "" {
		w.Header().Set("Location", "/api/v1/operations/"+resp.OperationID)
	}
	if err := gateway.WriteJSON(w, resp.Status, resp.Body); err != nil {
		a.d.Logger.Warn("api: write response", "error", err)
	}
}
