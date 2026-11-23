// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/agentsession"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/catalog"
	"github.com/qwq-panel/qwq/internal/events"
	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/pluginhost/updater"
	"github.com/qwq-panel/qwq/internal/privateexport"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// Options configure a Controller. Config is required.
type Options struct {
	Config config.Config
	// Logger receives operational logs. Defaults to a discard logger.
	Logger *slog.Logger
	// Clock is the single time source; it must be the same clock used by the
	// database so that tx.Now() and service timestamps agree.
	Clock clock.Clock
	// IDs generates resource IDs. Defaults to a generator over Clock.
	IDs *ids.Generator
	// PluginRuntime optionally dispatches plugin operations. It is built by
	// cmd/qwq/serve.go before New (the operation manager needs its dispatcher
	// at construction) and started after New (its sinks need the database).
	// Nil keeps every plugin action UNAVAILABLE, which is the documented
	// behaviour of a host without the plugin runtime.
	PluginRuntime *PluginRuntime
	// Updater optionally installs, updates and configures plugins (P3). It
	// needs the open database, so cmd/qwq/serve.go builds it after New and
	// stores it with SetUpdater; a caller that already has one may pass it
	// here instead. The controller does not close the updater: it owns no
	// background worker, and its lifetime is the process lifetime.
	Updater *updater.Updater
	// DeferOperations keeps the operation manager from running jobs or
	// resuming recovered operations until StartOperations. serve.go sets it so
	// nothing runs before the plugin runtime, the updater and every host
	// action handler are ready; tests leave it false.
	DeferOperations bool
}

// Controller owns the host services and their lifetime.
type Controller struct {
	cfg     config.Config
	log     *slog.Logger
	clk     clock.Clock
	ids     *ids.Generator
	db      *storage.DB
	keys    *secrets.KeyRing
	sec     *secrets.Store
	tls     *tlsmgr.Manager
	id      *identity.Service
	auth    *authz.Authorizer
	cat     *catalog.Catalog
	hub     *events.Hub
	lossy   *events.Lossy
	ops     *operations.Service
	exports *privateexport.Service
	gw      *gateway.Gateway
	// vis is the stream visibility the gateway uses; it resolves agent session
	// owners lazily through AgentSessions (gap 6).
	vis *visibility
	// plugins is the optional plugin runtime; Close stops it before the
	// database closes because its sinks write to the database.
	plugins *PluginRuntime
	// alertRelay forwards "*.alert" plugin events asynchronously to notify.hub.
	alertRelay *AlertEventRelay

	// updater is the optional install/update/configuration service. It is an
	// atomic pointer because serve.go installs it after New, and a reader must
	// never observe a half-initialised controller.
	updater atomic.Pointer[updater.Updater]

	// agentSessions is the native agent session backend (ADR-0010 §5). It is
	// built by NewAgentSessions when serve.go mounts the public API and is
	// owned by the controller so Close stops its turns before storage closes.
	agentSessions atomic.Pointer[agentsession.Service]
	// 续期事实源只由宿主装配；账号创建器绑定当前同步宿主事务。
	renewalPolicies atomic.Pointer[renewalPolicyHolder]
	renewalServices *renewalServiceSource
	prerequisites   atomic.Pointer[prerequisiteAuthorityHolder]

	// closeOnce runs Close once; closed is set first so Ready and new
	// builders refuse a controller that is shutting down.
	closeOnce sync.Once
	closed    atomic.Bool
	closeErr  error

	// Handler is the HTTP root handler. It is swapped for the gateway when the
	// remaining P1 services are assembled; the health endpoints below are the
	// readiness contract until then.
	handler http.Handler
}

// New opens storage, applies migrations and constructs the identity and
// authorization services. It does not start listeners or background workers;
// callers do that explicitly and call Close on the same controller.
func New(ctx context.Context, opts Options) (*Controller, error) {
	if err := opts.Config.Validate(); err != nil {
		return nil, fmt.Errorf("controller: config: %w", err)
	}
	retention, err := opts.Config.Retention.Windows()
	if err != nil {
		return nil, fmt.Errorf("controller: retention: %w", err)
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Clock == nil {
		opts.Clock = clock.System{}
	}
	if opts.IDs == nil {
		opts.IDs = ids.New(opts.Clock.Now)
	}
	// The data directory holds the database, the master key and TLS material;
	// it must not be readable by other local users.
	if err := os.MkdirAll(opts.Config.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("controller: create data dir: %w", err)
	}
	if err := checkDirMode(opts.Config.DataDir); err != nil {
		return nil, err
	}

	db, err := storage.Open(ctx, storage.Options{
		Path:   filepath.Join(opts.Config.DataDir, "qwq.db"),
		Clock:  opts.Clock,
		IDs:    opts.IDs,
		Logger: opts.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("controller: open storage: %w", err)
	}

	// The secret master key lives outside the database and is required before
	// identity can seal TOTP secrets (ADR-0008 §7).
	keys, err := secrets.LoadKeyRing(opts.Config.DataDir)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("controller: secret keys: %w", err)
	}
	sec, err := secrets.New(secrets.Options{DB: db, Keys: keys, Logger: opts.Logger})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("controller: secrets: %w", err)
	}

	// TLS material is created or loaded before the listener starts, so a
	// certificate problem fails startup instead of the first handshake.
	tm, err := tlsmgr.New(tlsmgr.Options{
		TLS:           opts.Config.HTTP.TLS,
		Listen:        opts.Config.HTTP.Listen,
		PublicOrigins: opts.Config.HTTP.PublicOrigins,
		DataDir:       opts.Config.DataDir,
		Clock:         opts.Clock,
		Logger:        opts.Logger,
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("controller: tls: %w", err)
	}

	id, err := identity.New(identity.Options{
		DB:               db,
		Clock:            opts.Clock,
		IDs:              opts.IDs,
		Logger:           opts.Logger,
		Sealer:           sec,
		Auditor:          auditor{},
		SessionRetention: retention.Sessions,
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("controller: identity: %w", err)
	}

	az, err := authz.New(authz.Options{
		DB:         db,
		Clock:      opts.Clock,
		Logger:     opts.Logger,
		Principals: id,
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("controller: authz: %w", err)
	}

	cat, err := catalog.New(catalogFloor, catalogReachability)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("controller: action catalog: %w", err)
	}

	hub, err := events.New(events.Config{
		Journal: db,
		Clock:   opts.Clock,
		Logger:  opts.Logger,
		Retain: events.Retain{
			Keep:     10000,
			MaxAge:   30 * 24 * time.Hour,
			Interval: time.Hour,
			Batch:    1000,
		},
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("controller: events: %w", err)
	}
	go hub.Run(ctx)
	lossy := events.NewLossy(events.LossyConfig{})

	argumentProtector, err := secrets.NewOperationProtector(ctx, sec)
	if err != nil {
		hub.Close()
		db.Close()
		return nil, fmt.Errorf("controller: operation secret protection: %w", err)
	}
	exports, err := privateexport.New(privateexport.Options{DB: db, Secrets: sec, Clock: opts.Clock, IDs: opts.IDs, NodeID: "local", Authorize: privateexport.CatalogAuthorization(cat, az)})
	if err != nil {
		hub.Close()
		db.Close()
		return nil, fmt.Errorf("controller: private export service: %w", err)
	}
	ops, err := operations.New(operations.Options{
		DB:                db,
		Clock:             opts.Clock,
		IDs:               opts.IDs,
		Logger:            opts.Logger,
		Catalog:           catalogAdapter{catalog: cat},
		Authorizer:        authorizerAdapter{authz: az},
		Policy:            policyAdapter{authz: az},
		Revisions:         revisionsAdapter{},
		NodeID:            "local",
		Dispatcher:        opts.PluginRuntime.Dispatcher(),
		DeferDispatch:     opts.DeferOperations,
		Pruner:            hostSecurityPruner{identity: id, exports: exports, db: db},
		ArgumentProtector: argumentProtector,
		Config: operations.Config{
			RetentionOperations: retention.Operations,
			RetentionAudit:      retention.Audit,
		},
	})
	if err != nil {
		hub.Close()
		db.Close()
		return nil, fmt.Errorf("controller: operations: %w", err)
	}
	c := &Controller{cfg: opts.Config, log: opts.Logger, clk: opts.Clock, ids: opts.IDs, db: db, keys: keys, sec: sec, tls: tm, id: id, auth: az, cat: cat, hub: hub, lossy: lossy, ops: ops, exports: exports, plugins: opts.PluginRuntime}
	if opts.Updater != nil {
		c.updater.Store(opts.Updater)
	}
	c.renewalServices = &renewalServiceSource{controller: c, nodeID: "local"}
	c.registerRenewalBootstrap()
	if err := ops.Start(ctx); err != nil {
		hub.Close()
		db.Close()
		return nil, fmt.Errorf("controller: start operations: %w", err)
	}
	// The stream's visibility resolves agent session owners through the
	// backend that serve.go builds later; until then the subject family is
	// denied (gap 6).
	c.vis = newVisibility(id, az, opts.Clock)
	c.vis.setSessionOwner(func(ctx context.Context, id string) (actor.Actor, bool) {
		if svc := c.AgentSessions(); svc != nil {
			return svc.OwnerOf(ctx, id)
		}
		return actor.Actor{}, false
	})

	gw, err := gateway.New(gateway.Config{
		Logger:           opts.Logger,
		Clock:            opts.Clock,
		IDs:              opts.IDs,
		TrustedProxies:   opts.Config.HTTP.TrustedProxies,
		PublicOrigins:    opts.Config.HTTP.PublicOrigins,
		TLS:              opts.Config.HTTP.TLS.Mode != config.TLSProxy,
		Auth:             authenticator{identity: id, authz: az},
		RateLimit:        gateway.NewTokenBuckets(opts.Clock, gateway.TokenBucketConfig{Rate: gateway.DefaultRequestRate, Burst: gateway.DefaultRequestBurst}),
		PreAuthLimit:     gateway.NewTokenBuckets(opts.Clock, gateway.TokenBucketConfig{Rate: gateway.DefaultPreAuthRate, Burst: gateway.DefaultPreAuthBurst}),
		PublicWriteLimit: gateway.NewTokenBuckets(opts.Clock, gateway.TokenBucketConfig{Rate: gateway.DefaultPublicWriteRate, Burst: gateway.DefaultPublicWriteBurst}),
		Limits:           gateway.DefaultLimits(),
		Events:           hub,
		Visibility:       c.vis.Allowed,
		Checks:           []gateway.Check{{Name: "host", Check: c.Ready}},
	})
	if err != nil {
		ops.Stop()
		hub.Close()
		db.Close()
		return nil, fmt.Errorf("controller: gateway: %w", err)
	}
	c.gw = gw
	c.handler = gw
	c.alertRelay = NewAlertEventRelay(c, opts.Logger)
	c.alertRelay.Start(context.Background())
	return c, nil
}

// StartOperations 在插件运行时、updater 恢复与全部路由（含宿主动作 handler）就绪后调用。
// It is a no-op unless the controller was built with DeferOperations.
func (c *Controller) StartOperations(ctx context.Context) { c.ops.StartDispatch(ctx) }

// Config returns the bootstrap configuration.
func (c *Controller) Config() config.Config { return c.cfg }

// Clock returns the time source shared by every host service.
func (c *Controller) Clock() clock.Clock { return c.clk }

// IDs returns the ID generator shared by every host service.
func (c *Controller) IDs() *ids.Generator { return c.ids }

// Logger returns the operational logger of the controller.
func (c *Controller) Logger() *slog.Logger { return c.log }

// PluginRuntime returns the plugin runtime, nil when it is not enabled.
func (c *Controller) PluginRuntime() *PluginRuntime { return c.plugins }

// Updater returns the plugin install/update service, nil when it is not
// enabled. It is the entry point for the P3 HTTP endpoints.
func (c *Controller) Updater() *updater.Updater { return c.updater.Load() }

// SetUpdater installs the plugin updater. cmd/qwq/serve.go calls it after New
// because the updater needs the open database, and Recover runs before requests
// are served. Passing nil disables the updater.
func (c *Controller) SetUpdater(u *updater.Updater) { c.updater.Store(u) }

// NewAgentSessions builds the native agent session backend and wires it to the
// operation path: the catalog offers the tools, AgentRunner executes them and
// AgentApprovals learns the human decision (ADR-0010 §5). The service is built
// once; a later call returns the same instance. cmd/qwq/serve.go passes it to
// api.Deps.AgentSessions, so the public routes never fall back to the
// runner-less default service of internal/api. The first call also repairs the
// sessions the previous process left busy, so it must precede serving requests.
func (c *Controller) NewAgentSessions(ctx context.Context) (*agentsession.Service, error) {
	if svc := c.agentSessions.Load(); svc != nil {
		return svc, nil
	}
	if c.closed.Load() || c.db == nil || c.ops == nil || c.cat == nil {
		return nil, errors.New("controller: closed")
	}
	logger := c.log
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	// Parse already validated the list; a failure here is a programming error.
	egressPrefixes, egressAddrs, err := config.ParseEgressAllow(c.cfg.Agent.ModelEgressAllow)
	if err != nil {
		return nil, fmt.Errorf("controller: agent.model_egress_allow: %w", err)
	}
	svc, err := agentsession.New(agentsession.Options{
		DB:      c.db,
		Clock:   c.clk,
		IDs:     c.ids,
		Logger:  logger,
		Secrets: c.sec,
		DataDir: c.cfg.DataDir,
		Catalog: AgentToolCatalog{Catalog: c.cat, HostAction: c.ops.HasHostAction},
		Runner: &AgentRunner{
			Ops: c.ops, Catalog: c.cat, NodeID: "local",
			Clock: c.clk, IDs: c.ids, Logger: logger,
		},
		Approvals: &AgentApprovals{Ops: c.ops, Clock: c.clk, Logger: logger},
		Native: agentsession.NativeOptions{
			EgressAllowPrefixes: egressPrefixes,
			EgressAllowAddrs:    egressAddrs,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("controller: agent sessions: %w", err)
	}
	if !c.agentSessions.CompareAndSwap(nil, svc) {
		// Another goroutine won the race; keep the installed service.
		svc.Close()
		return c.agentSessions.Load(), nil
	}
	if err := svc.Recover(ctx); err != nil {
		c.agentSessions.CompareAndSwap(svc, nil)
		svc.Close()
		return nil, fmt.Errorf("controller: recover agent sessions: %w", err)
	}
	return svc, nil
}

// AgentSessions returns the agent session backend, nil when serve.go has not
// built it.
func (c *Controller) AgentSessions() *agentsession.Service { return c.agentSessions.Load() }

// HostDeps returns the host services the plugin host channel uses. It is the
// argument of PluginRuntime.Start.
func (c *Controller) HostDeps() HostDeps {
	return HostDeps{
		DB:             c.db,
		Ops:            c.ops,
		Secrets:        c.sec,
		PrivateExports: c.exports,
		Config:         c.pluginConfigSource,
		SyncActiveConfig: func(pluginID string, rev int64, raw []byte) {
			if u := c.Updater(); u != nil {
				u.SyncActiveConfig(pluginID, rev, raw)
			}
		},
		Catalog:          c.cat,
		Lossy:            c.lossy,
		OnEventPublished: c.alertRelay.OnPluginEvent,
		IDs:              c.ids,
		Clock:            c.clk,
		Logger:           c.log,
		NodeID:           "local",
	}
}

// DB returns the open database; the controller owns it.
func (c *Controller) DB() *storage.DB { return c.db }

// Secrets returns the secret store.
func (c *Controller) Secrets() *secrets.Store { return c.sec }

// PrivateExports 返回会话绑定交付服务；它与插件/API共用现有数据库和维护循环。
func (c *Controller) PrivateExports() *privateexport.Service { return c.exports }

// TLS returns the TLS manager.
func (c *Controller) TLS() *tlsmgr.Manager { return c.tls }

// KeyRing returns the secret master key ring.
func (c *Controller) KeyRing() *secrets.KeyRing { return c.keys }

// Identity returns the identity service.
func (c *Controller) Identity() *identity.Service { return c.id }

// Authorizer returns the authorization service.
func (c *Controller) Authorizer() *authz.Authorizer { return c.auth }

// Catalog returns the merged host/plugin action catalog.
func (c *Controller) Catalog() *catalog.Catalog { return c.cat }

// Events returns the event hub.
func (c *Controller) Events() *events.Hub { return c.hub }

// Lossy returns the bounded in-memory realtime fanout for high-frequency samples.
func (c *Controller) Lossy() *events.Lossy { return c.lossy }

// Operations returns the operation manager.
func (c *Controller) Operations() *operations.Service { return c.ops }

// Gateway returns the HTTP gateway.
func (c *Controller) Gateway() *gateway.Gateway { return c.gw }

// Handler returns the HTTP root handler. Until the gateway is assembled this
// serves only /healthz and /readyz.
func (c *Controller) Handler() http.Handler { return c.handler }

// SetHandler replaces the root handler. It exists for the gateway assembly and
// for tests; the controller does not validate it.
func (c *Controller) SetHandler(h http.Handler) {
	if h == nil {
		panic("controller: nil handler")
	}
	c.handler = h
}

// Close releases the host services in reverse construction order. It is safe
// to call more than once and concurrently with readers: the fields are never
// cleared, so a handler still running during shutdown sees closed services
// that report errors instead of a nil pointer or a data race.
func (c *Controller) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		// Agent sessions go first: their turns call operations, so they must
		// be quiet before the operation manager and the database close.
		if svc := c.agentSessions.Swap(nil); svc != nil {
			svc.Close()
		}
		// Operations stop before the plugin runtime: a job whose stream the
		// runtime cut while the worker context is still live would be
		// recorded FAILED instead of staying RUNNING for the next recovery.
		if c.alertRelay != nil {
			c.alertRelay.Stop()
		}
		if c.ops != nil {
			c.ops.Stop()
		}
		// The plugin runtime goes next: its sinks write to the database, so
		// it must be quiet before storage is closed.
		if c.plugins != nil {
			c.plugins.Stop()
		}
		if c.gw != nil {
			c.gw.Close()
		}
		if c.hub != nil {
			c.hub.Close()
		}
		if c.db != nil {
			c.closeErr = c.db.Close()
		}
	})
	return c.closeErr
}

// Ready reports whether the host can serve requests. Today that means the
// database answers and migrations are applied; TLS and the local agent join the
// check when they are assembled.
func (c *Controller) Ready(ctx context.Context) error {
	if c.closed.Load() {
		return errors.New("controller: closed")
	}
	var one int
	if err := c.db.Reader().QueryRowContext(ctx, `SELECT 1`).Scan(&one); err != nil {
		return fmt.Errorf("controller: database: %w", err)
	}
	v, err := c.db.SchemaVersion(ctx)
	if err != nil {
		return fmt.Errorf("controller: schema version: %w", err)
	}
	if v == 0 {
		return errors.New("controller: no migrations applied")
	}
	if c.tls != nil {
		if err := c.tls.Ready(ctx); err != nil {
			return fmt.Errorf("controller: tls: %w", err)
		}
	}
	return nil
}

// checkDirMode refuses a data directory that another local user can read: it
// holds the database, the secret master key and TLS private keys.
func checkDirMode(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("controller: stat data dir: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("controller: data dir %s is not a directory", dir)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("controller: data dir %s has mode %04o; must not be accessible by group or others", dir, perm)
	}
	return nil
}
