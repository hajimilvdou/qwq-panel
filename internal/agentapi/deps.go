// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/catalog"
	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/storage"
)

// Tool limits from x-qwq-limits in api/public/v1/openapi.yaml. They are
// constants rather than configuration because the document is the contract: a
// deployment that lowered them would answer outside the published schema.
const (
	// FindActionsDefaultLimit is agent_find_actions_default.
	FindActionsDefaultLimit = 8
	// FindActionsMaxLimit is agent_find_actions_max.
	FindActionsMaxLimit = 20
	// ReadItemsDefault is agent_read_items_default.
	ReadItemsDefault = 20
	// ReadItemsMax is agent_read_items_max and the maximum `limit` of the
	// ReadRequest schema.
	ReadItemsMax = 100
	// ReadResponseBytes is agent_read_response_bytes, the cap of one read
	// response body.
	ReadResponseBytes = 32768

	// WaitTimeoutDefaultSeconds is agent_wait_timeout_default_seconds.
	WaitTimeoutDefaultSeconds = 25
	// WaitTimeoutMaxSeconds is agent_wait_timeout_max_seconds and the maximum
	// `timeout_seconds` of the WaitRequest schema.
	WaitTimeoutMaxSeconds = 55
	// ConcurrentWaitsPerDelegation is
	// agent_concurrent_waits_per_delegation.
	ConcurrentWaitsPerDelegation = 4
)

// WaitTimeoutDefault and WaitTimeoutMax are the durations behind the two
// timeout constants.
const (
	WaitTimeoutDefault = WaitTimeoutDefaultSeconds * time.Second
	WaitTimeoutMax     = WaitTimeoutMaxSeconds * time.Second
)

// DocsLoader loads the bundled Markdown documentation of a plugin action.
// catalog.Entry.Docs holds the package-relative path the plugin manifest
// declared; only the component that mounted the plugin package can read it.
// A nil loader means this host does not expose bundled docs, and
// describe_action omits them (the field is optional in ActionDescription).
type DocsLoader func(ctx context.Context, entry *catalog.Entry) ([]byte, error)

// Deps are the services the agent tools call. Every field except Logger,
// NodeID and Docs is required; Register fails closed when one is missing.
type Deps struct {
	DB       *storage.DB
	Clock    clock.Clock
	IDs      *ids.Generator
	Logger   *slog.Logger
	Identity *identity.Service
	Authz    *authz.Authorizer
	Ops      *operations.Service
	Catalog  *catalog.Catalog
	NodeID   string
	// Docs is optional; see DocsLoader.
	Docs DocsLoader
}

// normalize fills the optional defaults and validates the rest.
func (d Deps) normalize() (Deps, error) {
	switch {
	case d.DB == nil:
		return Deps{}, errors.New("agentapi: Deps.DB is required")
	case d.Identity == nil:
		return Deps{}, errors.New("agentapi: Deps.Identity is required")
	case d.Authz == nil:
		return Deps{}, errors.New("agentapi: Deps.Authz is required")
	case d.Ops == nil:
		return Deps{}, errors.New("agentapi: Deps.Ops is required")
	case d.Catalog == nil:
		return Deps{}, errors.New("agentapi: Deps.Catalog is required")
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
	return d, nil
}

// Register adds the seven agent tools to g. It must be called before the
// gateway starts serving.
//
// Every route accepts only a delegation bearer token (the OpenAPI
// `security: [delegationToken]`), takes an application/json body and relies on
// the gateway's limiter; plan and execute use the 4 MiB body limit of their
// x-qwq-limits override and the rest use the 1 MiB default.
func Register(g *gateway.Gateway, d Deps) error {
	if g == nil {
		return errors.New("agentapi: nil gateway")
	}
	d, err := d.normalize()
	if err != nil {
		return err
	}
	h := newHandlers(g, d)
	return h.register(g)
}

// register adds the seven routes to g. Register is the public entry point; the
// split exists so tests can keep the handlers (and their wait limiter) they
// registered.
func (h *handlers) register(g *gateway.Gateway) error {
	routes := []gateway.Route{
		{
			Method:  http.MethodPost,
			Pattern: "/api/v1/agent/find_actions",
			Access:  gateway.AccessDelegation,
			Body:    gateway.BodyJSON,
			Handler: http.HandlerFunc(h.findActions),
		},
		{
			Method:  http.MethodPost,
			Pattern: "/api/v1/agent/describe_action",
			Access:  gateway.AccessDelegation,
			Body:    gateway.BodyJSON,
			Handler: http.HandlerFunc(h.describeAction),
		},
		{
			Method:  http.MethodPost,
			Pattern: "/api/v1/agent/read",
			Access:  gateway.AccessDelegation,
			Body:    gateway.BodyJSON,
			Handler: http.HandlerFunc(h.read),
		},
		{
			// x-qwq-limits: max_body_bytes 4194304 for plan.
			Method:  http.MethodPost,
			Pattern: "/api/v1/agent/plan",
			Access:  gateway.AccessDelegation,
			Body:    gateway.BodyPluginJSON,
			Handler: http.HandlerFunc(h.plan),
		},
		{
			// x-qwq-limits: max_body_bytes 4194304 for execute.
			Method:  http.MethodPost,
			Pattern: "/api/v1/agent/execute",
			Access:  gateway.AccessDelegation,
			Body:    gateway.BodyPluginJSON,
			Handler: http.HandlerFunc(h.execute),
		},
		{
			Method:  http.MethodPost,
			Pattern: "/api/v1/agent/wait",
			Access:  gateway.AccessDelegation,
			Body:    gateway.BodyJSON,
			Handler: http.HandlerFunc(h.wait),
		},
		{
			Method:  http.MethodPost,
			Pattern: "/api/v1/agent/cancel",
			Access:  gateway.AccessDelegation,
			Body:    gateway.BodyJSON,
			Handler: http.HandlerFunc(h.cancel),
		},
	}
	for _, rt := range routes {
		if err := g.Handle(rt); err != nil {
			return fmt.Errorf("agentapi: %s %s: %w", rt.Method, rt.Pattern, err)
		}
	}
	return nil
}
