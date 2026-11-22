// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/supervisor"
)

// HostMux adapts a per-plugin factory to the single supervisor.HostServer the
// supervisor takes (ADR-0003 section 3: one host socket per plugin). The main
// session builds it from internal/hostsvc:
//
//	mux := agent.HostMux(func(pluginID string) (supervisor.HostServer, error) {
//		return hostsvc.New(pluginID)
//	})
//	sup, err := supervisor.New(supervisor.Options{Host: mux, Units: sandboxUnits, ...})
//
// A nil factory is valid: Serve then fails with UNAVAILABLE, so a build without
// the host service still starts and reports a clear problem instead of pretending
// the channel works.
func HostMux(factory func(pluginID string) (supervisor.HostServer, error)) supervisor.HostServer {
	return &hostMux{factory: factory}
}

type hostMux struct {
	factory func(pluginID string) (supervisor.HostServer, error)
}

// Serve builds the host server of pluginID and delegates to it.
func (m *hostMux) Serve(ctx context.Context, pluginID string) (func(), error) {
	if pluginID == "" {
		return nil, problem.New(problem.ValidationFailed, "agent: a plugin id is required to serve its host channel")
	}
	if m.factory == nil {
		return nil, problem.New(problem.Unavailable, "agent: the plugin host channel service is not wired into this build")
	}
	host, err := m.factory(pluginID)
	if err != nil {
		return nil, &problem.Error{
			Code:   problem.Unavailable,
			Detail: "agent: the host channel of plugin " + pluginID + " is unavailable",
			Cause:  err,
		}
	}
	if host == nil {
		return nil, problem.New(problem.Unavailable, "agent: no host channel service was built for plugin %s", pluginID)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	stop, err := host.Serve(ctx, pluginID)
	if err != nil {
		return nil, &problem.Error{
			Code:   problem.Unavailable,
			Detail: "agent: the host channel of plugin " + pluginID + " failed to serve",
			Cause:  err,
		}
	}
	if stop == nil {
		return func() {}, nil
	}
	return stop, nil
}
