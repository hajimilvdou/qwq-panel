// SPDX-License-Identifier: Apache-2.0

// Package pluginsdk implements the plugin side of Platform ABI v1
// (api/qwq/platform/v1/platform.proto): the author interfaces, the
// PluginService server, the Host Service client and the runtime helpers every
// plugin needs.
//
// # Scope
//
// The package is transport agnostic. It only depends on grpc.ServiceRegistrar
// and grpc.ClientConnInterface, so the same code runs over the bufconn test
// harness and over whatever listener ADR-0003 selects. The process entry
// point (go-plugin handshake, systemd socket activation, SO_PEERCRED peer
// checks and the host socket path) belongs to P2-T1; see the TODO in
// serve.go. Nothing here listens on a socket, reads environment variables that
// carry identity, or trusts an identity claim from a message field.
//
// # Author surface
//
// A plugin implements [Plugin] and returns one [Instance] per initialized
// instance:
//
//	type myPlugin struct{}
//
//	func (myPlugin) NewInstance(ctx context.Context, info pluginsdk.InstanceInfo) (pluginsdk.Instance, error) {
//		inst := &myInstance{InstanceBase: pluginsdk.NewInstanceBase(info)}
//		pluginsdk.HandleInvoke(inst, "my.echo", inst.echo)
//		pluginsdk.HandleJob(inst, "my.apply", inst.apply)
//		pluginsdk.HandlePlan(inst, "my.set", inst.plan)
//		pluginsdk.HandleInvoke(inst, "my.set", inst.set)
//		return inst, nil
//	}
//
//	type myInstance struct {
//		*pluginsdk.InstanceBase
//	}
//
//	func (i *myInstance) echo(ctx context.Context, in echoRequest) (echoResponse, error) {
//		return echoResponse{Message: in.Message, Instance: i.ID()}, nil
//	}
//
// The instance type may additionally implement any of [Starter], [Activator],
// [Deactivator], [Stopper], [Releaser], [ConfigValidator], [ConfigApplier],
// [HealthReporter] and [PublicRouteHandler]. Absent optional interfaces are
// no-ops, except ServePublicRoute which answers UNIMPLEMENTED.
//
// Embedding *InstanceBase is mandatory: [Instance] is a sealed interface whose
// unexported method is provided by InstanceBase. A missing embedding is a
// compile-time error at NewInstance's return statement.
//
// # Instance isolation
//
// One process serves several instances (ADR-0002). Every instance-level RPC
// is routed by RequestContext.instance_id; each instance owns its author
// object, its operation registry, its background context, its config snapshot
// and its in-flight accounting. ReleaseInstance frees them without touching
// the other instances.
//
// # Lifecycle
//
// The SDK enforces INITIALIZED -> READY (Start) -> ACTIVE (Activate) ->
// DRAINING (Stop) -> STOPPED. Requests that need to serve are accepted only in
// READY and ACTIVE; a new instance accepts nothing before Start, and a
// draining or stopped instance refuses new work. Background work must be
// started from [Activator.Activate] and tracked with [InstanceBase.Go];
// Activate is only called after the instance became ACTIVE, and Deactivate,
// Stop and ReleaseInstance cancel the background context and wait for the
// tracked goroutines up to the grace period. [InstanceBase.Go] refuses to start
// work outside ACTIVE, so a timer cannot start before Activate.
//
// # Errors
//
// ABI v1 separates transport failures from domain outcomes (platform.proto,
// "Errors"):
//
//   - gRPC status codes are used for addressing and lifecycle faults (unknown
//     instance: NOT_FOUND; instance not accepting requests: FAILED_PRECONDITION;
//     malformed request: INVALID_ARGUMENT) and for a broken stream.
//   - Once a call reaches an operation handler, its failure is an ErrorDetail
//     with a stable code while the gRPC status is OK. Return [*Error] values
//     built with [Errorf], [Validation] or [PreconditionFailed]; any other Go
//     error is logged and reported as INTERNAL without leaking its text.
//
// Handler errors are never returned as gRPC statuses, so a host outage during
// a call cannot be confused with a business failure of the plugin.
//
// # Host calls
//
// The instance's Host client wraps every Host Service RPC and fills
// HostCallContext automatically: instance_handle from Initialize, operation_id
// and trace_id from the request being served (or from Activate for background
// work). Callers pass their context; background work receives one from
// [InstanceBase.Go]. Host failures are returned as [*Error] with the mapped
// code, so [IsConflict] and friends work regardless of the transport.
//
// # Relative subjects
//
// Plugins name their own resources with relative subjects
// ("<segment>(/<segment>)*"). ResourceChange, PlannedChange, Precondition and
// EventDraft subjects are validated here before they reach the host, so a
// plugin cannot make the host reject an otherwise successful operation.
//
// # Logging and memory
//
// Logs are structured JSON on stderr (stdout belongs to the transport
// handshake), with plugin, instance and operation fields. GOMEMLIMIT is read
// and validated by [ReadMemoryLimit] and exposed in CheckHealth details; the
// Go runtime still reads the variable itself (ARCH §6.3).
package pluginsdk
