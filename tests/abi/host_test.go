// SPDX-License-Identifier: AGPL-3.0-only

package abi_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/qwq-panel/qwq/sdk/abi"
	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// hostMinor is the ABI minor the fake host implements.
const hostMinor = abi.Minor

// fakeHost is the Agent side of the trial: plugin supervisor, Host services, operation records
// and the event journal. Plugin identity comes only from the connection a call arrives on.
type fakeHost struct {
	ctx context.Context // parent of every operation context; canceled at cleanup
	wg  sync.WaitGroup  // background operation runners

	mu         sync.Mutex
	plugins    map[string]*hostPlugin // node_id + "/" + plugin_id
	ops        map[string]*hostOp
	idem       map[string]string // caller instance + idempotency_key -> operation_id
	kv         map[string]kvEntry
	events     []*pb.Event
	violations []string // plugin protocol violations seen by the host
	seq        uint64
}

// hostPlugin is one plugin process as seen by the host.
type hostPlugin struct {
	node    string
	desc    *pb.PluginDescriptor
	client  pb.PluginServiceClient
	handles map[string]*hostInstance // instance_handle -> instance; guarded by fakeHost.mu
	insts   map[string]*hostInstance // instance_id -> instance; guarded by fakeHost.mu
}

type hostInstance struct {
	plugin    *hostPlugin
	id        string
	handle    string
	config    []byte
	configRev string
	active    bool // routable: Activate succeeded and not cleaned up; guarded by fakeHost.mu
}

func (i *hostInstance) key() string {
	return i.plugin.node + "/" + i.plugin.desc.GetPluginId() + "/" + i.id
}

type kvEntry struct {
	value    []byte
	revision string
}

func newFakeHost(t *testing.T) *fakeHost {
	ctx, cancel := context.WithCancel(context.Background())
	h := &fakeHost{ctx: ctx, plugins: map[string]*hostPlugin{}, ops: map[string]*hostOp{},
		idem: map[string]string{}, kv: map[string]kvEntry{}}
	// Registered before any connection, so it runs after all of them have been closed.
	t.Cleanup(func() {
		cancel()
		h.wg.Wait()
	})
	return h
}

// pluginProcess is a plugin implementation plus the connector its main() would use to dial the
// host socket it was given.
type pluginProcess interface {
	pb.PluginServiceServer
	connectHost(grpc.ClientConnInterface)
}

// load starts a plugin process on node. The plugin serves PluginService on its own connection; the
// host reads the descriptor, checks the ABI, then serves the granted Host services on a second
// connection that belongs to this plugin only.
func (h *fakeHost) load(t *testing.T, node string, p pluginProcess) (*hostPlugin, error) {
	t.Helper()
	client := pb.NewPluginServiceClient(serve(t, func(s *grpc.Server) { pb.RegisterPluginServiceServer(s, p) }))
	resp, err := client.GetDescriptor(testCtx(t), &pb.GetDescriptorRequest{})
	if err != nil {
		return nil, err
	}
	d := resp.GetDescriptor_()
	// The manifest's abi.minimum_minor is authoritative; the trial plugins report it as abi_minor.
	if !abi.Compatible(abi.Major, hostMinor, d.GetAbiMajor(), d.GetAbiMinor()) {
		return nil, fmt.Errorf("plugin %s: ABI %d.%d is not supported by host %d.%d",
			d.GetPluginId(), d.GetAbiMajor(), d.GetAbiMinor(), abi.Major, hostMinor)
	}
	hp := &hostPlugin{node: node, desc: d, client: client,
		handles: map[string]*hostInstance{}, insts: map[string]*hostInstance{}}
	p.connectHost(serve(t, func(s *grpc.Server) { h.registerHostServices(s, hp) }))
	h.mu.Lock()
	h.plugins[node+"/"+d.GetPluginId()] = hp
	h.mu.Unlock()
	return hp, nil
}

func (h *fakeHost) mustLoad(t *testing.T, node string, p pluginProcess) *hostPlugin {
	t.Helper()
	hp, err := h.load(t, node, p)
	if err != nil {
		t.Fatal(err)
	}
	return hp
}

// registerHostServices serves the Host services on a plugin's own socket. A service whose RPCs all
// need one capability is registered only when it is granted (platform.proto, Services).
func (h *fakeHost) registerHostServices(s *grpc.Server, hp *hostPlugin) {
	pb.RegisterHostStateServiceServer(s, &stateService{h: h, p: hp})
	pb.RegisterHostEventsServiceServer(s, &eventsService{h: h, p: hp})
	pb.RegisterHostConfigServiceServer(s, &configService{h: h, p: hp})
	if hasCapability(hp.desc.GetCapabilities(), "plugin.invoke") {
		pb.RegisterHostInvokeServiceServer(s, &invokeService{h: h, p: hp})
	}
	// HostSecretsService needs secret.reveal, which no trial plugin is granted.
}

func hasCapability(caps []*pb.Capability, name string) bool {
	for _, c := range caps {
		if c.GetName() == name {
			return true
		}
	}
	return false
}

func (h *fakeHost) nextID(prefix string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seq++
	return fmt.Sprintf("%s-%d", prefix, h.seq)
}

// lifecycleContext is the RequestContext of a lifecycle call; the host itself is the actor.
func lifecycleContext(inst *hostInstance) *pb.RequestContext {
	return &pb.RequestContext{
		RequestId:  rand.Text(),
		TraceId:    rand.Text(),
		Actor:      &pb.Actor{Kind: pb.ActorKind_ACTOR_KIND_SYSTEM, Id: "agent"},
		NodeId:     inst.plugin.node,
		InstanceId: inst.id,
		Locale:     "zh-CN",
	}
}

// initialize issues a fresh instance_handle for instance id and calls Initialize.
func (h *fakeHost) initialize(t *testing.T, hp *hostPlugin, id, configRev string, config []byte) (*hostInstance, *pb.InitializeResponse) {
	t.Helper()
	inst := &hostInstance{plugin: hp, id: id, handle: rand.Text(), config: config, configRev: configRev}
	h.mu.Lock()
	hp.handles[inst.handle] = inst
	hp.insts[id] = inst
	h.mu.Unlock()
	resp, err := hp.client.Initialize(testCtx(t), &pb.InitializeRequest{
		Context:        lifecycleContext(inst),
		InstanceHandle: inst.handle,
		DataDir:        "/var/lib/qwq-plugins/" + hp.desc.GetPluginId() + "/" + id,
		ConfigJson:     config,
		ConfigRevision: configRev,
		HostAbiMinor:   hostMinor,
	})
	if err != nil {
		t.Fatalf("Initialize %s: %v", inst.key(), err)
	}
	return inst, resp
}

// start runs Initialize -> Start -> Activate and makes the instance routable.
func (h *fakeHost) start(t *testing.T, hp *hostPlugin, id string, config []byte) *hostInstance {
	t.Helper()
	inst, _ := h.initialize(t, hp, id, "1", config)
	ctx := testCtx(t)
	if _, err := hp.client.Start(ctx, &pb.StartRequest{Context: lifecycleContext(inst)}); err != nil {
		t.Fatalf("Start %s: %v", inst.key(), err)
	}
	if _, err := hp.client.Activate(ctx, &pb.ActivateRequest{Context: lifecycleContext(inst)}); err != nil {
		t.Fatalf("Activate %s: %v", inst.key(), err)
	}
	h.setActive(inst, true)
	return inst
}

func (h *fakeHost) setActive(inst *hostInstance, v bool) {
	h.mu.Lock()
	inst.active = v
	h.mu.Unlock()
}

// cleanupOwner is the host-side Cleanup(owner) of ARCH §5.7: it does not depend on the plugin. The
// handle stops working and operations the instance created or runs are canceled.
func (h *fakeHost) cleanupOwner(inst *hostInstance) {
	h.mu.Lock()
	delete(inst.plugin.handles, inst.handle)
	delete(inst.plugin.insts, inst.id)
	inst.active = false
	var owned []*hostOp
	for _, op := range h.ops {
		if op.creator == inst || op.target == inst {
			owned = append(owned, op)
		}
	}
	h.mu.Unlock()
	for _, op := range owned {
		h.cancelOp(op)
	}
}

// caller maps a Host service call to the calling instance. The plugin is known from the socket the
// call arrived on (hp); the handle only selects one of that plugin's instances. A handle of another
// plugin, or one invalidated by cleanup, is unknown here.
func (h *fakeHost) caller(hp *hostPlugin, hc *pb.HostCallContext) (*hostInstance, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	inst := hp.handles[hc.GetInstanceHandle()]
	if inst == nil {
		return nil, status.Error(codes.Unauthenticated, "unknown instance_handle")
	}
	return inst, nil
}

// authorize checks a Host service call against capability name:scope. With an operation_id the
// call must belong to an operation currently dispatched to the calling instance and is checked
// against that operation's capabilities; without one, against every capability of the plugin
// (ADR-0007 #4). Writes are refused while the operation is only being planned (ADR-0004 D7: plans
// are side-effect free); the proto does not state this rule (see report).
func (h *fakeHost) authorize(inst *hostInstance, hc *pb.HostCallContext, write bool, ok func(*pb.Capability) bool, need string) error {
	caps := inst.plugin.desc.GetCapabilities()
	if id := hc.GetOperationId(); id != "" {
		h.mu.Lock()
		op := h.ops[id]
		dispatched := op != nil && op.target == inst && op.dispatched
		planning := op != nil && op.planning
		h.mu.Unlock()
		if !dispatched {
			return status.Errorf(codes.PermissionDenied, "operation %s is not dispatched to this instance", id)
		}
		if planning && write {
			return status.Errorf(codes.PermissionDenied, "operation %s is being planned; %s is a write", id, need)
		}
		if len(op.desc.GetCapabilities()) > 0 {
			caps = op.desc.GetCapabilities()
		}
	}
	for _, c := range caps {
		if ok(c) {
			return nil
		}
	}
	return status.Errorf(codes.PermissionDenied, "missing capability %s", need)
}

func capMatch(name, scope string) func(*pb.Capability) bool {
	return func(c *pb.Capability) bool { return c.GetName() == name && c.GetScope() == scope }
}

// kvCap matches state.kv.<action> for the plugin's own store. The example manifest grants only
// state.kv.write:self yet its plan has to read, so write is taken to imply read (see report).
func kvCap(action string) func(*pb.Capability) bool {
	return func(c *pb.Capability) bool {
		return c.GetName() == "state.kv."+action || (action == "read" && c.GetName() == "state.kv.write")
	}
}
