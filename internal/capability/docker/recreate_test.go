// SPDX-License-Identifier: AGPL-3.0-only

package docker

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/qwq-panel/qwq/internal/sandbox"
)

func startMockDockerSocket(t *testing.T, handler http.Handler) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "qwq-dkr-*")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
	})
	return sock
}

func baseInspectJSON(id, name string, privileged bool, sizeRw int64, running bool, networks map[string]any) map[string]any {
	if networks == nil {
		networks = map[string]any{
			"app-net": map[string]any{
				"NetworkID": "net_app_1",
				"IPAddress": "172.28.0.5",
				"Aliases":   []string{id[:12], "web-alias"},
			},
		}
	}
	return map[string]any{
		"Id":     id,
		"Name":   "/" + name,
		"SizeRw": sizeRw,
		"State": map[string]any{
			"Running": running,
			"Status":  "running",
		},
		"Config": map[string]any{
			"Image":  "nginx:alpine",
			"Env":    []string{"FOO=bar"},
			"Labels": map[string]string{"app": "demo"},
			"ExposedPorts": map[string]any{
				"80/tcp": map[string]any{},
			},
		},
		"HostConfig": map[string]any{
			"Privileged":  privileged,
			"NetworkMode": "app-net",
			"PortBindings": map[string]any{
				"80/tcp": []map[string]string{{"HostIp": "127.0.0.1", "HostPort": "18080"}},
			},
		},
		"NetworkSettings": map[string]any{
			"Networks": networks,
		},
	}
}

func TestRecreateContainerPorts_RollbackOnStartFailure(t *testing.T) {
	const oldID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const newID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	var (
		mu             sync.Mutex
		renamedBack    bool
		oldRestarted   bool
		newRemoved     bool
		backupNameSeen string
	)

	sock := startMockDockerSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		p := strings.TrimPrefix(r.URL.Path, "/v1.41")
		switch {
		case r.Method == http.MethodGet && p == "/containers/"+oldID+"/json":
			_ = json.NewEncoder(w).Encode(baseInspectJSON(oldID, "demo-web", false, 0, true, nil))
		case r.Method == http.MethodPost && p == "/containers/"+oldID+"/stop":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && p == "/containers/"+oldID+"/rename":
			target := r.URL.Query().Get("name")
			if strings.HasPrefix(target, "demo-web-qwq-bak-") {
				backupNameSeen = target
			} else if target == "demo-web" {
				renamedBack = true
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && p == "/containers/create":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"Id": newID})
		case r.Method == http.MethodPost && p == "/containers/"+newID+"/start":
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "simulated start failure"})
		case r.Method == http.MethodDelete && p == "/containers/"+newID:
			newRemoved = true
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && p == "/containers/"+oldID+"/start":
			oldRestarted = true
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected docker call: %s %s?%s", r.Method, p, r.URL.RawQuery)
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	runner := &ControlledDockerCapabilityRunner{SocketPath: sock}
	_, err := runner.RecreateContainerWithPortBindings(context.Background(), RecreatePortsInput{
		ContainerID: oldID,
		Rules: []PortMappingRule{
			{BindMode: "loopback", HostPort: 0, ContainerPort: 80, Protocol: "tcp"},
		},
	}, []uint16{22, 8443})
	if err == nil {
		t.Fatalf("expected error on simulated start failure, got nil")
	}
	if !strings.Contains(err.Error(), "自动回滚") {
		t.Fatalf("expected rollback message, got: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if backupNameSeen == "" {
		t.Fatalf("expected old container to be renamed to backup name")
	}
	if !newRemoved || !renamedBack || !oldRestarted {
		t.Fatalf("rollback incomplete: newRemoved=%v renamedBack=%v oldRestarted=%v", newRemoved, renamedBack, oldRestarted)
	}
}

func TestRecreateContainerPorts_DirtyWritableLayerAndCommit(t *testing.T) {
	const oldID = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	const newID = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

	var (
		mu            sync.Mutex
		commitCalled  bool
		createdImage  string
		oldDeleted    bool
		secondaryConn bool
	)

	networks := map[string]any{
		"app-net": map[string]any{"NetworkID": "net_app", "Aliases": []string{"web"}},
		"db-net":  map[string]any{"NetworkID": "net_db", "Aliases": []string{"web-db"}},
	}

	sock := startMockDockerSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		p := strings.TrimPrefix(r.URL.Path, "/v1.41")
		switch {
		case r.Method == http.MethodGet && p == "/containers/"+oldID+"/json":
			_ = json.NewEncoder(w).Encode(baseInspectJSON(oldID, "dirty-app", false, 4<<20, true, networks))
		case r.Method == http.MethodPost && p == "/commit":
			commitCalled = true
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"Id": "sha256:snap123"})
		case r.Method == http.MethodPost && p == "/containers/"+oldID+"/stop":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && p == "/containers/"+oldID+"/rename":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && p == "/containers/create":
			var body struct {
				Image string `json:"Image"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			createdImage = body.Image
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"Id": newID})
		case r.Method == http.MethodPost && p == "/networks/db-net/connect":
			secondaryConn = true
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && p == "/containers/"+newID+"/start":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && p == "/containers/"+oldID:
			oldDeleted = true
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected docker call: %s %s", r.Method, p)
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	runner := &ControlledDockerCapabilityRunner{SocketPath: sock}

	// 1. Without CommitWritableLayer or AllowDiscardWritableLayer -> must block with WRITABLE_LAYER_DIRTY.
	out, err := runner.RecreateContainerWithPortBindings(context.Background(), RecreatePortsInput{
		ContainerID: oldID,
		Rules:       []PortMappingRule{{BindMode: "loopback", HostPort: 0, ContainerPort: 80, Protocol: "tcp"}},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "WRITABLE_LAYER_DIRTY") {
		t.Fatalf("expected WRITABLE_LAYER_DIRTY, got err=%v", err)
	}
	if out.WritableSizeBytes != 4<<20 {
		t.Fatalf("expected WritableSizeBytes=%d, got %d", 4<<20, out.WritableSizeBytes)
	}

	// 2. With CommitWritableLayer=true -> commits snapshot, creates new container from snapshot, reconnects secondary net, removes old.
	out, err = runner.RecreateContainerWithPortBindings(context.Background(), RecreatePortsInput{
		ContainerID:         oldID,
		CommitWritableLayer: true,
		Rules:               []PortMappingRule{{BindMode: "loopback", HostPort: 0, ContainerPort: 80, Protocol: "tcp"}},
	}, []uint16{22, 8443})
	if err != nil {
		t.Fatalf("expected commit recreate to succeed, got: %v", err)
	}
	if out.NewContainerID != newID || out.CommittedSnapshot == "" {
		t.Fatalf("unexpected output: %+v", out)
	}
	if len(out.AppliedRules) != 1 || out.AppliedRules[0].HostPort < 20000 {
		t.Fatalf("expected auto-allocated host port >=20000, got %+v", out.AppliedRules)
	}
	mu.Lock()
	defer mu.Unlock()
	if !commitCalled || !strings.HasPrefix(createdImage, "qwq-port-snapshot/dirty-app:") || !secondaryConn || !oldDeleted {
		t.Fatalf("state mismatch: commit=%v image=%q secondaryConn=%v oldDeleted=%v", commitCalled, createdImage, secondaryConn, oldDeleted)
	}
}

func TestRecreateContainerPorts_SecurityBoundaries(t *testing.T) {
	const privID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	const normalID = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	sock := startMockDockerSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/v1.41")
		switch p {
		case "/containers/" + privID + "/json":
			_ = json.NewEncoder(w).Encode(baseInspectJSON(privID, "priv-box", true, 0, true, nil))
		case "/containers/" + normalID + "/json":
			_ = json.NewEncoder(w).Encode(baseInspectJSON(normalID, "norm-box", false, 0, true, nil))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	svc := &Service{
		Runner: &ControlledDockerCapabilityRunner{SocketPath: sock},
		ReservedPortsFunc: func(context.Context) []uint16 {
			return []uint16{22}
		},
	}

	// 1. Privileged container must be refused with PERMISSION_DENIED.
	rawPriv, _ := json.Marshal(RecreatePortsInput{
		ContainerID: privID,
		Rules:       []PortMappingRule{{BindMode: "loopback", HostPort: 0, ContainerPort: 80, Protocol: "tcp"}},
	})
	resp, err := svc.Run(context.Background(), sandbox.CapabilityRequest{Op: "docker.recreate_ports", ID: "containers.docker", ParamsJSON: rawPriv})
	if err != nil || resp.OK || resp.Code != "PERMISSION_DENIED" || !strings.Contains(resp.Error, "PRIVILEGED_CONTAINER_REFUSED") {
		t.Fatalf("expected PRIVILEGED_CONTAINER_REFUSED, got resp=%+v err=%v", resp, err)
	}

	// 2. Host reserved port (22 or host-injected 8443) must be refused with PORT_RESERVED_HOST.
	for _, port := range []uint16{22, 8443} {
		rawRes, _ := json.Marshal(RecreatePortsInput{
			ContainerID:       normalID,
			ReservedHostPorts: []uint16{8443},
			Rules:             []PortMappingRule{{BindMode: "public", HostPort: port, ContainerPort: 80, Protocol: "tcp"}},
		})
		resp, err = svc.Run(context.Background(), sandbox.CapabilityRequest{Op: "docker.recreate_ports", ID: "containers.docker", ParamsJSON: rawRes})
		if err != nil || resp.OK || resp.Code != "PERMISSION_DENIED" || !strings.Contains(resp.Error, "PORT_RESERVED_HOST") {
			t.Fatalf("port %d: expected PORT_RESERVED_HOST, got resp=%+v err=%v", port, resp, err)
		}
	}

	// 3. Non-bridge driver must be refused.
	rawNet, _ := json.Marshal(CreateNetworkInput{Name: "bad-macvlan", Driver: "macvlan"})
	resp, err = svc.Run(context.Background(), sandbox.CapabilityRequest{Op: "docker.network.create", ID: "containers.docker", ParamsJSON: rawNet})
	if err != nil || resp.OK || resp.Code != "VALIDATION_FAILED" || !strings.Contains(resp.Error, "UNSUPPORTED_NETWORK_DRIVER") {
		t.Fatalf("expected UNSUPPORTED_NETWORK_DRIVER, got resp=%+v err=%v", resp, err)
	}
}

func TestNetworkHotplugAndLastNetworkProtected(t *testing.T) {
	const cid = "1111111111111111111111111111111111111111111111111111111111111111"

	var (
		mu          sync.Mutex
		attached    = map[string]any{"bridge": map[string]any{"NetworkID": "net_bridge"}}
		lastConnect map[string]any
	)

	sock := startMockDockerSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		p := strings.TrimPrefix(r.URL.Path, "/v1.41")
		switch {
		case r.Method == http.MethodGet && p == "/containers/"+cid+"/json":
			cp := make(map[string]any, len(attached))
			for k, v := range attached {
				cp[k] = v
			}
			_ = json.NewEncoder(w).Encode(baseInspectJSON(cid, "net-demo", false, 0, true, cp))
		case r.Method == http.MethodPost && p == "/networks/app-net/connect":
			_ = json.NewDecoder(r.Body).Decode(&lastConnect)
			attached["app-net"] = map[string]any{"NetworkID": "net_app"}
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && p == "/networks/bridge/disconnect":
			delete(attached, "bridge")
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	runner := &ControlledDockerCapabilityRunner{SocketPath: sock}

	// Disconnecting the sole network must fail with LAST_NETWORK_PROTECTED.
	err := runner.MutateContainerNetwork(context.Background(), NetworkMembershipInput{
		ContainerID: cid,
		NetworkID:   "bridge",
		Action:      "disconnect",
	})
	if err == nil || !strings.Contains(err.Error(), "LAST_NETWORK_PROTECTED") {
		t.Fatalf("expected LAST_NETWORK_PROTECTED, got: %v", err)
	}

	// Connecting second network with aliases & IPv4 succeeds.
	err = runner.MutateContainerNetwork(context.Background(), NetworkMembershipInput{
		ContainerID: cid,
		NetworkID:   "app-net",
		Action:      "connect",
		Aliases:     []string{"api", "backend"},
		IPv4Address: "172.28.0.10",
	})
	if err != nil {
		t.Fatalf("connect app-net failed: %v", err)
	}
	mu.Lock()
	ep, _ := lastConnect["EndpointConfig"].(map[string]any)
	mu.Unlock()
	if ep == nil || ep["Aliases"] == nil || ep["IPAMConfig"] == nil {
		t.Fatalf("expected Aliases and IPAMConfig in connect payload, got: %+v", lastConnect)
	}

	// Now disconnecting bridge succeeds because app-net remains attached.
	err = runner.MutateContainerNetwork(context.Background(), NetworkMembershipInput{
		ContainerID: cid,
		NetworkID:   "bridge",
		Action:      "disconnect",
	})
	if err != nil {
		t.Fatalf("disconnect bridge failed: %v", err)
	}

	// Verify endpoint allowlist boundaries.
	if !isAllowedDockerEndpoint(http.MethodGet, "/networks") {
		t.Fatalf("GET /networks should be allowed")
	}
	if !isAllowedDockerEndpoint(http.MethodDelete, "/networks/custom-net") {
		t.Fatalf("DELETE /networks/custom-net should be allowed")
	}
	if isAllowedDockerEndpoint(http.MethodDelete, "/networks/bridge") {
		t.Fatalf("DELETE /networks/bridge must be forbidden")
	}
	if isAllowedDockerEndpoint(http.MethodPost, "/containers/create") {
		t.Fatalf("POST /containers/create must remain forbidden via generic proxy")
	}
}
