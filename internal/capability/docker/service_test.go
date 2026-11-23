// SPDX-License-Identifier: AGPL-3.0-only

package docker

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	"github.com/qwq-panel/qwq/internal/sandbox"
	dockerv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/docker/v1"
)

func TestValidateComposeYAMLStrictRejectsAllBypassPayloads(t *testing.T) {
	rejected := []struct {
		name string
		yaml string
	}{
		{
			name: "spaced colon privileged",
			yaml: "services:\n  app:\n    image: nginx:alpine\n    privileged : true\n",
		},
		{
			name: "multiline privileged",
			yaml: "services:\n  app:\n    image: nginx:alpine\n    privileged:\n      true\n",
		},
		{
			name: "truthy yes alias",
			yaml: "services:\n  app:\n    image: nginx:alpine\n    privileged: yes\n",
		},
		{
			name: "double slash root mount",
			yaml: "services:\n  app:\n    image: nginx:alpine\n    volumes:\n      - //:/mnt\n",
		},
		{
			name: "etc host mount",
			yaml: "services:\n  app:\n    image: nginx:alpine\n    volumes:\n      - /etc:/h\n",
		},
		{
			name: "docker sock mount",
			yaml: "services:\n  app:\n    image: nginx:alpine\n    volumes:\n      - /var/run/docker.sock:/d.sock\n",
		},
		{
			name: "long syntax sensitive source",
			yaml: "services:\n  app:\n    image: nginx:alpine\n    volumes:\n      - type: bind\n        source: /var/lib/qwq\n        target: /data\n",
		},
		{
			name: "yaml anchor and alias",
			yaml: "x-p: &p true\nservices:\n  app:\n    image: nginx:alpine\n    privileged: *p\n",
		},
		{
			name: "inline cap_add SYS_ADMIN",
			yaml: "services:\n  app:\n    image: nginx:alpine\n    cap_add: [SYS_ADMIN]\n",
		},
		{
			name: "list cap_add SYS_ADMIN",
			yaml: "services:\n  app:\n    image: nginx:alpine\n    cap_add:\n      - SYS_ADMIN\n",
		},
		{
			name: "pid host",
			yaml: "services:\n  app:\n    image: nginx:alpine\n    pid: host\n",
		},
		{
			name: "devices mount",
			yaml: "services:\n  app:\n    image: nginx:alpine\n    devices:\n      - /dev/sda:/dev/sda\n",
		},
		{
			name: "flow mapping in volumes",
			yaml: "services:\n  app:\n    image: nginx:alpine\n    volumes:\n      - {type: bind, source: /etc, target: /h}\n",
		},
		{
			name: "top level include",
			yaml: "include:\n  - /etc/passwd\nservices:\n  app:\n    image: nginx:alpine\n",
		},
		{
			name: "path traversal env_file",
			yaml: "services:\n  app:\n    image: nginx:alpine\n    env_file:\n      - ../../etc/shadow\n",
		},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ValidateComposeYAMLStrict(tc.yaml); err == nil {
				t.Fatalf("expected payload %q to be rejected, but it succeeded", tc.name)
			}
		})
	}
}

func TestValidateComposeYAMLStrictAllowsSafeNamedAndRelativeVolumes(t *testing.T) {
	safeYAML := `services:
  web:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "127.0.0.1:8080:80"
    volumes:
      - app_data:/var/lib/app
      - ./data:/usr/share/nginx/html:ro
    env_file:
      - ./app.env
volumes:
  app_data:
`
	warnings, err := ValidateComposeYAMLStrict(safeYAML)
	if err != nil {
		t.Fatalf("expected valid compose YAML to succeed, got error: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("expected zero warnings for safe YAML, got %v", warnings)
	}

	hostNetYAML := "services:\n  app:\n    image: nginx:alpine\n    network_mode: host\n"
	warnings, err = ValidateComposeYAMLStrict(hostNetYAML)
	if err != nil {
		t.Fatalf("expected network_mode: host to warn rather than reject, got error: %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning for network_mode: host, got %v", warnings)
	}
}

func TestBuildSafeDockerUpdatePayloadSetsMemorySwapMinusOne(t *testing.T) {
	raw, err := BuildSafeDockerUpdatePayload(256, 150)
	if err != nil {
		t.Fatalf("BuildSafeDockerUpdatePayload: %v", err)
	}
	var doc map[string]int64
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if doc["Memory"] != 256*1024*1024 {
		t.Fatalf("unexpected Memory: %d", doc["Memory"])
	}
	if doc["MemorySwap"] != -1 {
		t.Fatalf("expected MemorySwap=-1, got %d", doc["MemorySwap"])
	}
	if doc["NanoCPUs"] != 1500000000 {
		t.Fatalf("unexpected NanoCPUs: %d", doc["NanoCPUs"])
	}
	if _, err := BuildSafeDockerUpdatePayload(0, 0); err == nil {
		t.Fatal("expected error when both memory and cpu are zero")
	}
}

func TestProxyAllowlistedRequestRejectsDisallowedEndpointsAndForwardsAllowed(t *testing.T) {
	sockDir, err := os.MkdirTemp("/tmp", "qwq-dkr-*")
	if err != nil {
		sockDir = t.TempDir()
	} else {
		t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	}
	sockPath := filepath.Join(sockDir, "docker.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer func() { _ = ln.Close() }()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1.41/info", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ServerVersion":"27.3.1","Containers":1}`))
	})
	mux.HandleFunc("/v1.41/containers/abc123/update", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_, _ = w.Write([]byte(`{"Warnings":[]}`))
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	runner := &ControlledDockerCapabilityRunner{SocketPath: sockPath, StacksRoot: t.TempDir()}

	// Disallowed endpoints MUST be rejected before touching docker.sock.
	for _, bad := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/containers/create"},
		{http.MethodPost, "/containers/abc123/exec"},
		{http.MethodPost, "/exec/abc123/start"},
		{http.MethodPost, "/volumes/create"},
		{http.MethodGet, "/containers/../info"},
		{http.MethodGet, "/containers/a/b/json"},
		{http.MethodDelete, "/images/abc123"},
	} {
		if _, _, err := runner.ProxyAllowlistedRequest(t.Context(), bad.method, bad.path, url.Values{}, nil); err == nil {
			t.Fatalf("expected %s %s to be rejected", bad.method, bad.path)
		}
	}

	// Allowed GET /info succeeds.
	code, body, err := runner.ProxyAllowlistedRequest(t.Context(), http.MethodGet, "/info", url.Values{}, nil)
	if err != nil || code != http.StatusOK || !strings.Contains(string(body), "27.3.1") {
		t.Fatalf("GET /info failed: code=%d body=%q err=%v", code, string(body), err)
	}

	// Allowed POST /containers/abc123/update succeeds.
	updateBody, _ := BuildSafeDockerUpdatePayload(128, 50)
	code, _, err = runner.ProxyAllowlistedRequest(t.Context(), http.MethodPost, "/containers/abc123/update", url.Values{}, updateBody)
	if err != nil || code != http.StatusOK {
		t.Fatalf("POST update failed: code=%d err=%v", code, err)
	}
}

type stubDockerHelper struct {
	svc *Service
}

func (h stubDockerHelper) Call(ctx context.Context, req sandbox.CapabilityRequest) (sandbox.CapabilityResponse, error) {
	return h.svc.Run(ctx, req)
}

func TestDockerServiceAndForwarderRoundTrip(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "docker.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer func() { _ = ln.Close() }()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1.41/info", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ServerVersion":"27.5.0"}`))
	})
	mux.HandleFunc("/v1.41/containers/web1/restart", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	var capturedEnv []string
	var capturedArgs []string
	runner := &ControlledDockerCapabilityRunner{
		SocketPath: sockPath,
		StacksRoot: t.TempDir(),
		composeRunner: func(_ context.Context, _ string, env []string, args []string) (string, error) {
			capturedEnv = append([]string(nil), env...)
			capturedArgs = append([]string(nil), args...)
			return "stack up ok", nil
		},
	}
	fwd := Forwarder{Helper: stubDockerHelper{svc: &Service{Runner: runner}}}

	readRes, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
		PluginID: "containers.docker",
		Method:   "ProxyRead",
		Request:  &dockerv1.ProxyReadRequest{Path: "/info"},
	})
	if err != nil || readRes.Error != nil {
		t.Fatalf("ProxyRead failed: res=%+v err=%v", readRes, err)
	}
	pr := readRes.Response.(*dockerv1.ProxyReadResponse)
	if pr.GetStatusCode() != 200 || !strings.Contains(string(pr.GetBody()), "27.5.0") {
		t.Fatalf("unexpected ProxyRead response: %+v", pr)
	}

	writeRes, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
		PluginID: "containers.docker",
		Method:   "ProxyWrite",
		Request:  &dockerv1.ProxyWriteRequest{Method: http.MethodPost, Path: "/containers/web1/restart", RawQuery: "t=10"},
	})
	if err != nil || writeRes.Error != nil {
		t.Fatalf("ProxyWrite failed: res=%+v err=%v", writeRes, err)
	}
	pw := writeRes.Response.(*dockerv1.ProxyWriteResponse)
	if pw.GetStatusCode() != http.StatusNoContent {
		t.Fatalf("unexpected ProxyWrite status: %d", pw.GetStatusCode())
	}

	// Disallowed write endpoint returns domain error PERMISSION_DENIED.
	denyRes, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
		PluginID: "containers.docker",
		Method:   "ProxyWrite",
		Request:  &dockerv1.ProxyWriteRequest{Method: http.MethodPost, Path: "/containers/create"},
	})
	if err != nil || denyRes.Error == nil || denyRes.Error.Code != "PERMISSION_DENIED" {
		t.Fatalf("expected PERMISSION_DENIED for /containers/create, got res=%+v err=%v", denyRes, err)
	}

	// ComposeAction verifies YAML, strips GOMEMLIMIT, and executes cleanly.
	compRes, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
		PluginID: "containers.docker",
		Method:   "ComposeAction",
		Request: &dockerv1.ComposeActionRequest{
			StackName:   "demo",
			Action:      "up",
			YamlContent: "services:\n  web:\n    image: nginx:alpine\n",
		},
	})
	if err != nil || compRes.Error != nil {
		t.Fatalf("ComposeAction failed: res=%+v err=%v", compRes, err)
	}
	if !slices.Contains(capturedArgs, "qwq_demo") {
		t.Fatalf("expected project qwq_demo in compose args, got %v", capturedArgs)
	}
	for _, kv := range capturedEnv {
		if strings.HasPrefix(kv, "GOMEMLIMIT=") {
			t.Fatalf("GOMEMLIMIT must not leak into compose env: %v", capturedEnv)
		}
	}

	// ComposeAction rejects privileged YAML on host helper side.
	badComp, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
		PluginID: "containers.docker",
		Method:   "ComposeAction",
		Request: &dockerv1.ComposeActionRequest{
			StackName:   "evil",
			Action:      "up",
			YamlContent: "services:\n  web:\n    image: nginx:alpine\n    privileged:\n      true\n",
		},
	})
	if err != nil || badComp.Error == nil {
		t.Fatalf("expected privileged compose to be rejected on helper side, got res=%+v err=%v", badComp, err)
	}
}
