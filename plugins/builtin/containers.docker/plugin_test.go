// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

func makeDockerMuxFrame(stream byte, line string) []byte {
	var hdr [8]byte
	hdr[0] = stream
	binary.BigEndian.PutUint32(hdr[4:8], uint32(len(line)))
	return append(hdr[:], []byte(line)...)
}

func startDockerTestServer(t *testing.T, cfgJSON []byte) *pluginsdk.Server {
	t.Helper()
	srv, err := pluginsdk.Serve(t.Context(), pluginsdk.Options{
		Plugin:             New(),
		Manifest:           Manifest(),
		Registrar:          grpc.NewServer(),
		DefaultGracePeriod: time.Second,
	})
	if err != nil {
		t.Fatalf("pluginsdk.Serve: %v", err)
	}
	t.Cleanup(srv.Close)

	rc := &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}
	if _, err := srv.Initialize(t.Context(), &pb.InitializeRequest{
		Context:        rc,
		InstanceHandle: "containers-docker-test",
		DataDir:        t.TempDir(),
		ConfigJson:     cfgJSON,
		ConfigRevision: "1",
	}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if _, err := srv.Start(t.Context(), &pb.StartRequest{Context: rc}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := srv.Activate(t.Context(), &pb.ActivateRequest{Context: rc}); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	return srv
}

func invokeDockerRaw(t *testing.T, srv *pluginsdk.Server, op string, req any) *pb.InvokeResponse {
	t.Helper()
	raw, _ := json.Marshal(req)
	resp, err := srv.Invoke(t.Context(), &pb.InvokeRequest{
		Context:     &pb.RequestContext{InstanceId: "default", NodeId: "local", OperationId: "op-" + op, Locale: "zh-CN"},
		Operation:   op,
		ApiVersion:  "v1",
		PayloadJson: raw,
	})
	if err != nil {
		t.Fatalf("invoke %s transport error: %v", op, err)
	}
	return resp
}

func invokeDocker(t *testing.T, srv *pluginsdk.Server, op string, req any) map[string]any {
	t.Helper()
	resp := invokeDockerRaw(t, srv, op, req)
	if resp.GetError() != nil {
		t.Fatalf("invoke %s business error: %+v", op, resp.GetError())
	}
	var out map[string]any
	if err := json.Unmarshal(resp.GetPayloadJson(), &out); err != nil {
		t.Fatalf("unmarshal %s: %v", op, err)
	}
	return out
}

func TestContainersDockerUnixSocketAPIAndComposeSecurity(t *testing.T) {
	sockDir := t.TempDir()
	sockPath := filepath.Join(sockDir, "docker.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	defer func() { _ = ln.Close() }()

	var mu sync.Mutex
	var lastAction string
	var updatedMem int64
	var removedID string

	mux := http.NewServeMux()
	mux.HandleFunc("/v1.41/info", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ServerVersion":     "27.3.1",
			"Containers":        2,
			"ContainersRunning": 1,
			"ContainersStopped": 1,
			"Images":            3,
			"MemTotal":          int64(1024 * 1024 * 1024),
		})
	})
	mux.HandleFunc("/v1.41/containers/json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"Id": "abc1234567890000", "Names": []string{"/web-app"}, "Image": "nginx:alpine",
				"State": "running", "Status": "Up 2 hours", "Created": 1700000000,
				"Ports": []map[string]any{{"PublicPort": 8080, "PrivatePort": 80, "Type": "tcp"}},
			},
			{
				"Id": "def9876543210000", "Names": []string{"/worker-oom"}, "Image": "python:3.12",
				"State": "exited", "Status": "Exited (137) 5 minutes ago", "Created": 1700000001,
			},
		})
	})
	mux.HandleFunc("/v1.41/containers/abc1234567890000/json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Id": "abc1234567890000", "Name": "/web-app", "RestartCount": 2,
			"Config":     map[string]any{"Image": "nginx:alpine"},
			"State":      map[string]any{"Status": "running", "Running": true, "OOMKilled": true},
			"HostConfig": map[string]any{"Memory": int64(256 * 1024 * 1024)},
		})
	})
	mux.HandleFunc("/v1.41/containers/abc1234567890000/stats", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"memory_stats": map[string]any{"usage": uint64(128 * 1024 * 1024), "limit": uint64(256 * 1024 * 1024)},
			"cpu_stats": map[string]any{
				"cpu_usage":        map[string]any{"total_usage": uint64(2000)},
				"system_cpu_usage": uint64(20000),
				"online_cpus":      uint64(2),
			},
			"precpu_stats": map[string]any{
				"cpu_usage":        map[string]any{"total_usage": uint64(1000)},
				"system_cpu_usage": uint64(10000),
			},
		})
	})
	mux.HandleFunc("/v1.41/containers/abc1234567890000/logs", func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		buf.Write(makeDockerMuxFrame(1, "2026-11-22T00:00:01Z started nginx\n"))
		buf.Write(makeDockerMuxFrame(2, "2026-11-22T00:00:02Z warning: high memory\n"))
		_, _ = w.Write(buf.Bytes())
	})
	mux.HandleFunc("/v1.41/containers/abc1234567890000/restart", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		lastAction = "restart"
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1.41/containers/abc1234567890000/update", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Memory int64 `json:"Memory"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		updatedMem = body.Memory
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Warnings":[]}`))
	})
	mux.HandleFunc("/v1.41/containers/def9876543210000", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			mu.Lock()
			removedID = "def9876543210000"
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	mux.HandleFunc("/v1.41/images/json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"Id": "sha256:1122334455667788", "RepoTags": []string{"nginx:alpine"}, "Size": int64(42 * 1024 * 1024), "Created": 1700000000},
		})
	})
	mux.HandleFunc("/v1.41/images/prune", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ImagesDeleted":  []map[string]any{{"Deleted": "sha256:deadbeef"}},
			"SpaceReclaimed": int64(64 * 1024 * 1024),
		})
	})

	httpSrv := &http.Server{Handler: mux}
	go func() { _ = httpSrv.Serve(ln) }()
	defer func() { _ = httpSrv.Close() }()

	cfgRaw, _ := json.Marshal(map[string]any{"docker_socket": sockPath, "http_timeout_seconds": 5})
	srv := startDockerTestServer(t, cfgRaw)

	// 1. 路径穿越容器 ID 必须被拒绝且返回精确错误码 INVALID_ARGUMENT
	badResp := invokeDockerRaw(t, srv, "docker.container.logs", map[string]any{"id": "../../etc/passwd", "tail": 10})
	if badResp.GetError() == nil || badResp.GetError().GetCode() != "INVALID_ARGUMENT" {
		t.Fatalf("expected INVALID_ARGUMENT for path-traversal container id, got %+v", badResp.GetError())
	}

	// 2. 总览、详情 + 实时 CPU/Memory/OOMKilled 统计、多路复用日志解包
	ov := invokeDocker(t, srv, "docker.overview", map[string]any{})
	if ov["daemon"].(map[string]any)["available"] != true || len(ov["containers"].([]any)) != 2 {
		t.Fatalf("unexpected overview: %+v", ov)
	}
	ins := invokeDocker(t, srv, "docker.container.inspect", map[string]any{"id": "abc1234567890000"})
	ct := ins["container"].(map[string]any)
	if ct["oom_killed"] != true || int(ct["memory_mb"].(float64)) != 128 {
		t.Fatalf("unexpected inspect detail: %+v", ct)
	}
	logs := invokeDocker(t, srv, "docker.container.logs", map[string]any{"id": "abc1234567890000", "tail": 50})
	logText := logs["logs"].(string)
	if !strings.Contains(logText, "started nginx") || !strings.Contains(logText, "high memory") {
		t.Fatalf("demuxed logs missing content: %q", logText)
	}

	// 3. 容器重启、动态内存限额、删除与镜像清理
	invokeDocker(t, srv, "docker.container.action", map[string]any{"id": "abc1234567890000", "action": "restart"})
	invokeDocker(t, srv, "docker.container.limits", map[string]any{"id": "abc1234567890000", "memory_mb": 256, "cpus": 1.0})
	invokeDocker(t, srv, "docker.container.remove", map[string]any{"id": "def9876543210000", "force": true})
	pruned := invokeDocker(t, srv, "docker.images.prune", map[string]any{"all": false})

	mu.Lock()
	gotAction, gotMem, gotRem := lastAction, updatedMem, removedID
	mu.Unlock()
	if gotAction != "restart" || gotMem != 256*1024*1024 || gotRem != "def9876543210000" || int(pruned["deleted_count"].(float64)) != 1 {
		t.Fatalf("docker mutations mismatch: action=%q mem=%d rem=%q pruned=%+v", gotAction, gotMem, gotRem, pruned)
	}

	// 4. Compose YAML 静态安全扫描：高危隔离逃逸项（privileged: true / include / 越界 env_file / 根目录挂载）强阻断，
	//    其余中高危项（network_mode: host / pid: host / SYS_ADMIN / docker.sock）在 Plan 与 dry_run 中告警。
	for _, blockedYAML := range []string{
		"services:\n  app:\n    image: nginx:alpine\n    privileged: true\n",
		"include:\n  - /etc/passwd\nservices:\n  app:\n    image: nginx:alpine\n",
		"services:\n  app:\n    image: nginx:alpine\n    env_file:\n      - ../../etc/shadow\n",
		"services:\n  app:\n    image: nginx:alpine\n    volumes:\n      - /:/host\n",
	} {
		badCP := invokeDockerRaw(t, srv, "docker.compose.deploy", map[string]any{
			"name": "blocked-demo", "compose_yaml": blockedYAML, "dry_run": true,
		})
		if badCP.GetError() == nil || badCP.GetError().GetCode() != "INVALID_ARGUMENT" {
			t.Fatalf("expected INVALID_ARGUMENT for blocked compose YAML %q, got %+v", blockedYAML, badCP.GetError())
		}
	}

	yamlDoc := "services:\n  app:\n    image: nginx:alpine\n    network_mode: \"host\"\n    pid: \"host\"\n    cap_add:\n      - SYS_ADMIN\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
	planRaw, _ := json.Marshal(map[string]any{"name": "risky-demo", "compose_yaml": yamlDoc})
	planResp, err := srv.PlanOperation(t.Context(), &pb.PlanOperationRequest{
		Context:     &pb.RequestContext{InstanceId: "default", NodeId: "local", OperationId: "plan-cp-1", Locale: "zh-CN"},
		Operation:   "docker.compose.deploy",
		ApiVersion:  "v1",
		PayloadJson: planRaw,
	})
	if err != nil || planResp.GetError() != nil || len(planResp.GetWarnings()) < 4 {
		t.Fatalf("expected >=4 security warnings in Plan response, got resp=%+v err=%v", planResp, err)
	}
	cpRes := invokeDocker(t, srv, "docker.compose.deploy", map[string]any{
		"name": "risky-demo", "compose_yaml": yamlDoc, "dry_run": true,
	})
	stack := cpRes["stack"].(map[string]any)
	warns := stack["warnings"].([]any)
	if len(warns) < 4 {
		t.Fatalf("expected >=4 security warnings on risky compose, got %+v", warns)
	}
	if _, err := os.Stat(filepath.Join(stack["work_dir"].(string), "compose.yml")); err != nil {
		t.Fatalf("expected compose.yml saved on disk: %v", err)
	}
	remStack := invokeDocker(t, srv, "docker.compose.remove", map[string]any{"name": "risky-demo"})
	if remStack["removed"] != true {
		t.Fatalf("expected compose stack removed: %+v", remStack)
	}

	// 5. AI 紧凑摘要发现异常退出容器
	digest := invokeDocker(t, srv, "docker.ai.digest", map[string]any{})
	if len(digest["anomalies"].([]any)) != 1 {
		t.Fatalf("expected 1 exited container anomaly in AI digest, got %+v", digest)
	}
}

func TestContainersDockerHonestUnavailableWhenSocketMissing(t *testing.T) {
	cfgRaw, _ := json.Marshal(map[string]any{"docker_socket": filepath.Join(t.TempDir(), "missing.sock")})
	srv := startDockerTestServer(t, cfgRaw)

	out := invokeDocker(t, srv, "docker.overview", map[string]any{})
	daemon := out["daemon"].(map[string]any)
	if daemon["available"] != false || daemon["reason"] == "" {
		t.Fatalf("expected honest unavailable status, got %+v", daemon)
	}
}
