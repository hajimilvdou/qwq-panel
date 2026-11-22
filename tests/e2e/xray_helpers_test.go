// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e && linux

package e2e

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/sandbox"
)

const xrayServerName = "xray-e2e.test"

type xrayFixture struct {
	port        int
	uuid        string
	privateKey  string
	publicKey   string
	shortID     string
	target      string
	reservation net.Listener
}

// newXrayFixture 只生成当次临时材料，目标和业务端口全部使用回环。
func newXrayFixture(t *testing.T) *xrayFixture {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var uuid [16]byte
	if _, err := rand.Read(uuid[:]); err != nil {
		t.Fatal(err)
	}
	uuid[6], uuid[8] = uuid[6]&0x0f|0x40, uuid[8]&0x3f|0x80
	id := hex.EncodeToString(uuid[:])
	var shortID [4]byte
	if _, err := rand.Read(shortID[:]); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &xrayFixture{port: listener.Addr().(*net.TCPAddr).Port, reservation: listener,
		uuid:       id[:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:],
		privateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()), publicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()),
		shortID: hex.EncodeToString(shortID[:]), target: newRealityTarget(t)}
	t.Cleanup(func() {
		if fixture.reservation != nil {
			_ = fixture.reservation.Close()
		}
	})
	return fixture
}

func newRealityTarget(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: xrayServerName}, DNSNames: []string{xrayServerName}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// 上游启动探测按 5s 检查握手后记录；回环 TLS 夹具需给已认证连接
	// 留出探测窗口，避免 3s 的 HTTP 握手超时先关闭原始目标连接。
	server := &http.Server{ReadHeaderTimeout: 15 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("qwq-reality-test-target")) })}
	done := make(chan error, 1)
	go func() { done <- server.ServeTLS(listener, "", "") }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			_ = server.Close()
			t.Errorf("回环 TLS 目标停止失败: %v", err)
		}
		select {
		case err := <-done:
			if !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("回环 TLS 目标异常: %v", err)
			}
		case <-ctx.Done():
			t.Error("回环 TLS 目标未回收")
		}
	})
	return listener.Addr().String()
}

func (f *xrayFixture) desired() map[string]any {
	return map[string]any{"schema_version": "1", "enabled": true, "inbound": map[string]any{
		"id": "e2e-inbound", "listen": "127.0.0.1", "port": f.port, "protocol": "vless", "transport": "raw", "flow": "xtls-rprx-vision",
		"security": map[string]any{"mode": "reality", "target": f.target, "server_names": []string{xrayServerName}, "private_key": f.privateKey, "short_ids": []string{f.shortID}},
		"users":    []map[string]string{{"id": "e2e-user", "uuid": f.uuid}},
	}, "outbound": map[string]string{"type": "direct"}}
}

func (f *xrayFixture) releasePort(t *testing.T) {
	t.Helper()
	if f.reservation != nil {
		if err := f.reservation.Close(); err != nil {
			t.Fatal(err)
		}
		f.reservation = nil
	}
}

func xrayPanel(t *testing.T) *panel {
	t.Helper()
	p := setupPanel(t)
	p.plugin = xrayID
	p.caps = []map[string]string{
		{"name": "network.proxy", "scope": "direct"}, {"name": "secret.reveal", "scope": "config"},
		{"name": "state.kv.read", "scope": "self"}, {"name": "state.kv.write", "scope": "self"},
	}
	return p
}

func saveXrayDesired(p *panel, fixture *xrayFixture, expected string) string {
	p.t.Helper()
	data, err := json.Marshal(map[string]any{"config": fixture.desired(), "expected_revision": expected})
	if err != nil {
		p.t.Fatal(err)
	}
	var saved struct {
		Revision string          `json:"revision"`
		Config   json.RawMessage `json:"config"`
	}
	p.decode(p.request(http.MethodPut, "/api/v1/plugins/"+xrayID+"/config", bytes.NewReader(data), "application/json", true), http.StatusOK, &saved)
	if saved.Revision == "" || saved.Revision == expected {
		p.t.Fatal("保存 desired 未推进版本")
	}
	for _, secret := range []string{fixture.uuid, fixture.privateKey} {
		if bytes.Contains(saved.Config, []byte(secret)) {
			p.t.Fatal("公开配置响应泄漏临时材料")
		}
	}
	if bytes.Contains(saved.Config, []byte(`"$secret"`)) {
		p.t.Fatal("公开配置响应泄漏秘密引用")
	}
	return saved.Revision
}

func applyXrayPlan(p *panel, revision, running string, mfa *xrayMFA) map[string]any {
	operation := startXrayPlan(p, revision, running, mfa)
	return p.waitOperation(operation)
}

func startXrayPlan(p *panel, revision, running string, mfa *xrayMFA) *operationResult {
	id := createXrayApplyPlan(p, revision, running)
	return executeXrayApplyPlan(p, id, mfa)
}

func createXrayApplyPlan(p *panel, revision, running string) string {
	p.t.Helper()
	before, reveals := readXrayStatus(p), xrayRevealCount(p)
	var plan struct {
		ID               string `json:"plan_id"`
		Executable       bool   `json:"executable"`
		RequiresApproval bool   `json:"requires_approval"`
		RequiresMFA      bool   `json:"requires_mfa"`
	}
	p.postJSON("/api/v1/plans", map[string]any{"action": xrayID + "/core.apply", "args": map[string]string{"config_revision": revision, "expected_running_revision": running}, "target": map[string]string{"node_id": "local", "plugin_id": xrayID, "instance_id": "default"}}, http.StatusCreated, &plan)
	if plan.ID == "" || !plan.Executable || !plan.RequiresApproval || plan.RequiresMFA {
		p.t.Fatalf("Xray write 预演审批范围无效：executable=%t approval=%t mfa=%t", plan.Executable, plan.RequiresApproval, plan.RequiresMFA)
	}
	after := readXrayStatus(p)
	if after.Running != before.Running || after.Digest != before.Digest || after.Epoch != before.Epoch || xrayRevealCount(p) != reveals {
		p.t.Fatal("预演改变了运行配置或揭示了秘密")
	}
	return plan.ID
}

func executeXrayApplyPlan(p *panel, id string, mfa *xrayMFA) *operationResult {
	p.t.Helper()
	var operation operationResult
	p.postJSON("/api/v1/plans/"+id+"/execute", nil, http.StatusAccepted, &operation)
	requireXrayApproval(p, &operation)
	p.approveFixtureJob(&operation)
	return &operation
}

type xrayStatus struct {
	State        string `json:"state"`
	ProcessState string `json:"process_state"`
	APIState     string `json:"api_state"`
	Desired      string `json:"desired_revision"`
	Running      string `json:"running_revision"`
	Digest       string `json:"config_digest"`
	Epoch        string `json:"reset_epoch"`
	Available    bool   `json:"proxy_available"`
}

func readXrayStatus(p *panel) xrayStatus {
	p.t.Helper()
	data, err := json.Marshal(p.invoke("core.status", map[string]any{}))
	if err != nil {
		p.t.Fatal(err)
	}
	var status xrayStatus
	if err := json.Unmarshal(data, &status); err != nil {
		p.t.Fatal(err)
	}
	return status
}

func requireHealthyXray(p *panel, revision, digest string) xrayStatus {
	p.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		status := readXrayStatus(p)
		if status.State == "RUNNING" && status.ProcessState == "RUNNING" && status.APIState == "READY" && status.Available && status.Running == revision && status.Epoch != "" && status.Digest != "" {
			if digest != "" && status.Digest != digest {
				p.t.Fatal("恢复后运行配置摘要改变")
			}
			return status
		}
		time.Sleep(200 * time.Millisecond)
	}
	p.t.Fatal("真实 Xray 未恢复到已提交健康配置")
	return xrayStatus{}
}

func xrayChild(t *testing.T, driver int) int {
	t.Helper()
	driverPath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", driver))
	if err != nil {
		t.Fatal(err)
	}
	children, err := processChildren(driver)
	if err != nil {
		t.Fatal(err)
	}
	pid := 0
	for _, value := range children {
		executable, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", value))
		if err != nil {
			continue
		}
		if filepath.Base(executable) == "xray" {
			if executable != filepath.Join(filepath.Dir(driverPath), "xray") {
				t.Fatal("运行核心不是当前驱动包内二进制")
			}
			if pid != 0 {
				t.Fatal("同一驱动存在重叠 Xray 进程")
			}
			pid = value
		}
	}
	if pid == 0 {
		t.Fatal("驱动没有真实包内 Xray 子进程")
	}
	if !bytes.Equal(readFile(t, fmt.Sprintf("/proc/%d/cgroup", driver)), readFile(t, fmt.Sprintf("/proc/%d/cgroup", pid))) {
		t.Fatal("Xray 脱离驱动单元 cgroup")
	}
	uid := processUID(t, driver)
	if uid == 0 || uid == lookupUID(t, qwqUser) || processUID(t, pid) != uid {
		t.Fatal("驱动与 Xray 的隔离 UID 不一致")
	}
	environment := readFile(t, fmt.Sprintf("/proc/%d/environ", pid))
	for _, marker := range [][]byte{[]byte("QWQ_"), []byte("PLUGIN_TOKEN"), []byte("CREDENTIALS_DIRECTORY")} {
		if bytes.Contains(environment, marker) {
			t.Fatal("核心继承了宿主控制凭据环境")
		}
	}
	return pid
}

func processChildren(parent int) ([]int, error) {
	if parent <= 0 {
		return nil, errors.New("父进程标识无效")
	}
	directory := fmt.Sprintf("/proc/%d/task", parent)
	threads, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	seen := make(map[int]bool)
	for _, thread := range threads {
		id, err := strconv.Atoi(thread.Name())
		if err != nil || id <= 0 {
			return nil, errors.New("进程线程标识无效")
		}
		raw, err := os.ReadFile(filepath.Join(directory, thread.Name(), "children"))
		// Go 工作线程可能在枚举期间退出；其余线程仍必须完整检查。
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, text := range strings.Fields(string(raw)) {
			pid, err := strconv.Atoi(text)
			if err != nil || pid <= 0 {
				return nil, errors.New("子进程标识无效")
			}
			seen[pid] = true
		}
	}
	children := make([]int, 0, len(seen))
	for pid := range seen {
		children = append(children, pid)
	}
	slices.Sort(children)
	return children, nil
}

func requireXrayPrivateTree(t *testing.T, driver int) {
	t.Helper()
	root := filepath.Join(sandbox.DefaultPluginDataRoot, xrayID, "default")
	uid := processUID(t, driver)
	uidText := strconv.FormatUint(uint64(uid), 10)
	// DynamicUser 可以通过 idmapped mount 映射宿主 inode 的 UID；在插件挂载视图验证归属。
	if owner := run(t, "nsenter", "-t", strconv.Itoa(driver), "-m", "--", "stat", "-c", "%u", root); owner != uidText {
		t.Fatal("私有根没有映射给插件动态 UID")
	}
	physical, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.Stat(physical)
	if err != nil {
		t.Fatal(err)
	}
	baseOwner, ok := base.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("私有根属主不可读")
	}
	err = filepath.WalkDir(physical, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("私有树含未授权链接")
		}
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != baseOwner.Uid {
			return errors.New("私有树属主不一致")
		}
		mode := os.FileMode(0o600)
		if info.IsDir() {
			mode = 0o700
		}
		if info.Mode().Perm() != mode {
			return errors.New("私有树权限不一致")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(root, "work")
	if entries, err := os.ReadDir(work); err != nil || len(entries) != 0 {
		t.Fatal("完成 Apply 后候选工作区未清理")
	}
	state := filepath.Join(root, "runtime", "state.json")
	if _, err := os.Stat(state); err != nil {
		t.Fatal("已提交状态不存在")
	}
	// 使用系统既有 nobody 身份实际检查权限；不创建或更改操作系统账户。
	nobody := run(t, "runuser", "-u", "nobody", "--", "id", "-u")
	if nobody == uidText {
		t.Fatal("隔离检查身份与插件相同")
	}
	if err := exec.Command("runuser", "-u", "nobody", "--", "test", "-r", state).Run(); exitCode(err) != 1 {
		t.Fatal("其他 UID 未被私有快照读取权限拒绝")
	}
}

func requirePIDsGone(t *testing.T, pids ...int) {
	t.Helper()
	for _, pid := range pids {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); !os.IsNotExist(err) {
			t.Fatal("停止/替换后原进程未回收")
		}
	}
}

func xrayRevealCount(p *panel) int {
	p.t.Helper()
	var page struct {
		Items []struct {
			Action string `json:"action"`
		} `json:"items"`
		Meta struct {
			Next string `json:"next_cursor"`
		} `json:"meta"`
	}
	p.decode(p.request(http.MethodGet, "/api/v1/audit?limit=100&action=secret.reveal&outcome=success", nil, "", false), http.StatusOK, &page)
	if page.Meta.Next != "" {
		p.t.Fatal("秘密审计计数超过本轮有界夹具范围")
	}
	count := 0
	for _, item := range page.Items {
		if item.Action == "secret.reveal" {
			count++
		}
	}
	return count
}
