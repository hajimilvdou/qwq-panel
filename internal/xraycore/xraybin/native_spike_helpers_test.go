// SPDX-License-Identifier: AGPL-3.0-only

//go:build x6spike && linux

package xraybin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/internal/xraycore/xrayconfig"
	"github.com/qwq-panel/qwq/sdk/coreapi"
)

// ---- 临时材料与生产渲染 ----------------------------------------------------

func spikeCandidate(t *testing.T, dir string) (string, int) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("cannot reserve a temporary loopback port")
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil || port < 1024 {
		t.Fatal("temporary business port is invalid")
	}
	var key [32]byte
	var uuid [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal("cannot generate temporary REALITY material")
	}
	if _, err := rand.Read(uuid[:]); err != nil {
		t.Fatal("cannot generate temporary user material")
	}
	uuid[6], uuid[8] = uuid[6]&0x0f|0x40, uuid[8]&0x3f|0x80
	encoded := hex.EncodeToString(uuid[:])
	secrets := xrayconfig.Secrets{
		PrivateKey: []byte(base64.RawURLEncoding.EncodeToString(key[:])),
		UUIDs:      map[string][]byte{"proof": []byte(encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:])},
	}
	clear(key[:])
	clear(uuid[:])
	defer secrets.Clear()
	enabled := true
	intent := &coreapi.Intent{SchemaVersion: "1", Enabled: &enabled,
		Inbound: &coreapi.Inbound{ID: "proof", Listen: "127.0.0.1", Port: port, Protocol: "vless", Transport: "raw", Flow: "xtls-rprx-vision",
			Security: &coreapi.Reality{Mode: "reality", Target: "127.0.0.1:11443", ServerNames: []string{"example.test"}, PrivateKey: coreapi.SecretRef{ID: "sec_00000000000000000000000000"}, ShortIDs: []string{"0123456789abcdef"}},
			Users:    []coreapi.User{{ID: "proof", UUID: coreapi.SecretRef{ID: "sec_00000000000000000000000001"}}}},
		Outbound: &coreapi.Outbound{Type: "direct"},
	}
	data, err := xrayconfig.Render(intent, secrets, xrayconfig.Options{APISocket: filepath.Join(dir, "api.sock")})
	if err != nil {
		t.Fatal("production renderer rejected the temporary intent")
	}
	defer clear(data)
	name := filepath.Join(dir, "candidate.json")
	if err := os.WriteFile(name, data, 0o600); err != nil {
		t.Fatal("cannot write a private candidate")
	}
	return name, port
}

// ---- 有界子进程与私有 socket ----------------------------------------------

type spikeProcess struct {
	command *exec.Cmd
	cancel  context.CancelFunc
	done    chan error
	stopped bool
}

func spikeStart(t *testing.T, parent context.Context, binary *Binary, candidate string) *spikeProcess {
	t.Helper()
	ctx, cancel := context.WithCancel(parent)
	command, err := binary.Command(ctx, candidate, false)
	if err != nil {
		cancel()
		t.Fatal("cannot create the fixed Xray command")
	}
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal("cannot start verified Xray")
	}
	process := &spikeProcess{command: command, cancel: cancel, done: make(chan error, 1)}
	go func() { process.done <- command.Wait() }()
	t.Cleanup(func() { process.stop(t) })
	return process
}

func (p *spikeProcess) stop(t *testing.T) {
	t.Helper()
	if p.stopped {
		return
	}
	p.stopped = true
	defer p.cancel()
	_ = p.command.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(3 * time.Second):
		p.cancel()
		select {
		case <-p.done:
		case <-time.After(2 * time.Second):
			t.Error("Xray did not exit after cancellation")
		}
	}
	if _, err := os.Stat("/proc/" + strconv.Itoa(p.command.Process.Pid)); !errors.Is(err, os.ErrNotExist) {
		t.Error("Xray process still exists after wait")
	}
}

func spikeWaitSocket(t *testing.T, ctx context.Context, process *spikeProcess, socket string) {
	t.Helper()
	deadline := time.NewTimer(8 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-process.done:
			process.stopped = true
			process.cancel()
			t.Fatal("Xray exited before the private socket was ready")
		case <-ctx.Done():
			t.Fatal("Xray start canceled")
		case <-deadline.C:
			t.Fatal("Xray did not create the private socket")
		case <-tick.C:
			info, err := os.Lstat(socket)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				t.Fatal("cannot inspect the API socket")
			}
			owner, ok := sandbox.FileOwner(info)
			if !ok || owner != os.Geteuid() || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
				t.Fatal("API socket is not a private filesystem socket")
			}
			return
		}
	}
}

func spikeRemoveSocket(t *testing.T, socket string) {
	t.Helper()
	for _, name := range []string{socket, socket + ".lock"} {
		if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal("socket cleanup failed")
		}
	}
}

// ---- 只读 StatsService 与监听集合 -----------------------------------------

func spikeQuery(t *testing.T, parent context.Context, binary *Binary, socket, pattern string) []spikeStat {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary.path, "api", "statsquery", "-server=unix://"+socket, "-timeout=3", "-pattern="+pattern)
	command.Dir = binary.root
	command.Env = []string{"LANG=C", "LC_ALL=C"}
	command.WaitDelay = time.Second
	stdout, stderr := &boundedOutput{data: make([]byte, 0, 8192)}, &boundedOutput{data: make([]byte, 0, 8192)}
	defer func() { clear(stdout.data); clear(stderr.data) }()
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil || stdout.overflow || stderr.overflow {
		t.Fatal("read-only StatsService query failed or exceeded its bound")
	}
	var response struct {
		Stats []spikeStat `json:"stat"`
	}
	if err := json.Unmarshal(stdout.data, &response); err != nil {
		t.Fatal("StatsService response is invalid JSON")
	}
	return response.Stats
}

type spikeStat struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
}

func spikeRequireCounters(t *testing.T, ctx context.Context, binary *Binary, socket string) {
	t.Helper()
	stats := spikeQuery(t, ctx, binary, socket, "inbound>>>qwq-in-proof>>>traffic>>>")
	if len(stats) != 2 {
		t.Fatal("inbound policy did not expose both counters")
	}
	want := map[string]bool{"inbound>>>qwq-in-proof>>>traffic>>>uplink": true, "inbound>>>qwq-in-proof>>>traffic>>>downlink": true}
	for _, stat := range stats {
		// CLI 的零值可能按 proto JSON 省略；int64 也可能编码成字符串。
		value := string(stat.Value)
		if !want[stat.Name] || value != "" && value != "0" && value != `"0"` {
			t.Fatal("unexpected inbound counter name or initial value")
		}
		delete(want, stat.Name)
	}
	if len(spikeQuery(t, ctx, binary, socket, "qwq-counter-that-does-not-exist")) != 0 {
		t.Fatal("missing counter query returned fabricated data")
	}
	users := spikeQuery(t, ctx, binary, socket, "user>>>qwq-user-proof>>>traffic>>>")
	t.Logf("read-only stats: two inbound counters at zero; missing series empty; user series before handshake=%d", len(users))
}

func spikeListeners(t *testing.T) map[int]bool {
	t.Helper()
	ports := make(map[int]bool)
	for _, name := range []string{"/proc/self/net/tcp", "/proc/self/net/tcp6"} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal("cannot inspect the isolated network namespace")
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			address := strings.Split(fields[1], ":")
			if len(address) != 2 {
				t.Fatal("invalid listener address")
			}
			port, err := strconv.ParseUint(address[1], 16, 16)
			if err != nil {
				t.Fatal("invalid listener port")
			}
			ports[int(port)] = true
		}
	}
	return ports
}

func spikeRequireListeners(t *testing.T, baseline map[int]bool, businessPort int) {
	t.Helper()
	current := spikeListeners(t)
	expected := len(baseline)
	if businessPort != 0 && !baseline[businessPort] {
		expected++
	}
	if len(current) != expected {
		t.Fatal("unexpected TCP listener count in the isolated namespace")
	}
	for port := range current {
		if !baseline[port] && port != businessPort {
			t.Fatal("Xray exposed an extra TCP listener")
		}
	}
}
