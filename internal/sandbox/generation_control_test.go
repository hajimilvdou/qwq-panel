// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

// ======================== 策略测试只验证固定句柄消费，不伪装真实 systemd/cgroup 证明 ========================

func generationTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func generationStopTestProof() ProcessProof {
	return ProcessProof{Version: 1, Unit: "qwq-plugin@alpha.service", PID: 42, KernelStartTicks: 123, UID: 1234,
		BootID: "0123456789abcdef0123456789abcdef", InvocationID: "fedcba9876543210fedcba9876543210",
		Cgroup: "/system.slice/qwq-plugin@alpha.service", CgroupDevice: 1, CgroupInode: 2}
}

type generationStopFixture struct {
	proof       ProcessProof
	exited      bool
	empty       bool
	exitAfter   GenerationSignal
	clearOnExit bool
	signalErr   error
	exitErr     error
	groupErr    error
	closeErr    error
	signals     []GenerationSignal
	closeCalls  int
}

func (fixture *generationStopFixture) Proof() ProcessProof { return fixture.proof }

func (fixture *generationStopFixture) Signal(signal GenerationSignal) error {
	fixture.signals = append(fixture.signals, signal)
	if fixture.signalErr != nil {
		return fixture.signalErr
	}
	if signal == fixture.exitAfter {
		fixture.exited = true
		if fixture.clearOnExit {
			fixture.empty = true
		}
	}
	return nil
}

func (fixture *generationStopFixture) OriginalExited(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return fixture.exited, fixture.exitErr
}

func (fixture *generationStopFixture) OriginalCgroupEmpty(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return fixture.empty, fixture.groupErr
}

func (fixture *generationStopFixture) Close() error {
	fixture.closeCalls++
	return fixture.closeErr
}

func generationStopTestPolicy() GenerationStopPolicy {
	return GenerationStopPolicy{Timeout: 80 * time.Millisecond, Grace: 10 * time.Millisecond, CheckEvery: time.Millisecond}
}

func TestGenerationStopRequiresExactProofBeforeSignal(t *testing.T) {
	proof := generationStopTestProof()
	changes := []struct {
		name string
		edit func(*ProcessProof)
	}{
		{"boot", func(value *ProcessProof) { value.BootID = "1123456789abcdef0123456789abcdef" }},
		{"ticks", func(value *ProcessProof) { value.KernelStartTicks++ }},
		{"invocation", func(value *ProcessProof) { value.InvocationID = "eedcba9876543210fedcba9876543210" }},
		{"uid", func(value *ProcessProof) { value.UID++ }},
		{"root", func(value *ProcessProof) { value.UID = 0 }},
		{"inode", func(value *ProcessProof) { value.CgroupInode++ }},
		{"device", func(value *ProcessProof) { value.CgroupDevice++ }},
		{"pid", func(value *ProcessProof) { value.PID++ }},
		{"cgroup", func(value *ProcessProof) { value.Cgroup = "/other.slice/qwq-plugin@alpha.service" }},
		{"zero", func(value *ProcessProof) { *value = ProcessProof{} }},
	}
	for _, change := range changes {
		t.Run(change.name, func(t *testing.T) {
			actual := proof
			change.edit(&actual)
			fixture := &generationStopFixture{proof: actual, exited: true, empty: true}
			if _, err := StopPinnedGeneration(generationTestContext(t), "alpha", proof, fixture, generationStopTestPolicy()); !errors.Is(err, ErrGenerationIdentity) {
				t.Fatalf("身份失配未拒绝：%v", err)
			}
			if len(fixture.signals) != 0 || fixture.closeCalls != 1 {
				t.Fatalf("拒绝路径发信号或未关闭：signals=%v close=%d", fixture.signals, fixture.closeCalls)
			}
		})
	}
}

func TestGenerationStopEscalatesOnlyPinnedHandle(t *testing.T) {
	proof := generationStopTestProof()
	fixture := &generationStopFixture{proof: proof, exitAfter: GenerationKill, clearOnExit: true}
	observation, err := StopPinnedGeneration(generationTestContext(t), "alpha", proof, fixture, generationStopTestPolicy())
	if err != nil || observation.ValidateCompleted("alpha", proof) != nil {
		t.Fatalf("原主与原组完整退出未确认：%+v %v", observation, err)
	}
	if !slices.Equal(fixture.signals, []GenerationSignal{GenerationTerminate, GenerationContinue, GenerationKill}) || fixture.closeCalls != 1 {
		t.Fatalf("固定停止序列或关闭错误：%v close=%d", fixture.signals, fixture.closeCalls)
	}
}

func TestGenerationStopExitedMainDoesNotCompletePopulatedGroup(t *testing.T) {
	proof := generationStopTestProof()
	fixture := &generationStopFixture{proof: proof, exited: true}
	observation, err := StopPinnedGeneration(generationTestContext(t), "alpha", proof, fixture, generationStopTestPolicy())
	if !errors.Is(err, ErrGenerationUnconfirmed) || !errors.Is(err, context.DeadlineExceeded) || !observation.OriginalExited || observation.OriginalCgroupEmpty {
		t.Fatalf("主退出被误当成旧组完成：%+v %v", observation, err)
	}
	if slices.Contains(fixture.signals, GenerationKill) || fixture.closeCalls != 1 {
		t.Fatalf("原主已退出仍升级或未关闭：%v close=%d", fixture.signals, fixture.closeCalls)
	}
}

func TestGenerationStopCancellationClosesWithoutSignal(t *testing.T) {
	ctx, cancel := context.WithCancel(generationTestContext(t))
	cancel()
	proof := generationStopTestProof()
	fixture := &generationStopFixture{proof: proof}
	if _, err := StopPinnedGeneration(ctx, "alpha", proof, fixture, generationStopTestPolicy()); !errors.Is(err, context.Canceled) {
		t.Fatalf("取消未返回：%v", err)
	}
	if len(fixture.signals) != 0 || fixture.closeCalls != 1 {
		t.Fatalf("取消路径发信号或未关闭：%v close=%d", fixture.signals, fixture.closeCalls)
	}
}

func TestGenerationStopErrorsCloseAndRemainErrors(t *testing.T) {
	proof := generationStopTestProof()
	for _, failure := range []string{"signal", "poll", "events", "close"} {
		t.Run(failure, func(t *testing.T) {
			cause := errors.New("test " + failure)
			fixture := &generationStopFixture{proof: proof, exited: true, empty: true}
			switch failure {
			case "signal":
				fixture.signalErr = cause
			case "poll":
				fixture.exitErr = cause
			case "events":
				fixture.groupErr = cause
			case "close":
				fixture.closeErr = cause
			}
			if _, err := StopPinnedGeneration(generationTestContext(t), "alpha", proof, fixture, generationStopTestPolicy()); !errors.Is(err, cause) {
				t.Fatalf("关键错误被吞掉：%v", err)
			}
			if fixture.closeCalls != 1 {
				t.Fatalf("错误路径未关闭：%d", fixture.closeCalls)
			}
		})
	}
}

func TestGenerationStopCannotWidenRequestBudget(t *testing.T) {
	proof := generationStopTestProof()
	fixture := &generationStopFixture{proof: proof}
	ctx, cancel := context.WithTimeout(generationTestContext(t), 5*time.Millisecond)
	defer cancel()
	if _, err := StopPinnedGeneration(ctx, "alpha", proof, fixture, generationStopTestPolicy()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("父请求期限未生效：%v", err)
	}
	if fixture.closeCalls != 1 || slices.Contains(fixture.signals, GenerationKill) {
		t.Fatalf("请求期限后继续升级或未关闭：%v close=%d", fixture.signals, fixture.closeCalls)
	}
	fixture = &generationStopFixture{proof: proof}
	policy := generationStopTestPolicy()
	policy.Timeout = DefaultGenerationStopTimeout + time.Second
	if _, err := StopPinnedGeneration(generationTestContext(t), "alpha", proof, fixture, policy); err == nil || len(fixture.signals) != 0 || fixture.closeCalls != 1 {
		t.Fatalf("允许扩大总预算：%v signals=%v close=%d", err, fixture.signals, fixture.closeCalls)
	}
}
