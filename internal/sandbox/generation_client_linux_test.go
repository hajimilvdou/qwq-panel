// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package sandbox

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// ======================== 真实 Unix peer 集成；fixture 只回协议数据，不做进程/记录动作 ========================

func generationProtocolClientFixture(t *testing.T, answer func(DecodedHelperRequest) (any, error)) (*HelperClient, *atomic.Int32) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("generation正向协议要求真实root Unix peer，须在Root Linux门禁执行")
	}
	address := "@" + ids.New(nil).New(ids.Generation)
	listener, err := net.Listen("unix", address)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(generationTestContext(t), 2*time.Second)
	done := make(chan struct{})
	var fixtureErr error
	var requests atomic.Int32
	go func() {
		defer close(done)
		connection, err := listener.Accept()
		if err != nil {
			fixtureErr = err
			return
		}
		defer connection.Close()
		deadline, _ := ctx.Deadline()
		if err := connection.SetDeadline(deadline); err != nil {
			fixtureErr = err
			return
		}
		raw, err := ReadHelperDocument(bufio.NewReaderSize(connection, 64<<10))
		defer clear(raw)
		if err != nil {
			fixtureErr = err
			return
		}
		request, err := DecodePrivilegedHelperRequest(raw)
		if err != nil {
			fixtureErr = err
			return
		}
		requests.Add(1)
		response, err := answer(request)
		if err != nil {
			fixtureErr = err
			return
		}
		fixtureErr = WriteHelperJSON(connection, response)
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		select {
		case <-done:
			if fixtureErr != nil && !errors.Is(fixtureErr, net.ErrClosed) {
				t.Errorf("协议fixture失败：%v", fixtureErr)
			}
		case <-time.After(time.Second):
			t.Error("协议fixture未回收")
		}
	})
	client := NewHelperClient("/run/qwq/generation-test.sock")
	client.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", address)
	}
	return client, &requests
}

func TestGenerationClientUsesRootPeerAndExactObserve(t *testing.T) {
	proof := generationProtocolStopFixture().Expected
	client, count := generationProtocolClientFixture(t, func(request DecodedHelperRequest) (any, error) {
		if request.Observe == nil || request.Observe.ID != "alpha" {
			return nil, errors.New("incorrect observe request")
		}
		return GenerationObserveResponse{GenerationResponseStatus: GenerationResponseStatus{OK: true}, Observed: &proof}, nil
	})
	observed, err := client.ObserveGeneration(generationTestContext(t), "alpha")
	if err != nil || observed != proof || count.Load() != 1 {
		t.Fatalf("真实root observe协议失败：%+v count=%d %v", observed, count.Load(), err)
	}
}

func TestGenerationClientStopAndRetireExactReference(t *testing.T) {
	request := generationProtocolStopFixture()
	completion := generationProtocolCompletionFixture(t)
	client, count := generationProtocolClientFixture(t, func(decoded DecodedHelperRequest) (any, error) {
		if decoded.Stop == nil || *decoded.Stop != request {
			return nil, errors.New("incorrect bound stop request")
		}
		return GenerationStopResponse{GenerationResponseStatus: GenerationResponseStatus{OK: true}, Stopped: &completion}, nil
	})
	if result, err := client.StopGeneration(generationTestContext(t), request); err != nil || result != completion || count.Load() != 1 {
		t.Fatalf("stop未保留准确引用：%+v %v", result, err)
	}
	ref := completion.Reference
	retire := GenerationRetireRequest{ID: ref.ID, OperationID: ref.OperationID, TargetRef: ref.TargetRef,
		ProofDigest: ref.ProofDigest, ReceiptDigest: ref.ReceiptDigest}
	client, count = generationProtocolClientFixture(t, func(decoded DecodedHelperRequest) (any, error) {
		if decoded.Retire == nil || decoded.Retire.Reference() != ref {
			return nil, errors.New("incorrect retire request")
		}
		return GenerationRetireResponse{GenerationResponseStatus: GenerationResponseStatus{OK: true}, Retired: &ref}, nil
	})
	if result, err := client.RetireGeneration(generationTestContext(t), retire); err != nil || result != ref || count.Load() != 1 {
		t.Fatalf("retire未保留准确引用：%+v %v", result, err)
	}
}

func TestGenerationClientDoesNotAcceptAnotherValidWitnessOrRetry(t *testing.T) {
	request := generationProtocolStopFixture()
	other := request
	other.OperationID = "op_01h455vb4pex5vsknk084sn02r"
	completion, err := NewGenerationCompletion(other, StopObservation{Proof: other.Expected, OriginalExited: true, OriginalCgroupEmpty: true}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	client, count := generationProtocolClientFixture(t, func(DecodedHelperRequest) (any, error) {
		return GenerationStopResponse{GenerationResponseStatus: GenerationResponseStatus{OK: true}, Stopped: &completion}, nil
	})
	if _, err := client.StopGeneration(generationTestContext(t), request); !errors.Is(err, ErrGenerationDocument) || count.Load() != 1 {
		t.Fatalf("跨operation witness被接受/业务被重试：count=%d %v", count.Load(), err)
	}
}

func TestGenerationClientRejectsNonUnixPeerBeforeBody(t *testing.T) {
	server, connection := net.Pipe()
	defer server.Close()
	if err := server.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	type received struct {
		count int
		err   error
	}
	done := make(chan received, 1)
	go func() {
		var body [1]byte
		n, err := server.Read(body[:])
		done <- received{n, err}
	}()
	client := NewHelperClient("/run/qwq/generation-test.sock")
	client.dial = func(context.Context, string, string) (net.Conn, error) { return connection, nil }
	var denied *problem.Error
	if _, err := client.ObserveGeneration(generationTestContext(t), "alpha"); !errors.As(err, &denied) || denied.Code != problem.Unauthenticated {
		t.Fatalf("非Unix peer未作为未认证拒绝：%v", err)
	}
	select {
	case result := <-done:
		if result.count != 0 || !errors.Is(result.err, io.EOF) {
			t.Fatalf("验证peer前写了正文：%+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("非Unix拒绝路径未关闭连接")
	}
}
