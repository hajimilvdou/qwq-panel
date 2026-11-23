// SPDX-License-Identifier: AGPL-3.0-only

package anytls

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// LosslessEpochAligner 将 AnyTLS 进程内单调累计流量表无损对齐到当前 Xray snapshot.Epoch：
//   - 当 xrayEpoch 未变时：返回 monotonicTotals[k] - epochBase[k]（正常单调递增）；
//   - 当 Xray 子进程重启导致 xrayEpoch 切换时：将新纪元的 epochBase 锚定在 lastObserved（上次已被采走的值），
//     使得新纪元首包 projected = currentTotal - lastObserved，既不翻倍重扣历史流量，也不丢失切换窗口内的真实增量。
type LosslessEpochAligner struct {
	mu           sync.Mutex
	currentEpoch string
	lastObserved map[string]int64
	epochBase    map[string]int64
}

// NewLosslessEpochAligner 创建无损跨纪元流量对齐器。
func NewLosslessEpochAligner() *LosslessEpochAligner {
	return &LosslessEpochAligner{
		lastObserved: make(map[string]int64),
		epochBase:    make(map[string]int64),
	}
}

// ProjectForEpoch 将 AnyTLS 累计计数器投影到指定 xrayEpoch。
func (a *LosslessEpochAligner) ProjectForEpoch(xrayEpoch string, monotonicTotals map[string]int64) map[string]int64 {
	if a == nil || len(monotonicTotals) == 0 || xrayEpoch == "" {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.currentEpoch == "" {
		a.currentEpoch = xrayEpoch
	} else if a.currentEpoch != xrayEpoch {
		for k, obs := range a.lastObserved {
			a.epochBase[k] = obs
		}
		for k, cur := range monotonicTotals {
			if _, seen := a.epochBase[k]; !seen {
				a.epochBase[k] = 0
			}
			if cur < a.epochBase[k] {
				a.epochBase[k] = 0
			}
		}
		a.currentEpoch = xrayEpoch
	}

	out := make(map[string]int64, len(monotonicTotals))
	for k, cur := range monotonicTotals {
		base := a.epochBase[k]
		if cur < base {
			base = 0
			a.epochBase[k] = 0
		}
		out[k] = cur - base
		a.lastObserved[k] = cur
	}
	return out
}

// GenerateProcessEpoch 为纯 AnyTLS 独立运行场景生成稳定纪元号。
func GenerateProcessEpoch() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "atls_" + hex.EncodeToString(b[:])
}

const (
	linuxSOLSocket = 1  // unix.SOL_SOCKET
	linuxSOMark    = 36 // unix.SO_MARK (Linux amd64/arm64)
)

// setsockoptIntBestEffort 由平台构建文件（mark_linux.go / mark_other.go）绑定。
var setsockoptIntBestEffort = func(fd uintptr, level, opt, value int) error {
	return nil
}

// DialOutboundWithMark 在 AnyTLS 拨号目标地址时尝试打上用户的 traffic_mark（0x5100..0x51FF）；
// 无 CAP_NET_ADMIN 权限时静默忽略，绝不阻断正常代理连接。
func DialOutboundWithMark(ctx context.Context, network, address string, trafficMark uint32, timeout time.Duration) (net.Conn, error) {
	return dialOutboundWithPolicyAndMark(ctx, network, address, trafficMark, timeout, false)
}

func dialOutboundWithPolicyAndMark(ctx context.Context, network, address string, trafficMark uint32, timeout time.Duration, enforcePublic bool) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout, KeepAlive: tcpKeepAlivePeriod}
	wantMark := trafficMark >= 0x5100 && trafficMark <= 0x51FF
	if enforcePublic || wantMark {
		d.Control = func(_, addr string, c syscall.RawConn) error {
			if enforcePublic {
				host, portStr, err := net.SplitHostPort(addr)
				if err != nil {
					return ErrBlockedDestination
				}
				port, err := strconv.Atoi(portStr)
				if err != nil || port < 1 || port > 65535 {
					return ErrBlockedDestination
				}
				ip, err := netip.ParseAddr(host)
				if err != nil || !IsPublicOutboundAddr(ip) {
					return ErrBlockedDestination
				}
			}
			if wantMark {
				_ = c.Control(func(fd uintptr) {
					_ = setsockoptIntBestEffort(fd, linuxSOLSocket, linuxSOMark, int(trafficMark))
				})
			}
			return nil
		}
	}
	return d.DialContext(ctx, network, address)
}

// TokenBucketShaper 是并发安全的每用户共享带宽令牌桶（支持多连接聚合共享同一速率上限）。
type TokenBucketShaper struct {
	rateBytesPerSec atomic.Int64 // <= 0 表示不限速
	mu              sync.Mutex
	tokens          float64
	lastRefill      time.Time
}

// NewTokenBucketShaper 按 Kbps 创建令牌桶（0 表示不限速）。
func NewTokenBucketShaper(kbps uint32) *TokenBucketShaper {
	s := &TokenBucketShaper{lastRefill: time.Now()}
	s.SetLimitKbps(kbps)
	return s
}

// SetLimitKbps 动态调整每用户限速（Kbps，0 表示不限速）。
func (s *TokenBucketShaper) SetLimitKbps(kbps uint32) {
	if s == nil {
		return
	}
	if kbps == 0 {
		s.rateBytesPerSec.Store(0)
		return
	}
	bps := int64(kbps) * 1000 / 8
	if bps < 1024 {
		bps = 1024
	}
	s.rateBytesPerSec.Store(bps)
}

// WaitN 在必要时等待足够令牌以执行 n 字节传输。
func (s *TokenBucketShaper) WaitN(ctx context.Context, n int) error {
	if s == nil || n <= 0 {
		return nil
	}
	rate := s.rateBytesPerSec.Load()
	if rate <= 0 {
		return nil
	}
	burst := float64(max(rate/2, 32<<10)) // 0.5s 突发窗口，最低 32 KiB 保障 TLS 握手流畅

	for remaining := n; remaining > 0; {
		step := min(remaining, int(burst))
		s.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(s.lastRefill).Seconds()
		if elapsed > 0 {
			s.tokens = min(burst, s.tokens+elapsed*float64(rate))
			s.lastRefill = now
		}
		if s.tokens >= float64(step) {
			s.tokens -= float64(step)
			s.mu.Unlock()
			remaining -= step
			continue
		}
		deficit := float64(step) - s.tokens
		s.tokens = 0
		waitDur := time.Duration(deficit / float64(rate) * float64(time.Second))
		s.mu.Unlock()

		if waitDur > 0 {
			timer := time.NewTimer(waitDur)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		remaining -= step
	}
	return nil
}

// WrapConnWithUserShaper 包装用户代理连接，使单用户多连接并发与非 fwmark 路径均受限于上下行带宽。
func WrapConnWithUserShaper(ctx context.Context, c net.Conn, upShaper, downShaper *TokenBucketShaper) net.Conn {
	if upShaper == nil && downShaper == nil {
		return c
	}
	return &shapedConn{
		Conn: c,
		ctx:  ctx,
		up:   upShaper,
		down: downShaper,
	}
}

type shapedConn struct {
	net.Conn
	ctx  context.Context
	up   *TokenBucketShaper // 客户端 -> 服务端上行读取
	down *TokenBucketShaper // 服务端 -> 客户端下行写出
}

func (c *shapedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && c.up != nil {
		if werr := c.up.WaitN(c.ctx, n); werr != nil && err == nil {
			return n, io.ErrClosedPipe
		}
	}
	return n, err
}

func (c *shapedConn) Write(p []byte) (int, error) {
	if len(p) > 0 && c.down != nil {
		if werr := c.down.WaitN(c.ctx, len(p)); werr != nil {
			return 0, io.ErrClosedPipe
		}
	}
	return c.Conn.Write(p)
}
