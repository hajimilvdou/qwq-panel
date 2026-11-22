// SPDX-License-Identifier: AGPL-3.0-only

package resolve

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"golang.org/x/net/dns/dnsmessage"
)

// ======================== DNS UDP 与受限 TCP 回退 ========================

type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type SystemExchange struct {
	Dialer Dialer
	Random io.Reader
	mu     sync.Mutex
}

func (s *SystemExchange) Query(ctx context.Context, server netip.Addr, question dnsmessage.Question, recursive bool) (dnsmessage.Message, error) {
	if !publicServer(server) || question.Class != dnsmessage.ClassINET {
		return dnsmessage.Message{}, fault.New("DNS_UNSAFE_SERVER", "DNS 查询只允许公网服务和 IN 问题")
	}
	s.mu.Lock()
	random := s.Random
	if random == nil {
		random = rand.Reader
	}
	var nonce [2]byte
	_, err := io.ReadFull(random, nonce[:])
	s.mu.Unlock()
	if err != nil {
		return dnsmessage.Message{}, fault.New("DNS_UNAVAILABLE", "无法生成 DNS 请求标识")
	}
	request := dnsmessage.Message{Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(nonce[:]), RecursionDesired: recursive}, Questions: []dnsmessage.Question{question}}
	packed, err := request.Pack()
	if err != nil || len(packed) > 4096 {
		return dnsmessage.Message{}, fault.New("VALIDATION_FAILED", "DNS 问题无法编码")
	}
	response, err := s.exchange(ctx, "udp", server, packed)
	if err != nil {
		return dnsmessage.Message{}, err
	}
	if response.ID != request.ID || !response.Response {
		return dnsmessage.Message{}, fault.New("DNS_INVALID_RESPONSE", "DNS 响应标识不匹配")
	}
	if response.Truncated {
		response, err = s.exchange(ctx, "tcp", server, packed)
		if err != nil {
			return dnsmessage.Message{}, err
		}
		if response.ID != request.ID || !response.Response || response.Truncated {
			return dnsmessage.Message{}, fault.New("DNS_INVALID_RESPONSE", "DNS TCP 回退响应无效")
		}
	}
	return response, nil
}

func (s *SystemExchange) exchange(ctx context.Context, network string, server netip.Addr, query []byte) (dnsmessage.Message, error) {
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ctx = bounded
	dialer := s.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 3 * time.Second}
	}
	connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(server.String(), "53"))
	if err != nil {
		return dnsmessage.Message{}, fault.New("DNS_UNAVAILABLE", "DNS 来源连接失败")
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if connection.SetDeadline(deadline) != nil {
		return dnsmessage.Message{}, fault.New("DNS_UNAVAILABLE", "DNS 查询无法设置硬超时")
	}
	data := query
	if network == "tcp" {
		data = make([]byte, len(query)+2)
		binary.BigEndian.PutUint16(data[:2], uint16(len(query)))
		copy(data[2:], query)
	}
	if written, err := connection.Write(data); err != nil || written != len(data) {
		return dnsmessage.Message{}, fault.New("DNS_UNAVAILABLE", "DNS 问题发送失败")
	}
	var raw []byte
	if network == "tcp" {
		var length [2]byte
		if _, err := io.ReadFull(connection, length[:]); err != nil {
			return dnsmessage.Message{}, fault.New("DNS_UNAVAILABLE", "DNS TCP 响应头读取失败")
		}
		size := int(binary.BigEndian.Uint16(length[:]))
		if size < 12 {
			return dnsmessage.Message{}, fault.New("DNS_INVALID_RESPONSE", "DNS TCP 响应长度无效")
		}
		raw = make([]byte, size)
		if _, err := io.ReadFull(connection, raw); err != nil {
			return dnsmessage.Message{}, fault.New("DNS_UNAVAILABLE", "DNS TCP 响应读取失败")
		}
	} else {
		raw = make([]byte, 65535)
		count, err := connection.Read(raw)
		if err != nil || count < 12 {
			return dnsmessage.Message{}, fault.New("DNS_UNAVAILABLE", "DNS UDP 响应读取失败")
		}
		raw = raw[:count]
	}
	if err := ctx.Err(); err != nil {
		return dnsmessage.Message{}, err
	}
	var result dnsmessage.Message
	var parser dnsmessage.Parser
	header, err := parser.Start(raw)
	if err != nil {
		return dnsmessage.Message{}, fault.New("DNS_INVALID_RESPONSE", "DNS 响应头编码无效")
	}
	// 截断 UDP 可能连最后一条 RDATA 都不完整，只读取头后转受控 TCP。
	if network == "udp" && header.Truncated {
		return dnsmessage.Message{Header: header}, nil
	}
	if result.Unpack(raw) != nil {
		return dnsmessage.Message{}, fault.New("DNS_INVALID_RESPONSE", "DNS 响应编码无效")
	}
	return result, nil
}
