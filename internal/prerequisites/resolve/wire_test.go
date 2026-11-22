// SPDX-License-Identifier: AGPL-3.0-only

package resolve

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"golang.org/x/net/dns/dnsmessage"
)

// ======================== 实际 DNS 编解码与 TCP 回退 ========================

type wireConnection struct {
	network string
	data    *bytes.Reader
	wrong   bool
}

func (c *wireConnection) Write(data []byte) (int, error) {
	query := data
	if c.network == "tcp" {
		query = data[2:]
	}
	var request dnsmessage.Message
	if request.Unpack(query) != nil {
		return 0, io.ErrUnexpectedEOF
	}
	message := response(request.Questions[0], request.RecursionDesired, []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: request.Questions[0].Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}, Body: &dnsmessage.TXTResource{TXT: []string{"answer"}}}})
	message.ID = request.ID
	if c.wrong {
		message.ID++
	}
	if c.network == "udp" {
		message.Truncated = true
	}
	packed, err := message.Pack()
	if err != nil {
		return 0, err
	}
	if c.network == "udp" {
		packed = packed[:len(packed)-3]
	} else {
		frame := make([]byte, len(packed)+2)
		binary.BigEndian.PutUint16(frame[:2], uint16(len(packed)))
		copy(frame[2:], packed)
		packed = frame
	}
	c.data = bytes.NewReader(packed)
	return len(data), nil
}
func (c *wireConnection) Read(data []byte) (int, error)  { return c.data.Read(data) }
func (*wireConnection) Close() error                     { return nil }
func (*wireConnection) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*wireConnection) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*wireConnection) SetDeadline(time.Time) error      { return nil }
func (*wireConnection) SetReadDeadline(time.Time) error  { return nil }
func (*wireConnection) SetWriteDeadline(time.Time) error { return nil }

type wireDialer struct {
	networks []string
	wrong    bool
}

func (d *wireDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	if address != "1.1.1.1:53" {
		return nil, io.ErrUnexpectedEOF
	}
	d.networks = append(d.networks, network)
	return &wireConnection{network: network, wrong: d.wrong}, nil
}

func TestSystemExchangeRetriesTruncatedUDPWithSameQuestionOverTCP(t *testing.T) {
	dialer := &wireDialer{}
	exchange := &SystemExchange{Dialer: dialer, Random: bytes.NewReader([]byte{1, 2})}
	q, err := question("_acme-challenge.example.com", dnsmessage.TypeTXT)
	if err != nil {
		t.Fatal(err)
	}
	message, err := exchange.Query(context.Background(), netip.MustParseAddr("1.1.1.1"), q, true)
	if err != nil || message.Truncated || len(message.Answers) != 1 {
		t.Fatalf("TCP fallback = %v %v", message, err)
	}
	if len(dialer.networks) != 2 || dialer.networks[0] != "udp" || dialer.networks[1] != "tcp" {
		t.Fatal("truncated response did not use bounded TCP fallback")
	}
}

func TestSystemExchangeRejectsMismatchedIDAndPrivateEndpoint(t *testing.T) {
	dialer := &wireDialer{wrong: true}
	exchange := &SystemExchange{Dialer: dialer, Random: bytes.NewReader([]byte{1, 2})}
	q, err := question("example.com", dnsmessage.TypeTXT)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exchange.Query(context.Background(), netip.MustParseAddr("1.1.1.1"), q, true); fault.Code(err) != "DNS_INVALID_RESPONSE" || len(dialer.networks) != 1 {
		t.Fatalf("mismatched ID = %v", err)
	}
	if _, err := exchange.Query(context.Background(), netip.MustParseAddr("127.0.0.1"), q, true); fault.Code(err) != "DNS_UNSAFE_SERVER" {
		t.Fatalf("private source = %v", err)
	}
}
