// Package client implements the DNS tunnel client.
//
// The client exposes a SOCKS5 proxy on a local TCP address.  When an
// application connects to the proxy and issues a CONNECT request, the client
// creates a DNS tunnel session to the server, encodes outgoing data as DNS
// queries, and feeds incoming data (carried in DNS responses) back to the
// application.
package client

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/norschel/TCPIP_over_DNS/internal/protocol"
)

// session holds client-side state for one tunneled TCP connection.
type session struct {
	id     string
	seq    uint32 // monotonically increasing sequence number for upstream data
	target string // "host:port" requested by the application

	// sendBuf buffers data read from the local SOCKS5 connection,
	// waiting to be sent upstream via DNS queries.
	sendBuf  []byte
	mu       sync.Mutex
	connTime time.Time

	closed bool

	// Traffic counters — updated only inside the relay loop (single goroutine),
	// so no additional synchronisation is needed.
	upBytes      int64 // raw payload bytes sent upstream (before encoding)
	downBytes    int64 // raw payload bytes received downstream (after decoding)
	dataQueries  int64 // DNS data queries issued (carry upstream payload)
	pollQueries  int64 // DNS poll queries issued (no payload)
	qnameBytes   int64 // sum of QNAME lengths sent (DNS wire overhead measure)
}

// Client is the DNS tunnel client / SOCKS5 proxy.
type Client struct {
	domain    string
	dnsServer string // host:port of the tunnel DNS server
	dnsClient *dns.Client
}

// New creates a new Client that tunnels through the given DNS server and domain.
// dnsServer should be in "host:port" format (e.g. "192.168.1.1:53").
func New(domain, dnsServer string) *Client {
	return &Client{
		domain:    domain,
		dnsServer: dnsServer,
		dnsClient: &dns.Client{
			Net:     "udp",
			Timeout: 5 * time.Second,
		},
	}
}

// ListenAndServe starts the SOCKS5 proxy on addr (e.g. "127.0.0.1:1080").
func (c *Client) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	defer ln.Close()

	log.Printf("[client] SOCKS5 proxy on %s, tunneling through %s (domain: %s)",
		addr, c.dnsServer, c.domain)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		go c.handleConn(conn)
	}
}

// handleConn processes a single SOCKS5 connection.
func (c *Client) handleConn(conn net.Conn) {
	defer conn.Close()

	host, port, err := socks5Handshake(conn)
	if err != nil {
		log.Printf("[client] SOCKS5 handshake: %v", err)
		return
	}

	log.Printf("[client] SOCKS5 CONNECT -> %s:%d", host, port)

	sess := &session{
		id:       newSessionID(),
		target:   net.JoinHostPort(host, strconv.Itoa(int(port))),
		connTime: time.Now(),
	}

	// Establish the tunnel connection on the server side.
	if err := c.dnsConnect(sess, host, port); err != nil {
		log.Printf("[client] DNS connect session=%s: %v", sess.id, err)
		// Reply: general SOCKS failure
		_, _ = conn.Write(socks5Reply(0x01))
		return
	}

	// Reply: success (bind address 0.0.0.0:0)
	_, _ = conn.Write(socks5Reply(0x00))

	c.relay(conn, sess)
}

// dnsConnect sends a connect query and waits for OK.
func (c *Client) dnsConnect(sess *session, host string, port uint16) error {
	qname := protocol.BuildConnectQuery(sess.id, c.domain, host, port)
	txt, err := c.queryTXT(qname)
	if err != nil {
		return fmt.Errorf("DNS query: %w", err)
	}
	status, _, err := protocol.ParseResponse(txt)
	if err != nil {
		return fmt.Errorf("parse response: %w", err)
	}
	if status != protocol.RespOK {
		return fmt.Errorf("server returned %q", txt)
	}
	return nil
}

// relay bidirectionally relays data between localConn and the DNS tunnel.
func (c *Client) relay(localConn net.Conn, sess *session) {
	defer sess.logSummary()

	// Reader goroutine: continuously reads from the local connection and
	// appends received bytes to sess.sendBuf.
	go func() {
		buf := make([]byte, 4096)
		for {
			_ = localConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, err := localConn.Read(buf)
			if n > 0 {
				sess.mu.Lock()
				sess.sendBuf = append(sess.sendBuf, buf[:n]...)
				sess.mu.Unlock()
			}
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				sess.mu.Lock()
				sess.closed = true
				sess.mu.Unlock()
				return
			}
		}
	}()

	// Main DNS polling loop.
	for {
		sess.mu.Lock()
		closed := sess.closed
		var chunk []byte
		if len(sess.sendBuf) > 0 {
			n := len(sess.sendBuf)
			if n > protocol.MaxUpstreamChunk {
				n = protocol.MaxUpstreamChunk
			}
			chunk = make([]byte, n)
			copy(chunk, sess.sendBuf[:n])
			sess.sendBuf = sess.sendBuf[n:]
		}
		sess.mu.Unlock()

		if closed {
			c.dnsClose(sess)
			return
		}

		var (
			txt string
			err error
		)
		if len(chunk) > 0 {
			txt, err = c.dnsSend(sess, chunk)
		} else {
			txt, err = c.dnsPoll(sess)
		}
		if err != nil {
			log.Printf("[client] DNS error session=%s: %v", sess.id, err)
			time.Sleep(200 * time.Millisecond)
			// Put the chunk back if we failed to send it.
			if len(chunk) > 0 {
				sess.mu.Lock()
				sess.sendBuf = append(chunk, sess.sendBuf...)
				sess.mu.Unlock()
			}
			continue
		}

		status, data, err := protocol.ParseResponse(txt)
		if err != nil {
			log.Printf("[client] parse response session=%s: %v", sess.id, err)
			continue
		}

		// Count upstream payload after a successful send.
		if len(chunk) > 0 && (status == protocol.RespData || status == protocol.RespAck) {
			sess.upBytes += int64(len(chunk))
		}

		switch status {
		case protocol.RespEOF:
			log.Printf("[client] session %s: upstream EOF", sess.id)
			return
		case protocol.RespError:
			log.Printf("[client] session %s: server error: %s", sess.id, string(data))
			return
		case protocol.RespData:
			sess.downBytes += int64(len(data))
			if _, err := localConn.Write(data); err != nil {
				log.Printf("[client] session %s local write: %v", sess.id, err)
				c.dnsClose(sess)
				return
			}
		case protocol.RespAck:
			// No downstream data; back off briefly to reduce DNS traffic.
			if len(chunk) == 0 {
				time.Sleep(50 * time.Millisecond)
			}
		}
	}
}

func (c *Client) dnsSend(sess *session, data []byte) (string, error) {
	sess.seq++
	qname := protocol.BuildDataQuery(sess.id, sess.seq, data, c.domain)
	sess.dataQueries++
	sess.qnameBytes += int64(len(qname))
	return c.queryTXT(qname)
}

func (c *Client) dnsPoll(sess *session) (string, error) {
	qname := protocol.BuildPollQuery(sess.id, sess.seq, c.domain)
	sess.pollQueries++
	sess.qnameBytes += int64(len(qname))
	return c.queryTXT(qname)
}

func (c *Client) dnsClose(sess *session) {
	qname := protocol.BuildCloseQuery(sess.id, c.domain)
	_, _ = c.queryTXT(qname)
	log.Printf("[client] session %s closed", sess.id)
}

// queryTXT sends a DNS TXT query and returns the first TXT string in the answer.
func (c *Client) queryTXT(qname string) (string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), dns.TypeTXT)
	m.RecursionDesired = false

	r, _, err := c.dnsClient.Exchange(m, c.dnsServer)
	if err != nil {
		return "", fmt.Errorf("exchange %q: %w", qname, err)
	}
	if r.Rcode != dns.RcodeSuccess {
		return "", fmt.Errorf("DNS rcode %s for %q", dns.RcodeToString[r.Rcode], qname)
	}
	for _, ans := range r.Answer {
		if t, ok := ans.(*dns.TXT); ok && len(t.Txt) > 0 {
			return t.Txt[0], nil
		}
	}
	return "", fmt.Errorf("no TXT record in response for %q", qname)
}

// logSummary emits a structured statistics log line for the session.
//
// Example output:
//
//	[client] session a1b2c3d4 CLOSED | target=example.com:443 | duration=3.2s | up=4096B down=2048B | queries=data:45 poll:12 | qname_bytes=12800 | upstream_efficiency=32%
func (s *session) logSummary() {
	duration := time.Since(s.connTime).Round(time.Millisecond)

	// upstream efficiency = raw payload bytes / QNAME bytes sent for data queries.
	// Shows what fraction of DNS traffic carries real data (higher = more efficient).
	efficiency := "N/A"
	if s.qnameBytes > 0 {
		efficiency = fmt.Sprintf("%d%%", s.upBytes*100/s.qnameBytes)
	}

	log.Printf("[client] session %s CLOSED | target=%s | duration=%s | up=%dB down=%dB | queries=data:%d poll:%d | qname_bytes=%d | upstream_efficiency=%s",
		s.id, s.target, duration, s.upBytes, s.downBytes,
		s.dataQueries, s.pollQueries, s.qnameBytes, efficiency)
}

// newSessionID generates a random 8-character lowercase hex session ID using
// crypto/rand to prevent predictable session enumeration.
func newSessionID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return fmt.Sprintf("%08x", b)
}

// ────────────────────────────────────────────────────────────────────────────
// SOCKS5 helpers
// ────────────────────────────────────────────────────────────────────────────

// socks5Handshake performs the SOCKS5 greeting + request handshake and returns
// the target host and port requested by the client application.
func socks5Handshake(conn net.Conn) (host string, port uint16, err error) {
	// 1. Greeting: VER(1) NMETHODS(1) METHODS(NMETHODS)
	buf := make([]byte, 2)
	if _, err = io.ReadFull(conn, buf); err != nil {
		return "", 0, fmt.Errorf("read greeting header: %w", err)
	}
	if buf[0] != 0x05 {
		return "", 0, fmt.Errorf("unsupported SOCKS version %d", buf[0])
	}
	nmethods := int(buf[1])
	methods := make([]byte, nmethods)
	if _, err = io.ReadFull(conn, methods); err != nil {
		return "", 0, fmt.Errorf("read methods: %w", err)
	}

	// 2. Method selection: always choose NO AUTH (0x00).
	hasNoAuth := false
	for _, m := range methods {
		if m == 0x00 {
			hasNoAuth = true
			break
		}
	}
	if !hasNoAuth {
		_, _ = conn.Write([]byte{0x05, 0xFF}) // no acceptable methods
		return "", 0, fmt.Errorf("no acceptable authentication method")
	}
	if _, err = conn.Write([]byte{0x05, 0x00}); err != nil {
		return "", 0, fmt.Errorf("write method selection: %w", err)
	}

	// 3. Request: VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR(var) DST.PORT(2)
	hdr := make([]byte, 4)
	if _, err = io.ReadFull(conn, hdr); err != nil {
		return "", 0, fmt.Errorf("read request header: %w", err)
	}
	if hdr[0] != 0x05 {
		return "", 0, fmt.Errorf("unsupported SOCKS version in request %d", hdr[0])
	}
	if hdr[1] != 0x01 {
		_, _ = conn.Write(socks5Reply(0x07)) // command not supported
		return "", 0, fmt.Errorf("unsupported command %d (only CONNECT is supported)", hdr[1])
	}

	// Parse address.
	switch hdr[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err = io.ReadFull(conn, addr); err != nil {
			return "", 0, fmt.Errorf("read IPv4 address: %w", err)
		}
		host = net.IP(addr).String()
	case 0x03: // domain name
		lenBuf := make([]byte, 1)
		if _, err = io.ReadFull(conn, lenBuf); err != nil {
			return "", 0, fmt.Errorf("read domain length: %w", err)
		}
		domBuf := make([]byte, lenBuf[0])
		if _, err = io.ReadFull(conn, domBuf); err != nil {
			return "", 0, fmt.Errorf("read domain: %w", err)
		}
		host = string(domBuf)
	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err = io.ReadFull(conn, addr); err != nil {
			return "", 0, fmt.Errorf("read IPv6 address: %w", err)
		}
		host = net.IP(addr).String()
	default:
		_, _ = conn.Write(socks5Reply(0x08)) // address type not supported
		return "", 0, fmt.Errorf("unsupported address type %d", hdr[3])
	}

	// Port (2 bytes, big-endian).
	portBuf := make([]byte, 2)
	if _, err = io.ReadFull(conn, portBuf); err != nil {
		return "", 0, fmt.Errorf("read port: %w", err)
	}
	port = binary.BigEndian.Uint16(portBuf)
	return host, port, nil
}

// socks5Reply builds a minimal SOCKS5 reply with the given reply code.
// The bound address is 0.0.0.0:0 (not meaningful for a tunnel proxy).
func socks5Reply(code byte) []byte {
	return []byte{0x05, code, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
}
