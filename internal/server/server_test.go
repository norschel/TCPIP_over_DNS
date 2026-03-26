package server_test

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/norschel/TCPIP_over_DNS/internal/protocol"
	"github.com/norschel/TCPIP_over_DNS/internal/server"
)

// startEchoServer starts a TCP echo server on a random port and returns its address.
func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// startDNSServer starts the tunnel server on a random UDP/TCP port and returns
// a dns.Client already configured to reach it.
func startDNSServer(t *testing.T, domain string) (dnsAddr string) {
	t.Helper()

	// Find a free UDP port.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	dnsAddr = pc.LocalAddr().String()
	pc.Close()

	srv := server.New(domain, "" /* no auth */)
	go func() {
		// We ignore the error because the server is stopped by test cleanup.
		_ = srv.ListenAndServe(dnsAddr)
	}()
	// Give the server a moment to start.
	time.Sleep(100 * time.Millisecond)
	return dnsAddr
}

// queryTXT is a helper that sends a single TXT query and returns the first answer.
func queryTXT(t *testing.T, c *dns.Client, server, qname string) string {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), dns.TypeTXT)
	m.RecursionDesired = false

	r, _, err := c.Exchange(m, server)
	if err != nil {
		t.Fatalf("DNS exchange %q: %v", qname, err)
	}
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("DNS rcode %s for %q", dns.RcodeToString[r.Rcode], qname)
	}
	for _, ans := range r.Answer {
		if txt, ok := ans.(*dns.TXT); ok && len(txt.Txt) > 0 {
			return txt.Txt[0]
		}
	}
	t.Fatalf("no TXT answer for %q", qname)
	return ""
}

// TestServerConnectDataClose exercises the full connect → send → receive → close cycle.
func TestServerConnectDataClose(t *testing.T) {
	const domain = "test.tunnel"
	echoAddr := startEchoServer(t)
	dnsAddr := startDNSServer(t, domain)

	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}

	// Parse echo server host and port.
	echoHost, echoPortStr, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatalf("split echo addr: %v", err)
	}
	var echoPort uint16
	fmt.Sscan(echoPortStr, &echoPort)

	session := "deadbeef"

	// 1. Connect
	connectQ := protocol.BuildConnectQuery(session, domain, echoHost, echoPort)
	resp := queryTXT(t, c, dnsAddr, connectQ)
	status, _, err := protocol.ParseResponse(resp)
	if err != nil {
		t.Fatalf("parse connect response: %v", err)
	}
	if status != protocol.RespOK {
		t.Fatalf("connect: want OK, got %q", resp)
	}

	// 2. Send data
	payload := []byte("hello DNS tunnel")
	dataQ := protocol.BuildDataQuery(session, 1, payload, domain)
	// The echo server may not have responded yet; poll until we get the echo.
	var received []byte
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp = queryTXT(t, c, dnsAddr, dataQ)
		status, data, err := protocol.ParseResponse(resp)
		if err != nil {
			t.Fatalf("parse data response: %v", err)
		}
		switch status {
		case protocol.RespData:
			received = append(received, data...)
		case protocol.RespAck:
			// Still waiting; poll
			time.Sleep(50 * time.Millisecond)
			pollQ := protocol.BuildPollQuery(session, 1, domain)
			resp = queryTXT(t, c, dnsAddr, pollQ)
			status, data, err = protocol.ParseResponse(resp)
			if err != nil {
				t.Fatalf("parse poll response: %v", err)
			}
			if status == protocol.RespData {
				received = append(received, data...)
			}
		}
		if bytes.Equal(received, payload) {
			break
		}
	}
	if !bytes.Equal(received, payload) {
		t.Errorf("echo mismatch: want %q, got %q", payload, received)
	}

	// 3. Close
	closeQ := protocol.BuildCloseQuery(session, domain)
	resp = queryTXT(t, c, dnsAddr, closeQ)
	status, _, _ = protocol.ParseResponse(resp)
	if status != protocol.RespOK {
		t.Errorf("close: want OK, got %q", resp)
	}
}

// TestServerNoSession verifies that data/poll queries for unknown sessions return ERR.
func TestServerNoSession(t *testing.T) {
	const domain = "test.tunnel"
	dnsAddr := startDNSServer(t, domain)

	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}

	pollQ := protocol.BuildPollQuery("ffffffff", 0, domain)
	resp := queryTXT(t, c, dnsAddr, pollQ)
	status, _, _ := protocol.ParseResponse(resp)
	if status != protocol.RespError {
		t.Errorf("expected ERR for unknown session, got %q", resp)
	}
}

// TestServerDuplicateDataQuery verifies that replaying a data query (same seq) does
// not cause the same bytes to be written to the upstream connection twice.
func TestServerDuplicateDataQuery(t *testing.T) {
	const domain = "test.tunnel"
	echoAddr := startEchoServer(t)
	dnsAddr := startDNSServer(t, domain)

	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}

	echoHost, echoPortStr, _ := net.SplitHostPort(echoAddr)
	var echoPort uint16
	fmt.Sscan(echoPortStr, &echoPort)

	session := "aabb1122"

	// Connect
	connectQ := protocol.BuildConnectQuery(session, domain, echoHost, echoPort)
	queryTXT(t, c, dnsAddr, connectQ)

	// Send the same data query twice (simulates UDP retry).
	payload := []byte("dedup_test")
	dataQ := protocol.BuildDataQuery(session, 1, payload, domain)

	// collect is a helper that appends DATA payloads from a TXT response.
	collect := func(resp string) []byte {
		status, data, _ := protocol.ParseResponse(resp)
		if status == protocol.RespData {
			return data
		}
		return nil
	}

	var received []byte
	received = append(received, collect(queryTXT(t, c, dnsAddr, dataQ))...)
	received = append(received, collect(queryTXT(t, c, dnsAddr, dataQ))...) // duplicate

	// Poll until we have the full echo (the echo might not be ready immediately).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !bytes.Equal(received, payload) {
		pollQ := protocol.BuildPollQuery(session, 1, domain)
		resp := queryTXT(t, c, dnsAddr, pollQ)
		received = append(received, collect(resp)...)
		if !bytes.Equal(received, payload) {
			time.Sleep(50 * time.Millisecond)
		}
	}

	// We should have received exactly one copy of the payload.
	if !bytes.Equal(received, payload) {
		t.Errorf("dedup test: want %q, got %q", payload, received)
	}
}

// startDNSServerWithSecret starts the tunnel server configured with a shared secret.
func startDNSServerWithSecret(t *testing.T, domain, secret string) (dnsAddr string) {
t.Helper()

pc, err := net.ListenPacket("udp", "127.0.0.1:0")
if err != nil {
t.Fatalf("find free port: %v", err)
}
dnsAddr = pc.LocalAddr().String()
pc.Close()

srv := server.New(domain, secret)
go func() {
_ = srv.ListenAndServe(dnsAddr)
}()
time.Sleep(100 * time.Millisecond)
return dnsAddr
}

// TestServerProbe_NoAuth verifies that a probe succeeds when the server has
// no authentication configured.
func TestServerProbe_NoAuth(t *testing.T) {
const domain = "test.tunnel"
dnsAddr := startDNSServer(t, domain)

c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}

session := "probe001"
probeQ := protocol.BuildProbeQuery(session, "" /* no secret */, domain)
resp := queryTXT(t, c, dnsAddr, probeQ)
status, _, err := protocol.ParseResponse(resp)
if err != nil {
t.Fatalf("ParseResponse: %v", err)
}
if status != protocol.RespOK {
t.Errorf("want OK, got %q", resp)
}
}

// TestServerProbe_CorrectSecret verifies that a probe with the correct HMAC
// token is accepted when the server requires a shared secret.
func TestServerProbe_CorrectSecret(t *testing.T) {
const (
domain = "test.tunnel"
secret = "supersecret"
)
dnsAddr := startDNSServerWithSecret(t, domain, secret)

c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}

session := "probe002"
probeQ := protocol.BuildProbeQuery(session, secret, domain)
resp := queryTXT(t, c, dnsAddr, probeQ)
status, _, err := protocol.ParseResponse(resp)
if err != nil {
t.Fatalf("ParseResponse: %v", err)
}
if status != protocol.RespOK {
t.Errorf("want OK, got %q", resp)
}
}

// TestServerProbe_WrongSecret verifies that a probe with an incorrect HMAC
// token is rejected when the server requires a shared secret.
func TestServerProbe_WrongSecret(t *testing.T) {
const (
domain       = "test.tunnel"
serverSecret = "supersecret"
clientSecret = "wrongsecret"
)
dnsAddr := startDNSServerWithSecret(t, domain, serverSecret)

c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}

session := "probe003"
probeQ := protocol.BuildProbeQuery(session, clientSecret, domain)
resp := queryTXT(t, c, dnsAddr, probeQ)
status, _, _ := protocol.ParseResponse(resp)
if status != protocol.RespError {
t.Errorf("want ERR for wrong secret, got %q", resp)
}
}
