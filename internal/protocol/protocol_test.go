package protocol_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/norschel/TCPIP_over_DNS/internal/protocol"
)

// ─── Encode / Decode ─────────────────────────────────────────────────────────

func TestEncodeDecode_RoundTrip(t *testing.T) {
	inputs := [][]byte{
		[]byte("hello world"),
		[]byte{0x00, 0xFF, 0x01, 0xFE},
		make([]byte, 100),
		[]byte("example.com:443"),
	}
	for _, in := range inputs {
		encoded := protocol.Encode(in)
		decoded, err := protocol.Decode(encoded)
		if err != nil {
			t.Fatalf("Decode(%q): %v", encoded, err)
		}
		if !bytes.Equal(in, decoded) {
			t.Fatalf("round-trip mismatch: want %v, got %v", in, decoded)
		}
	}
}

func TestDecode_CaseInsensitive(t *testing.T) {
	src := []byte("hello")
	upper := protocol.Encode(src)
	lower := strings.ToLower(upper)

	dec, err := protocol.Decode(lower)
	if err != nil {
		t.Fatalf("Decode lowercase: %v", err)
	}
	if !bytes.Equal(src, dec) {
		t.Fatalf("case-insensitive decode mismatch: want %q, got %q", src, dec)
	}
}

// ─── Connect query ───────────────────────────────────────────────────────────

func TestBuildParseConnectQuery(t *testing.T) {
	domain := "tunnel.example.com"
	session := "aabbccdd"
	host := "10.0.0.1"
	port := uint16(8080)

	qname := protocol.BuildConnectQuery(session, domain, host, port)

	// Must end with the domain.
	if !strings.HasSuffix(qname, domain) {
		t.Fatalf("qname %q does not end with domain %q", qname, domain)
	}
	// All labels must be ≤63 characters.
	for _, label := range strings.Split(qname, ".") {
		if len(label) > 63 {
			t.Fatalf("label %q exceeds 63 chars", label)
		}
	}

	q, err := protocol.ParseQuery(qname+".", domain)
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}
	if q.Cmd != protocol.CmdConnect {
		t.Errorf("Cmd: want %q, got %q", protocol.CmdConnect, q.Cmd)
	}
	if q.Session != session {
		t.Errorf("Session: want %q, got %q", session, q.Session)
	}
	if q.Host != host {
		t.Errorf("Host: want %q, got %q", host, q.Host)
	}
	if q.Port != port {
		t.Errorf("Port: want %d, got %d", port, q.Port)
	}
}

// ─── Data query ──────────────────────────────────────────────────────────────

func TestBuildParseDataQuery(t *testing.T) {
	domain := "tunnel.example.com"
	session := "deadbeef"
	seq := uint32(42)
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	qname := protocol.BuildDataQuery(session, seq, payload, domain)

	for _, label := range strings.Split(qname, ".") {
		if len(label) > 63 {
			t.Fatalf("label %q exceeds 63 chars", label)
		}
	}

	q, err := protocol.ParseQuery(qname+".", domain)
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}
	if q.Cmd != protocol.CmdData {
		t.Errorf("Cmd: want %q, got %q", protocol.CmdData, q.Cmd)
	}
	if q.Session != session {
		t.Errorf("Session: want %q, got %q", session, q.Session)
	}
	if q.Seq != seq {
		t.Errorf("Seq: want %d, got %d", seq, q.Seq)
	}
	if !bytes.Equal(q.Data, payload) {
		t.Errorf("Data: want %q, got %q", payload, q.Data)
	}
}

func TestDataQuery_MaxChunk(t *testing.T) {
	domain := "t.example.com"
	session := "aabbccdd"
	payload := make([]byte, protocol.MaxUpstreamChunk)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	qname := protocol.BuildDataQuery(session, 1, payload, domain)

	if len(qname) > 253 {
		t.Fatalf("qname length %d exceeds 253-char DNS limit", len(qname))
	}
	for _, label := range strings.Split(qname, ".") {
		if len(label) > 63 {
			t.Fatalf("label %q exceeds 63 chars", label)
		}
	}

	q, err := protocol.ParseQuery(qname+".", domain)
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}
	if !bytes.Equal(q.Data, payload) {
		t.Errorf("Data round-trip failed for MaxUpstreamChunk bytes")
	}
}

// ─── Poll query ──────────────────────────────────────────────────────────────

func TestBuildParsePollQuery(t *testing.T) {
	domain := "tunnel.example.com"
	session := "cafebabe"
	ack := uint32(7)

	qname := protocol.BuildPollQuery(session, ack, domain)

	q, err := protocol.ParseQuery(qname+".", domain)
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}
	if q.Cmd != protocol.CmdPoll {
		t.Errorf("Cmd: want %q, got %q", protocol.CmdPoll, q.Cmd)
	}
	if q.Session != session {
		t.Errorf("Session: want %q, got %q", session, q.Session)
	}
	if q.Seq != ack {
		t.Errorf("Seq/ack: want %d, got %d", ack, q.Seq)
	}
}

// ─── Close query ─────────────────────────────────────────────────────────────

func TestBuildParseCloseQuery(t *testing.T) {
	domain := "tunnel.example.com"
	session := "11223344"

	qname := protocol.BuildCloseQuery(session, domain)

	q, err := protocol.ParseQuery(qname+".", domain)
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}
	if q.Cmd != protocol.CmdClose {
		t.Errorf("Cmd: want %q, got %q", protocol.CmdClose, q.Cmd)
	}
	if q.Session != session {
		t.Errorf("Session: want %q, got %q", session, q.Session)
	}
}

// ─── ParseQuery error cases ───────────────────────────────────────────────────

func TestParseQuery_WrongDomain(t *testing.T) {
	_, err := protocol.ParseQuery("c.aabbccdd.notours.example.com.", "tunnel.example.com")
	if err == nil {
		t.Fatal("expected error for wrong domain, got nil")
	}
}

func TestParseQuery_UnknownCmd(t *testing.T) {
	_, err := protocol.ParseQuery("z.aabbccdd.tunnel.example.com.", "tunnel.example.com")
	if err == nil {
		t.Fatal("expected error for unknown command, got nil")
	}
}

// ─── Response encoding ────────────────────────────────────────────────────────

func TestBuildParseResponse_Data(t *testing.T) {
	payload := []byte("HTTP/1.1 200 OK\r\n\r\nhello")
	txt := protocol.BuildResponse(protocol.RespData, payload)

	status, data, err := protocol.ParseResponse(txt)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if status != protocol.RespData {
		t.Errorf("status: want %q, got %q", protocol.RespData, status)
	}
	if !bytes.Equal(data, payload) {
		t.Errorf("data: want %q, got %q", payload, data)
	}
}

func TestBuildParseResponse_NoData(t *testing.T) {
	for _, s := range []string{protocol.RespOK, protocol.RespAck, protocol.RespEOF} {
		txt := protocol.BuildResponse(s, nil)
		status, data, err := protocol.ParseResponse(txt)
		if err != nil {
			t.Fatalf("ParseResponse(%q): %v", s, err)
		}
		if status != s {
			t.Errorf("status: want %q, got %q", s, status)
		}
		if len(data) != 0 {
			t.Errorf("expected empty data for %q, got %v", s, data)
		}
	}
}
