// Package protocol defines the DNS tunnel wire format used by server and client.
//
// # Wire format
//
// Each DNS tunnel message is encoded in the query QNAME:
//
//	c.<session>.<b32_labels(host:port)>.<domain>   — connect to upstream host
//	d.<session>.<8hex_seq>.<b32_labels(data)>.<domain> — send data upstream
//	p.<session>.<8hex_ack>.<domain>                — poll for downstream data
//	x.<session>.<domain>                           — close session
//
// The server always replies with a TXT record whose first string contains a
// status line in one of the following forms:
//
//	OK                 — connect succeeded
//	DATA:<b32_data>    — downstream data payload
//	ACK                — no data available right now
//	EOF                — upstream connection closed
//	ERR:<message>      — error description
//
// Data is encoded with base32 (standard alphabet, no padding) so that every
// character in a DNS label is in the range [A-Z2-7].  Labels are capped at 63
// characters as required by RFC 1035.
//
// # Compression
//
// Every non-empty payload is run through an adaptive zlib compression step
// before base32-encoding.  A single prefix byte is prepended to signal which
// path was taken:
//
//	0x00 — raw (compression did not reduce the size)
//	0x01 — zlib best-compression
//
// Both sides always apply compressPayload on encode and decompressPayload on
// decode, so the format is self-describing and transparent to callers.
package protocol

import (
	"bytes"
	"compress/zlib"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"io"
	"strings"
)

// Command tokens embedded as the first DNS label of every tunnel query.
const (
	CmdConnect = "c"
	CmdData    = "d"
	CmdPoll    = "p"
	CmdClose   = "x"
	// CmdProbe is used for the startup connection probe and authentication
	// handshake.  The client sends a probe before accepting any SOCKS5
	// connections; the server validates the HMAC token and replies with OK.
	CmdProbe = "h"
)

// Status tokens returned in the TXT response from the server.
const (
	RespOK    = "OK"
	RespData  = "DATA"
	RespAck   = "ACK"
	RespEOF   = "EOF"
	RespError = "ERR"
)

// MaxUpstreamChunk is the maximum number of raw bytes encoded in a single
// upstream DNS query.  100 bytes ⇒ 160 base32 characters ⇒ three 53-char
// labels, keeping the total QNAME well under the 253-character RFC limit.
const MaxUpstreamChunk = 100

// enc is base32 without padding (padding '=' is invalid in a DNS label).
var enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// compressPayload prepends a 1-byte flag and optionally compresses data with
// zlib BestCompression before base32 encoding:
//
//	0x00 prefix — raw copy (compression would have made the payload larger)
//	0x01 prefix — zlib-compressed
//
// Empty input is returned as nil so that zero-length payloads continue to
// round-trip as empty base32 strings.
func compressPayload(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}

	var buf bytes.Buffer
	w, _ := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	_, _ = w.Write(data)
	_ = w.Close()

	if buf.Len() < len(data) {
		// Compression helped: return 0x01 || compressed.
		result := make([]byte, 1+buf.Len())
		result[0] = 0x01
		copy(result[1:], buf.Bytes())
		return result
	}

	// Compression did not help: return 0x00 || raw.
	result := make([]byte, 1+len(data))
	result[0] = 0x00
	copy(result[1:], data)
	return result
}

// decompressPayload reverses compressPayload. It reads the flag byte and either
// returns the raw payload or decompresses it with zlib.
// Empty input is returned as nil (matching compressPayload's behaviour).
func decompressPayload(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	flag, payload := data[0], data[1:]
	switch flag {
	case 0x00:
		return payload, nil
	case 0x01:
		r, err := zlib.NewReader(bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("zlib new reader: %w", err)
		}
		defer r.Close()
		out, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("zlib decompress: %w", err)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unknown compression flag %#x", flag)
	}
}

// Encode returns the base32-encoded representation of data.
func Encode(data []byte) string {
	return enc.EncodeToString(data)
}

// Decode decodes a base32 string (case-insensitive) back to bytes.
func Decode(s string) ([]byte, error) {
	return enc.DecodeString(strings.ToUpper(s))
}

// splitLabels breaks a string into DNS labels of at most 63 characters each.
func splitLabels(s string) []string {
	var labels []string
	for len(s) > 0 {
		n := 63
		if n > len(s) {
			n = len(s)
		}
		labels = append(labels, s[:n])
		s = s[n:]
	}
	return labels
}

// ComputeToken derives a fixed-length base32 authentication token from a
// shared secret and a session identifier using HMAC-SHA256.  The first 16
// bytes of the MAC are encoded, yielding a 26-character base32 string that
// fits in a single DNS label.
//
// When secret is empty the function still returns a valid (but trivially
// forgeable) token; the server skips validation when no secret is configured.
func ComputeToken(secret, session string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(session))
	return Encode(mac.Sum(nil)[:16])
}

// BuildProbeQuery returns the QNAME for the startup probe / authentication
// handshake.  token = ComputeToken(secret, session).
func BuildProbeQuery(session, secret, domain string) string {
	token := ComputeToken(secret, session)
	return fmt.Sprintf("%s.%s.%s.%s", CmdProbe, session, token, domain)
}

// BuildConnectQuery returns the QNAME for a connect request.
func BuildConnectQuery(session, domain, host string, port uint16) string {
	payload := Encode(compressPayload([]byte(fmt.Sprintf("%s:%d", host, port))))
	parts := []string{CmdConnect, session}
	parts = append(parts, splitLabels(payload)...)
	parts = append(parts, domain)
	return strings.Join(parts, ".")
}

// BuildDataQuery returns the QNAME for an upstream data transfer.
func BuildDataQuery(session string, seq uint32, data []byte, domain string) string {
	payload := Encode(compressPayload(data))
	parts := []string{CmdData, session, fmt.Sprintf("%08x", seq)}
	parts = append(parts, splitLabels(payload)...)
	parts = append(parts, domain)
	return strings.Join(parts, ".")
}

// BuildPollQuery returns the QNAME for a downstream-data poll.
func BuildPollQuery(session string, ack uint32, domain string) string {
	return fmt.Sprintf("%s.%s.%08x.%s", CmdPoll, session, ack, domain)
}

// BuildCloseQuery returns the QNAME for a session-close notification.
func BuildCloseQuery(session, domain string) string {
	return fmt.Sprintf("%s.%s.%s", CmdClose, session, domain)
}

// Query is the parsed representation of a tunnel QNAME.
type Query struct {
	// Cmd is one of CmdConnect, CmdData, CmdPoll, CmdClose, CmdProbe.
	Cmd string
	// Session is the 8-character hex session identifier.
	Session string
	// Seq is the client sequence number (CmdData) or ack value (CmdPoll).
	Seq uint32
	// Data is the decoded payload (CmdData or CmdConnect).
	Data []byte
	// Host and Port are the upstream destination (CmdConnect only).
	Host string
	Port uint16
	// Token is the HMAC authentication token (CmdProbe only).
	Token string
}

// ParseQuery parses a DNS QNAME into a Query, stripping the given domain suffix.
func ParseQuery(qname, domain string) (*Query, error) {
	qname = strings.TrimSuffix(qname, ".")
	domain = strings.TrimSuffix(domain, ".")

	suffix := "." + domain
	if !strings.HasSuffix(strings.ToLower(qname), strings.ToLower(suffix)) {
		return nil, fmt.Errorf("not our domain: %s", qname)
	}
	// Strip domain suffix (case-insensitive comparison already done above)
	qname = qname[:len(qname)-len(suffix)]

	parts := strings.Split(qname, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("query too short: %q", qname)
	}

	q := &Query{
		Cmd:     strings.ToLower(parts[0]),
		Session: strings.ToLower(parts[1]),
	}

	switch q.Cmd {
	case CmdConnect:
		if len(parts) < 3 {
			return nil, fmt.Errorf("connect query missing payload")
		}
		b32 := strings.Join(parts[2:], "")
		compressed, err := Decode(b32)
		if err != nil {
			return nil, fmt.Errorf("decode connect payload: %w", err)
		}
		data, err := decompressPayload(compressed)
		if err != nil {
			return nil, fmt.Errorf("decompress connect payload: %w", err)
		}
		addr := string(data)
		idx := strings.LastIndex(addr, ":")
		if idx < 0 {
			return nil, fmt.Errorf("invalid connect address %q", addr)
		}
		q.Host = addr[:idx]
		var port int
		if _, err = fmt.Sscanf(addr[idx+1:], "%d", &port); err != nil {
			return nil, fmt.Errorf("invalid port in %q: %w", addr, err)
		}
		q.Port = uint16(port)

	case CmdData:
		if len(parts) < 3 {
			return nil, fmt.Errorf("data query missing sequence number")
		}
		var seq uint64
		if _, err := fmt.Sscanf(parts[2], "%x", &seq); err != nil {
			return nil, fmt.Errorf("parse seq %q: %w", parts[2], err)
		}
		q.Seq = uint32(seq)
		if len(parts) > 3 {
			b32 := strings.Join(parts[3:], "")
			compressed, err := Decode(b32)
			if err != nil {
				return nil, fmt.Errorf("decode data payload: %w", err)
			}
			q.Data, err = decompressPayload(compressed)
			if err != nil {
				return nil, fmt.Errorf("decompress data payload: %w", err)
			}
		}

	case CmdPoll:
		if len(parts) < 3 {
			return nil, fmt.Errorf("poll query missing ack")
		}
		var ack uint64
		if _, err := fmt.Sscanf(parts[2], "%x", &ack); err != nil {
			return nil, fmt.Errorf("parse ack %q: %w", parts[2], err)
		}
		q.Seq = uint32(ack)

	case CmdClose:
		// no additional fields required

	case CmdProbe:
		if len(parts) < 3 {
			return nil, fmt.Errorf("probe query missing token")
		}
		q.Token = parts[2]

	default:
		return nil, fmt.Errorf("unknown command %q", q.Cmd)
	}

	return q, nil
}

// BuildResponse formats a TXT response string from the server.
// data may be nil/empty for non-DATA responses.
func BuildResponse(status string, data []byte) string {
	if len(data) == 0 {
		return status
	}
	return status + ":" + Encode(compressPayload(data))
}

// ParseResponse splits a TXT response string into its status and optional payload.
// Only DATA responses carry a base32-encoded compressed payload; all other statuses
// (including ERR:message) carry plain-text after the colon.
func ParseResponse(txt string) (status string, data []byte, err error) {
	idx := strings.IndexByte(txt, ':')
	if idx < 0 {
		return txt, nil, nil
	}
	status = txt[:idx]
	rest := txt[idx+1:]
	if rest == "" {
		return status, nil, nil
	}

	if status != RespData {
		// Non-DATA payloads (e.g. ERR:message) are plain text.
		return status, []byte(rest), nil
	}

	compressed, err := Decode(rest)
	if err != nil {
		return "", nil, fmt.Errorf("decode response payload: %w", err)
	}
	data, err = decompressPayload(compressed)
	if err != nil {
		return "", nil, fmt.Errorf("decompress response payload: %w", err)
	}
	return status, data, nil
}
