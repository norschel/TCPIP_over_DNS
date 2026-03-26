// Package server implements the DNS tunnel server.
//
// The server listens for DNS TXT queries on a configured domain, manages
// upstream TCP sessions, and returns downstream data in TXT responses.
package server

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/norschel/TCPIP_over_DNS/internal/protocol"
)

// session holds state for one tunneled TCP connection.
type session struct {
	id   string
	conn net.Conn

	// target is the upstream "host:port" this session is connected to.
	target   string
	connTime time.Time

	// downBuf buffers data read from the upstream TCP connection,
	// waiting to be returned to the client in DNS responses.
	downBuf []byte
	downMu  sync.Mutex

	// seenSeqs tracks recently processed client sequence numbers to detect
	// duplicates and replayed UDP packets. The window size is sufficient to
	// cover any realistic UDP jitter while bounding memory usage.
	seenSeqs [32]uint32
	seenIdx  int  // circular-buffer write index
	seenFull bool // true once the buffer has wrapped at least once

	closed   bool
	lastSeen time.Time

	// Traffic counters — updated with sync/atomic so they are safe to read
	// from any goroutine without holding downMu.
	upBytes      int64 // raw payload bytes written to the upstream TCP connection
	downBytes    int64 // raw bytes read from the upstream TCP connection
	dnsQueries   int64 // total tunnel DNS queries handled for this session
	dnsQnameBytes int64 // sum of QNAME lengths received (DNS wire overhead)
}

// Server is the DNS tunnel server.
type Server struct {
	domain   string
	sessions map[string]*session
	mu       sync.RWMutex
}

// New creates a new Server that handles queries for the given domain.
func New(domain string) *Server {
	s := &Server{
		domain:   domain,
		sessions: make(map[string]*session),
	}
	go s.cleanupLoop()
	return s
}

// cleanupLoop removes stale sessions every 30 seconds.
func (s *Server) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		for id, sess := range s.sessions {
			if time.Since(sess.lastSeen) > 5*time.Minute {
				sess.conn.Close()
				delete(s.sessions, id)
				sess.logSummary("expired")
			}
		}
		s.mu.Unlock()
	}
}

// ServeDNS implements dns.Handler.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.RecursionAvailable = false

	if len(r.Question) == 0 {
		_ = w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	if q.Qtype != dns.TypeTXT {
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}

	log.Printf("[server] DNS query: %s", q.Name)

	query, err := protocol.ParseQuery(q.Name, s.domain)
	if err != nil {
		log.Printf("[server] parse error for %q: %v", q.Name, err)
		m.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(m)
		return
	}

	var txt string
	switch query.Cmd {
	case protocol.CmdConnect:
		txt = s.handleConnect(query)
	case protocol.CmdData:
		txt = s.handleData(query, len(q.Name))
	case protocol.CmdPoll:
		txt = s.handlePoll(query, len(q.Name))
	case protocol.CmdClose:
		txt = s.handleClose(query)
	default:
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}

	m.Answer = append(m.Answer, &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		Txt: []string{txt},
	})
	_ = w.WriteMsg(m)
}

func (s *Server) handleConnect(q *protocol.Query) string {
	addr := net.JoinHostPort(q.Host, portStr(q.Port))
	log.Printf("[server] CONNECT session=%s target=%s", q.Session, addr)

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		log.Printf("[server] CONNECT FAILED session=%s target=%s: %v", q.Session, addr, err)
		return protocol.RespError + ":" + err.Error()
	}

	sess := &session{
		id:       q.Session,
		conn:     conn,
		target:   addr,
		connTime: time.Now(),
		lastSeen: time.Now(),
	}

	s.mu.Lock()
	// Close any pre-existing session with the same ID.
	if old, ok := s.sessions[q.Session]; ok {
		old.conn.Close()
	}
	s.sessions[q.Session] = sess
	s.mu.Unlock()

	go s.readUpstream(sess)
	return protocol.RespOK
}

func (s *Server) readUpstream(sess *session) {
	buf := make([]byte, 4096)
	for {
		n, err := sess.conn.Read(buf)
		if n > 0 {
			atomic.AddInt64(&sess.downBytes, int64(n))
			sess.downMu.Lock()
			sess.downBuf = append(sess.downBuf, buf[:n]...)
			sess.downMu.Unlock()
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[server] session %s upstream read: %v", sess.id, err)
			}
			sess.downMu.Lock()
			sess.closed = true
			sess.downMu.Unlock()
			return
		}
	}
}

func (s *Server) handleData(q *protocol.Query, qnameLen int) string {
	s.mu.RLock()
	sess, ok := s.sessions[q.Session]
	s.mu.RUnlock()
	if !ok {
		return protocol.RespError + ":nosession"
	}

	sess.lastSeen = time.Now()
	atomic.AddInt64(&sess.dnsQueries, 1)
	atomic.AddInt64(&sess.dnsQnameBytes, int64(qnameLen))

	if sess.isDuplicateSeq(q.Seq) {
		log.Printf("[server] session %s duplicate seq %d, skipping write", q.Session, q.Seq)
	} else {
		sess.recordSeq(q.Seq)
		if len(q.Data) > 0 {
			atomic.AddInt64(&sess.upBytes, int64(len(q.Data)))
			if _, err := sess.conn.Write(q.Data); err != nil {
				log.Printf("[server] session %s write: %v", q.Session, err)
				return protocol.RespError + ":" + err.Error()
			}
		}
	}

	return s.drainDownstream(sess)
}

func (s *Server) handlePoll(q *protocol.Query, qnameLen int) string {
	s.mu.RLock()
	sess, ok := s.sessions[q.Session]
	s.mu.RUnlock()
	if !ok {
		return protocol.RespError + ":nosession"
	}
	sess.lastSeen = time.Now()
	atomic.AddInt64(&sess.dnsQueries, 1)
	atomic.AddInt64(&sess.dnsQnameBytes, int64(qnameLen))
	return s.drainDownstream(sess)
}

func (s *Server) handleClose(q *protocol.Query) string {
	s.mu.Lock()
	sess, ok := s.sessions[q.Session]
	if ok {
		delete(s.sessions, q.Session)
	}
	s.mu.Unlock()

	if ok {
		sess.conn.Close()
		sess.logSummary("closed by client")
	}
	return protocol.RespOK
}

// drainDownstream returns a response TXT string containing up to
// MaxUpstreamChunk bytes from the session's downstream buffer.
func (s *Server) drainDownstream(sess *session) string {
	sess.downMu.Lock()
	defer sess.downMu.Unlock()

	if len(sess.downBuf) == 0 {
		if sess.closed {
			return protocol.RespEOF
		}
		return protocol.RespAck
	}

	n := len(sess.downBuf)
	if n > protocol.MaxUpstreamChunk {
		n = protocol.MaxUpstreamChunk
	}
	chunk := make([]byte, n)
	copy(chunk, sess.downBuf[:n])
	sess.downBuf = sess.downBuf[n:]

	return protocol.BuildResponse(protocol.RespData, chunk)
}

// logSummary emits a structured statistics log line for the session.
//
// Example output:
//
//	[server] session a1b2c3d4 closed by client | target=93.184.216.34:80 | duration=3.2s | up=1024B down=2048B | dns_queries=32 | qname_bytes=4096 | overhead=4.0x
func (s *session) logSummary(reason string) {
	up := atomic.LoadInt64(&s.upBytes)
	down := atomic.LoadInt64(&s.downBytes)
	queries := atomic.LoadInt64(&s.dnsQueries)
	qnameBytes := atomic.LoadInt64(&s.dnsQnameBytes)
	duration := time.Since(s.connTime).Round(time.Millisecond)

	// overhead = DNS QNAME bytes / raw payload bytes (higher = more overhead)
	overhead := "N/A"
	if up > 0 {
		overhead = fmt.Sprintf("%.1fx", float64(qnameBytes)/float64(up))
	}

	log.Printf("[server] session %s %s | target=%s | duration=%s | up=%dB down=%dB | dns_queries=%d | qname_bytes=%d | overhead=%s",
		s.id, reason, s.target, duration, up, down, queries, qnameBytes, overhead)
}

// ListenAndServe starts the DNS server on addr (e.g. ":53") over UDP and TCP.
func (s *Server) ListenAndServe(addr string) error {
	mux := dns.NewServeMux()
	mux.Handle(s.domain+".", s)

	errCh := make(chan error, 2)

	udpSrv := &dns.Server{Addr: addr, Net: "udp", Handler: mux}
	tcpSrv := &dns.Server{Addr: addr, Net: "tcp", Handler: mux}

	log.Printf("[server] DNS tunnel server listening on %s (UDP+TCP) for domain %s", addr, s.domain)

	go func() { errCh <- udpSrv.ListenAndServe() }()
	go func() { errCh <- tcpSrv.ListenAndServe() }()

	return <-errCh
}

// portStr converts a uint16 port number to its decimal string representation.
func portStr(p uint16) string {
	return strconv.Itoa(int(p))
}

// isDuplicateSeq reports whether seq has already been processed.
func (s *session) isDuplicateSeq(seq uint32) bool {
	limit := s.seenIdx
	if s.seenFull {
		limit = len(s.seenSeqs)
	}
	for i := 0; i < limit; i++ {
		if s.seenSeqs[i] == seq {
			return true
		}
	}
	return false
}

// recordSeq adds seq to the circular seen-sequence window.
func (s *session) recordSeq(seq uint32) {
	s.seenSeqs[s.seenIdx] = seq
	s.seenIdx++
	if s.seenIdx >= len(s.seenSeqs) {
		s.seenIdx = 0
		s.seenFull = true
	}
}
