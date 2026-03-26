// Command server runs the DNS tunnel server.
//
// Usage:
//
//	server [flags]
//
// Flags:
//
//	-addr   string   UDP/TCP address to listen on (default ":53")
//	-domain string   DNS tunnel domain (default "tunnel.example.com")
//
// The server must be authoritative for the tunnel domain.  Point an NS record
// at the machine running this binary, or use -domain with a name that your
// resolver forwards to this server.
package main

import (
	"flag"
	"log"

	"github.com/norschel/TCPIP_over_DNS/internal/server"
)

func main() {
	addr := flag.String("addr", ":53", "address to listen on (UDP+TCP)")
	domain := flag.String("domain", "tunnel.example.com", "DNS tunnel domain")
	secret := flag.String("secret", "", "shared secret for authentication (empty = no auth)")
	flag.Parse()

	s := server.New(*domain, *secret)
	if err := s.ListenAndServe(*addr); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
