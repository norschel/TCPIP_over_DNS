// Command client runs the DNS tunnel client / local SOCKS5 proxy.
//
// Usage:
//
//	client [flags]
//
// Flags:
//
//	-proxy    string   SOCKS5 listen address              (default "127.0.0.1:1080")
//	-dns      string   DNS tunnel server address (host:port) (default "127.0.0.1:53")
//	-domain   string   DNS tunnel domain                  (default "tunnel.example.com")
//
// Example — start the client then use curl through the SOCKS5 proxy:
//
//	client -dns 203.0.113.1:53 -domain tunnel.example.com -proxy 127.0.0.1:1080
//	curl --socks5 127.0.0.1:1080 http://example.com/
package main

import (
	"flag"
	"log"

	"github.com/norschel/TCPIP_over_DNS/internal/client"
)

func main() {
	proxy := flag.String("proxy", "127.0.0.1:1080", "SOCKS5 proxy listen address")
	dns := flag.String("dns", "127.0.0.1:53", "DNS tunnel server address (host:port)")
	domain := flag.String("domain", "tunnel.example.com", "DNS tunnel domain")
	secret := flag.String("secret", "", "shared secret for authentication (empty = no auth)")
	flag.Parse()

	c := client.New(*domain, *dns, *secret)
	if err := c.ListenAndServe(*proxy); err != nil {
		log.Fatalf("client error: %v", err)
	}
}
