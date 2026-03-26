# TCP/IP over DNS

A DNS tunneling tool written in Go that transports TCP/IP traffic over DNS queries and responses.  
The **client** runs as a local SOCKS5 proxy; the **server** acts as a custom DNS authority and relays traffic to its final upstream destination.

---

## How it works

```
Application ──SOCKS5──▶ Client (local proxy)
                              │
                         DNS queries (TXT)
                              │
                              ▼
                        Server (DNS authority)
                              │
                         TCP connection
                              │
                              ▼
                       Upstream host/port
```

1. An application connects to the local SOCKS5 proxy and issues a `CONNECT` request.
2. The client encodes the target address and any payload bytes as base32 sub-labels in a DNS query QNAME and sends a `TXT` query to the tunnel DNS server.
3. The server decodes the query, opens a real TCP connection to the upstream host, and echoes any downstream data back as a `TXT` record in the DNS response.
4. The client feeds the response data back to the application. Polling queries carry no upstream data when the application is idle.

### Wire format

| Direction | Encoding |
|-----------|----------|
| Upstream (client → server) | QNAME: `<cmd>.<session>.<seq>.<base32-data>.<domain>` |
| Downstream (server → client) | TXT record: `STATUS[:<base32-data>]` |

Commands: `c` = connect, `d` = data, `p` = poll, `x` = close  
Statuses: `OK`, `DATA`, `ACK`, `EOF`, `ERR`

Data is encoded with **base32** (RFC 4648, no padding) so every DNS label character is in the set `[A-Z2-7]`.  Each label is capped at 63 characters and the total QNAME stays well under the 253-character DNS limit.

---

## Prerequisites

- Go 1.21 or later

---

## Building

```bash
go build -o dns-tunnel-server ./cmd/server
go build -o dns-tunnel-client ./cmd/client
```

---

## Running

### Server

The server must be reachable as the **authoritative DNS server** for the tunnel domain (add an `NS` record pointing to its public IP, or configure your resolver to forward queries for that domain to it).

```bash
# Listen on all interfaces, port 53, for the domain "tunnel.example.com"
sudo ./dns-tunnel-server -addr ":53" -domain "tunnel.example.com"
```

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `:53` | UDP/TCP listen address |
| `-domain` | `tunnel.example.com` | DNS tunnel domain |

### Client

```bash
# Forward queries to the server at 203.0.113.1:53, expose SOCKS5 on localhost:1080
./dns-tunnel-client \
    -dns    "203.0.113.1:53" \
    -domain "tunnel.example.com" \
    -proxy  "127.0.0.1:1080"
```

| Flag | Default | Description |
|------|---------|-------------|
| `-proxy` | `127.0.0.1:1080` | SOCKS5 listen address |
| `-dns` | `127.0.0.1:53` | DNS tunnel server address (`host:port`) |
| `-domain` | `tunnel.example.com` | DNS tunnel domain |

### Using the proxy

```bash
# curl
curl --socks5 127.0.0.1:1080 http://example.com/

# wget
wget --execute "use_proxy = on" \
     --execute "socks_proxy = socks5://127.0.0.1:1080" \
     http://example.com/

# ssh (requires netcat-openbsd for ProxyCommand)
ssh -o "ProxyCommand=nc -x 127.0.0.1:1080 %h %p" user@remote-host
```

---

## Running the tests

```bash
go test ./...
```

---

## Project layout

```
.
├── cmd/
│   ├── client/main.go   — client entrypoint (SOCKS5 proxy)
│   └── server/main.go   — server entrypoint (DNS authority)
├── internal/
│   ├── client/          — SOCKS5 proxy + DNS query engine
│   ├── protocol/        — shared wire-format encoding/decoding
│   └── server/          — DNS handler + upstream session management
├── go.mod
└── go.sum
```

---

## Security notes

* This tool is a **playground / educational project**.  DNS tunneling is detectable and is intentionally simple — it does not attempt to evade inspection.
* All traffic between the client and server is **unencrypted**.  Do not use it to carry sensitive data.
* The server connects to any host/port requested by the client.  Deploy it on a trusted network or add your own allow-list.
