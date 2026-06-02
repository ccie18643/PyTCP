# Socket API — BSD-style data-plane surface

| Field           | Value                                                                                |
|-----------------|--------------------------------------------------------------------------------------|
| Status          | shipped                                                                              |
| Module path     | `pytcp.socket`                                                                       |
| Linux analogue  | `socket(2)` family — `socket`, `bind`, `listen`, `accept`, `connect`, `send`, `recv` |
| Refactor plan   | `docs/refactor/socket_linux_parity_audit.md` (Linux-parity gaps + Phase-1 backlog)   |

## Purpose

The Socket API is PyTCP's data-plane consumer surface — the
canonical way for application code to send / receive packets
through the stack. Mirrors the BSD socket(2) family
verbatim: `socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)`
returns a `TcpSocket`; `socket(AF_INET, SOCK_DGRAM)` returns
a `UdpSocket`; `socket(AF_INET, SOCK_RAW, IPPROTO_X)`
returns a `RawSocket`.

Per CLAUDE.md Phase-3: **the `__new__` factory is the
user/kernel transition**. It validates arguments and
dispatches to the per-flavour socket class; protocol logic
lives in the subclass, not the factory.

## Public namespace

`pytcp.socket` re-exports the BSD-equivalent constants and
the abstract `socket` factory:

| Symbol                                              | Purpose                                                       |
|-----------------------------------------------------|---------------------------------------------------------------|
| `socket(family, type, protocol)`                    | Factory — returns `TcpSocket` / `UdpSocket` / `RawSocket`    |
| `AF_INET` / `AF_INET4` / `AF_INET6`                 | Address-family constants                                      |
| `SOCK_STREAM` / `SOCK_DGRAM` / `SOCK_RAW`           | Socket-type constants                                         |
| `IPPROTO_TCP` / `IPPROTO_UDP` / `IPPROTO_ICMP` etc. | Protocol constants                                            |
| `INADDR_ANY` / `INADDR_BROADCAST` / `INADDR_LOOPBACK` | BSD `<arpa/inet.h>` constants for `bind()` shortcuts        |
| `SocketOption`, `IP_TOS`, `IP_TTL`, …               | `setsockopt` / `getsockopt` option-name constants             |
| `getaddrinfo`, `gethostbyname`, `gethostname`, …    | DNS resolution — re-exported verbatim from CPython's stdlib   |
| `gaierror`                                           | DNS resolution exception                                      |

## Factory contract

```python
import pytcp.socket as sock

# TCP — most common
s = sock.socket(sock.AF_INET, sock.SOCK_STREAM)        # IPPROTO_TCP default
s = sock.socket(sock.AF_INET, sock.SOCK_STREAM, sock.IPPROTO_TCP)

# UDP
s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)         # IPPROTO_UDP default
s = sock.socket(sock.AF_INET6, sock.SOCK_DGRAM)        # IPv6 UDP

# Raw — pick the IP protocol explicitly
s = sock.socket(sock.AF_INET, sock.SOCK_RAW, sock.IPPROTO_ICMP)
```

The factory rejects:

- Unknown address families (only `INET4` / `INET6`).
- Unknown socket types (only `STREAM` / `DGRAM` / `RAW`).
- Family/type/proto combinations that aren't valid
  (e.g. `SOCK_STREAM` with `IPPROTO_UDP`).

## Connection-oriented (TCP) usage

```python
import pytcp.socket as sock

server = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
server.bind(("0.0.0.0", 8080))
server.listen(backlog=16)
conn, peer = server.accept()
data = conn.recv(4096)
conn.send(b"hello\n")
conn.close()
server.close()
```

```python
client = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
client.connect(("10.0.0.1", 8080))
client.send(b"GET / HTTP/1.0\r\n\r\n")
response = client.recv(65536)
client.close()
```

## Connectionless (UDP) usage

```python
import pytcp.socket as sock

s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
s.bind(("0.0.0.0", 5300))
data, peer = s.recvfrom(65535)
s.sendto(b"reply", peer)
s.close()
```

## Socket options

```python
s.setsockopt(sock.IPPROTO_TCP, sock.SocketOption.TCP_NODELAY, 1)
s.setsockopt(sock.SOL_SOCKET, sock.SocketOption.SO_REUSEADDR, 1)
ttl = s.getsockopt(sock.IPPROTO_IP, sock.IP_TTL)
```

Supported levels:

- `SOL_SOCKET` — generic socket-level options (`SO_REUSEADDR`,
  `SO_BROADCAST`, `SO_SNDBUF`, `SO_RCVBUF`, `SO_RCVTIMEO`,
  `SO_SNDTIMEO`).
- `IPPROTO_IP` — IPv4 options (`IP_TOS`, `IP_TTL`).
- `IPPROTO_IPV6` — IPv6 options (`IPV6_UNICAST_HOPS`,
  `IPV6_TCLASS`).
- `IPPROTO_TCP` — TCP options (`TCP_NODELAY`, `TCP_KEEPIDLE`,
  `TCP_KEEPINTVL`, `TCP_KEEPCNT`, `TCP_CONGESTION`,
  `TCP_FASTOPEN`).

## DNS

`pytcp.socket.getaddrinfo` and friends are re-exported from
CPython's stdlib. PyTCP does not implement a DNS resolver
of its own — applications use the host OS resolver to turn
hostnames into IPs, then feed numeric IPs into PyTCP's
`bind()` / `connect()` / `sendto()`.

## Examples in the repo

- `examples_legacy/stack.py` — TCP and UDP service registration.
- `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__*.py`
  — end-to-end TCP session scenarios.
- `packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py` — UDP socket
  consumer (DHCP DISCOVER / OFFER / REQUEST / ACK).

## Deferred / out of scope

The full Linux-parity audit is at
`docs/refactor/socket_linux_parity_audit.md` — 26
identified gaps with Phase-1 priorities. Notable absent
features:

- `socketpair`, `socket.dup`, `socket.fromfd`.
- `SOCK_SEQPACKET` (SCTP-style).
- Unix-domain sockets (out of scope; not a TCP/IP-stack
  concern).
- `MSG_*` flags on `send`/`recv` (`MSG_DONTWAIT`,
  `MSG_OOB`, `MSG_PEEK`, etc.).
- `recvmsg` / `sendmsg` ancillary data (control messages,
  `IP_PKTINFO`).
- `IP_RECVERR` / `IPV6_RECVERR` — Linux extension for
  receiving ICMP errors at the socket layer.
- `SO_BINDTODEVICE` — per-socket interface binding (needs
  the multi-interface Link API extension first).

## Plan / history

- Refactor plan: `docs/refactor/socket_linux_parity_audit.md`.
- Memory reference: `reference_socket_parity_audit.md`.
- Cross-API: depends on the **Sysctl registry** for some
  TCP-level option defaults (`TCP_KEEPIDLE` etc.).
