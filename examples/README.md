# PyTCP Examples — daemon-backed applications

Real, off-the-shelf-shaped programs that run **against a running PyTCP
daemon** through the 1:1 stdlib-`socket` drop-in introduced in 3.0.8. Each
one changes nothing about how ordinary Python network code is written — it
imports `pytcp.socket` in place of the standard library's `socket`, and the
factory opens the socket on the daemon over its AF_UNIX control boundary,
handing back a real, `selectors`-pollable descriptor:

```python
from pytcp import socket          # the daemon-backed stdlib-socket drop-in
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("10.0.1.1", 7))     # a real, selectable fd backs this socket
```

Every program here takes its socket from an injectable `make_socket`
factory, so the same application logic is exercised over real loopback
sockets in the project's test suite and wired to daemon sockets by its
`main` entry point. They double as the proof points that off-the-shelf
protocol code — including **blocking** stdlib programs and **`asyncio`**
servers and clients — runs unmodified over PyTCP.

> These examples are for **writing applications** against a running stack.
> For how to **boot and run the stack itself** — opening the TAP/TUN
> interface, `stack.init(...)`, the in-process lifecycle, the raw
> `pytcp.client` control API, and the daemon launcher — see
> [`examples_legacy/`](../examples_legacy/) (still current, not deprecated).

## Prerequisites

All of these need a **running daemon** that owns the TAP interface. The
first-class launcher ships in the package; `pytcp stack start`
autoconfigures via DHCPv4, so either run a DHCP server on the link or boot
with a static address:

```bash
sudo make bridge && sudo make tap7 && make venv
pytcp stack start -i tap7 --ip4-host 192.168.1.77/24     # or: python -m pytcp.daemon
```

The client programs find the daemon through `$PYTCP_DAEMON_SOCKET` (the
same default the daemon uses):

```bash
export PYTCP_DAEMON_SOCKET=/tmp/pytcp.sock
```

## The examples

| Program | What it shows | Consumption path |
|---|---|---|
| [`ping.py`](ping.py) | ICMP Echo (v4/v6) with hostname resolution through the daemon's DNS resolver; unprivileged ICMP datagram socket with raw-socket fallback, mirroring Linux `ping` | drop-in + `pytcp.cli.cli__ping` engine |
| [`tcp_echo_server__async.py`](tcp_echo_server__async.py) / [`tcp_echo_client.py`](tcp_echo_client.py) | RFC 862 TCP Echo — an `asyncio` server (`start_server(sock=...)`) and a blocking client, over the daemon's stream sockets | drop-in (asyncio + blocking) |
| [`udp_echo_server__async.py`](udp_echo_server__async.py) / [`udp_echo_client.py`](udp_echo_client.py) | RFC 862 UDP Echo — an `asyncio` datagram server and a blocking client | drop-in (asyncio + blocking) |
| [`ftp_server__async.py`](ftp_server__async.py) / [`ftp_client__async.py`](ftp_client__async.py) | A read-only anonymous FTP server + client (RFC 959): control + PASV data connections, byte-exact binary transfer — a full real-world `asyncio` program over the daemon | drop-in (asyncio) |
| [`mcast_announce.py`](mcast_announce.py) / [`mcast_discover.py`](mcast_discover.py) | Multicast service discovery — the shape SSDP / mDNS / cluster beacons use — exercising the IGMP group-membership API (`IP_ADD_MEMBERSHIP` / `IP_DROP_MEMBERSHIP`) end to end | drop-in (UDP multicast) |
| [`lib/malpi.py`](lib/malpi.py) / [`mcast_proto.py`](mcast_proto.py) | Shared helpers — the ASCII-art "monkey" easter-egg payloads and echo reply selector, and the tiny text discovery wire format | (library, not run directly) |

## Running them

With the daemon up and `$PYTCP_DAEMON_SOCKET` exported:

```bash
# ICMP Echo to an address or a hostname (resolved through the daemon)
./examples/ping.py 192.168.1.1
./examples/ping.py example.com -c 3

# TCP Echo — start the async server on the stack, echo from the client
./examples/tcp_echo_server__async.py --host 192.168.1.77 &
python -m examples.tcp_echo_client 192.168.1.77 --message malpi

# UDP Echo
./examples/udp_echo_server__async.py --host 192.168.1.77 &
python -m examples.udp_echo_client 192.168.1.77 --message malpi

# Async FTP — serve a directory, then LIST / RETR from the client
./examples/ftp_server__async.py --host 192.168.1.77 --root /srv/ftp &
./examples/ftp_client__async.py --host 192.168.1.77 --get blob.bin > got.bin

# Multicast service discovery — announce on one stack, discover on another
python -m examples.mcast_announce --service echo --host 192.168.1.77 --service-port 7 &
python -m examples.mcast_discover
```

The FTP pair is verified live end to end against a real `ftplib` client and
byte-exact against a control transfer; with the loopback interface (3.0.8)
the server and client can even share a single daemon, traffic looping
inside the stack over `lo`. The full reproducible recipe is in
[`docs/refactor/daemon_socket_library_and_cli.md`](../docs/refactor/daemon_socket_library_and_cli.md)
(§9).

## See also

- **[`examples_legacy/`](../examples_legacy/)** — the in-process
  bootstrap reference (`stack.py`), the raw `pytcp.client` out-of-process
  control API demo (`client__tcp_echo_ipc.py`), and the in-process service
  programs the `tools/capture` live-demo harness drives.
- **The `pytcp` CLI** — `pytcp ping / host / nc / traceroute` are
  batteries-included tools over the same daemon; `pytcp ss / link / addr /
  route / neigh / sysctl` introspect and drive the control plane.
- The main [`README.md`](../README.md) — live wire captures of the stack in
  action (SLAAC + DAD, ARP ACD, TCP under packet loss, IP fragmentation).
