# RFC 922 — Broadcasting Internet Datagrams in the Presence of Subnets

| Field       | Value                                                |
|-------------|------------------------------------------------------|
| RFC number  | 922                                                  |
| Title       | Broadcasting Internet Datagrams in the Presence of Subnets |
| Category    | Internet Standard (STD 5)                            |
| Date        | October 1984                                         |
| Source text | [`rfc922.txt`](rfc922.txt)                           |

This document records the PyTCP codebase's adherence to RFC 922
clause by clause. RFC 922 extends RFC 919 to subnetted networks
— it defines the {net, subnet, -1} subnet-directed broadcast
and the {net, -1, -1} all-subnets broadcast forms. PyTCP
implements the subnet-directed form via the per-`Ip4IfAddr`
network-broadcast machinery; the all-subnets form is
operationally deprecated and not implemented.

The audit was performed by reading the RFC text fresh and
inspecting `packages/net_addr/net_addr/ip4_network.py`,
`packages/net_addr/net_addr/ip4_ifaddr.py`, and the IPv4 packet handlers directly;
no prior memory or rule-file content was reused. Non-normative
content (§1 Introduction, §2 Why Subnets, §3 Architecture, §8
Acknowledgments) is omitted.

---

## Top-line adherence

PyTCP **meets** the subnet-directed broadcast form. The
all-subnets broadcast form (`{net, -1, -1}`) is **not
implemented** — operationally deprecated since RFC 922 itself
(§7 IMPLEMENTATION notes the form's awkwardness), with most
modern stacks gating it off by default (Linux:
`net.ipv4.conf.*.bc_forwarding=0`). PyTCP follows the
modern posture (no all-subnets handling).

| Section | Topic                                                 | Status |
|---------|-------------------------------------------------------|--------|
| §6      | Subnet-directed broadcast `{net, subnet, -1}` recognition | met (via Ip4Network.broadcast) |
| §6      | All-subnets broadcast `{net, -1, -1}` recognition     | not implemented (operationally deprecated) |
| §6      | Subnet broadcasts MUST be received                    | met for `{net, subnet, -1}` |
| §7      | Gateway forwarding of subnet-directed broadcasts      | met by refusal — forward path drops directed-broadcast destinations (RFC 2644 default-off) |

---

## §6 Broadcast Addressing in Subnetted Networks

> "A datagram destined for {<Network-number>, <Subnet-number>,
> -1} ... is a subnet-directed broadcast."

**Adherence:** met. `Ip4Network.broadcast` computes the
broadcast address for a given network using "network | ~mask"
which yields exactly `{net, subnet, -1}` for any subnet mask.
At boot, the stack populates `_ip4_broadcast` with the
`network.broadcast` for every owned `Ip4IfAddr`
(`packages/pytcp/pytcp/runtime/packet_handler/__init__.py:194+`). The RX
handler admits frames with destination matching any entry in
`_ip4_broadcast`.

> "A datagram destined for {<Network-number>, -1, -1} ... is
> an all-subnets broadcast."

**Adherence:** not implemented. The all-subnets broadcast
requires a router (or host) to enumerate every known subnet
of the destination network and emit a copy to each — that's
forwarding plane work. As a host stack PyTCP would only
receive an all-subnets broadcast if a router explicitly
forwarded one to its own subnet, in which case it would look
identical to a subnet-directed broadcast at PyTCP's interface
and be received normally. The "all-subnets" semantics is lost
above the IP layer.

> "An incoming broadcast datagram is destined for the host if
> the datagram's destination address field is ... an IP
> broadcast address valid for the connected network."
> (RFC 1122 §3.2.1.3 derivative)

**Adherence:** met. See RFC 919 audit §5 entry — the
`_ip4_broadcast` set comparison admits subnet-directed
broadcasts the host owns.

## §7 Gateway forwarding of subnet broadcasts

> "Gateways must therefore consider all-subnets broadcasts to
> be a request to be forwarded ... [with appropriate loop
> protection]."

**Adherence:** met by refusal for the subnet-directed form. PyTCP
forwards unicast as of 3.0.9, and its forward path drops any datagram
whose destination is a directly-connected subnet's directed broadcast
(`stack.is_ip4_broadcast`), the RFC 2644 smurf-prevention default.
All-subnets enumeration / replication remains unimplemented
(deprecated).

---

## Test coverage audit

### §6 Subnet-directed broadcast recognition

- **Unit:**
  `packages/net_addr/net_addr/tests/unit/test__ip4_network.py`
  `Ip4Network.broadcast` property test (e.g.
  `Ip4Network("10.0.0.0/24").broadcast == Ip4Address("10.0.0.255")`).
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__rx.py`
  Broadcast destination matrix exercises subnet-directed
  broadcast admission.

**Status:** locked in.

### TX-side subnet broadcast source replacement

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__tx.py`
  Verifies `_ip4_src in _ip4_broadcast` → replaced with the
  matching host's primary address per the `network.broadcast`
  lookup (`packet_handler__ip4__tx.py:411-425`).

**Status:** locked in.

### TX-side subnet broadcast destination gate (`ip4.allow_broadcast`)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__tx.py::TestIp4TxRfc919AllowBroadcast::test__ip4__tx__network_broadcast_dst_default_deny__dropped`
  Drives an outbound datagram to the subnet-directed
  broadcast `10.0.1.255` and verifies the gate drops with
  `DROPPED__IP4__DST_BROADCAST_DISALLOWED`. The companion
  unit tests in `TestIp4AllowBroadcastSysctl` lock the
  validator's {0, 1} acceptance.

**Status:** locked in.

### All-subnets broadcast (not implemented)

**No test surface — not implemented.** Phase-2 router work.

### Test coverage summary

| Aspect                                              | Coverage |
|-----------------------------------------------------|----------|
| §6 Subnet-directed broadcast recognition (RX)       | locked in |
| §6 Subnet broadcast source replacement (TX)         | locked in |
| §6 Subnet broadcast destination gate (TX)           | locked in (sysctl `ip4.allow_broadcast`) |
| §6 All-subnets broadcast                            | n/a (not implemented) |
| §7 Gateway forwarding                               | met by refusal (directed broadcasts not forwarded; RFC 2644) |

---

## Overall assessment

| Aspect                                              | Status |
|-----------------------------------------------------|--------|
| §6 Subnet-directed broadcast {net, subnet, -1}      | met    |
| §6 All-subnets broadcast {net, -1, -1}              | not implemented (operationally deprecated; Phase 2 if needed) |
| §7 Gateway forwarding of broadcasts                 | met by refusal (directed broadcasts not forwarded; RFC 2644) |

RFC 922 is fully covered for the subnet-directed form. The
all-subnets broadcast is operationally deprecated and not on
the PyTCP roadmap; the Phase-2 router plane may revisit if a
specific consumer surfaces.
