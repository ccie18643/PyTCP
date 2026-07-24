# RFC 6890 — Special-Purpose IP Address Registries

| Field       | Value                                                |
|-------------|------------------------------------------------------|
| RFC number  | 6890                                                 |
| Title       | Special-Purpose IP Address Registries                |
| Category    | Best Current Practice (BCP 153)                      |
| Date        | April 2013                                           |
| Obsoletes   | RFC 4773, RFC 5156, RFC 5735, RFC 5736               |
| Source text | [`rfc6890.txt`](rfc6890.txt)                         |

This document records the PyTCP codebase's adherence to RFC 6890
for the IPv4 portion of the registry. RFC 6890 consolidates the
IPv4 and IPv6 special-purpose registries and lists each
reserved block with attributes (Source/Destination valid,
Forwardable, Globally Reachable, Reserved-by-Protocol). PyTCP
implements per-class predicates on `Ip4Address` for the most
load-bearing classifications (loopback, link-local, private,
multicast, reserved, limited broadcast). Block-by-block audit
below.

The audit was performed by reading the RFC text fresh and
inspecting `packages/net_addr/net_addr/ip4_address.py` directly. Non-normative
content (§1 Introduction, §2.1 / §2.2 procedural metadata, §3
Security boilerplate, §4 Acknowledgements, §5 References) is
omitted.

---

## Top-line adherence

PyTCP **meets** the host-stack-relevant classifications: every
RFC 6890 IPv4 special-purpose block that has security or
behavioural significance for a host is recognised by an
`Ip4Address` predicate, and the parser's source-sanity rules
reject the most dangerous classes. Blocks that are only
operationally interesting (Documentation, Benchmark, etc.) are
not specially classified — they are treated as ordinary
globally-routable addresses, which is the conservative default
for a host.

| RFC 6890 block         | Predicate                                  | Status |
|------------------------|--------------------------------------------|--------|
| 0.0.0.0/8              | `is_invalid` + 0.0.0.0 → `is_unspecified` | met    |
| 10.0.0.0/8             | `is_private`                               | met    |
| 100.64.0.0/10 (CGN)    | no predicate (treated as global)           | partial |
| 127.0.0.0/8            | `is_loopback`                              | met    |
| 169.254.0.0/16         | `is_link_local`                            | met    |
| 172.16.0.0/12          | `is_private`                               | met    |
| 192.0.0.0/24 (IETF)    | no predicate (treated as global)           | partial |
| 192.0.0.0/29 (DS-Lite) | no predicate                               | partial |
| 192.0.2.0/24 (TEST-NET-1)        | no predicate                     | partial (documentation; rarely seen) |
| 192.88.99.0/24 (6to4 relay anycast)  | no predicate                 | n/a (6to4 deprecated by RFC 7526) |
| 192.168.0.0/16         | `is_private`                               | met    |
| 198.18.0.0/15 (Benchmark)        | no predicate                     | partial |
| 198.51.100.0/24 (TEST-NET-2)     | no predicate                     | partial |
| 203.0.113.0/24 (TEST-NET-3)      | no predicate                     | partial |
| 240.0.0.0/4 (Reserved)           | `is_reserved`                    | met    |
| 255.255.255.255/32 (Limited Broadcast) | `is_limited_broadcast`     | met    |
| 224.0.0.0/4 (Multicast, RFC 1112) | `is_multicast`                  | met    |

---

## §2.2.2 IPv4 Special-Purpose Address Registry Entries

### 0.0.0.0/8 — "This host on this network" + invalid

> "[0.0.0.0/8] Source: True. Destination: False. Forwardable:
> False. Globally Reachable: False."

**Adherence:** met. `Ip4Address.is_unspecified` is the
zero-address case (the address is 0.0.0.0 by construction
when no argument is supplied to the constructor — see
`packages/net_addr/net_addr/ip4_address.py:_address = 0` branch). The
non-zero 0.0.0.0/8 range is classified via
`Ip4Address.is_invalid` (`packages/net_addr/net_addr/ip4_address.py:244-251`):

```python
return (
    self._address & 0xFF_00_00_00 == 0x00_00_00_00
) and self._address != 0x00_00_00_00  # 0.0.0.1 - 0.255.255.255
```

The combined classification (`is_unspecified | is_invalid`)
covers the full RFC 6890 entry. RFC 1122 §3.2.1.3 allows
0.0.0.0 as source during host initialisation (DHCPv4
DISCOVER carrying src=0.0.0.0); PyTCP exempts this case in the
TX path
(`packet_handler__ip4__tx.py:432-443`).

### 127.0.0.0/8 — Loopback

> "[127.0.0.0/8] Source: False. Destination: False.
> Forwardable: False. Globally Reachable: False."

**Adherence:** met. `Ip4Address.is_loopback` recognises 127/8.
The RX sanity check at `ip4__parser.py:187-191` rejects
loopback sources via a dedicated `is_loopback` branch (skipped
when the RX consumer marked the packet `from_loopback`, so an
internally looped datagram legitimately carrying a loopback
source is not rejected).

### 169.254.0.0/16 — Link-Local

> "[169.254.0.0/16] Source: True. Destination: True.
> Forwardable: False. Globally Reachable: False."

**Adherence:** met. `Ip4Address.is_link_local` recognises
169.254/16. See RFC 3927 audit for the full link-local
behaviour.

### 224.0.0.0/4 — Multicast

> "[224.0.0.0/4] Source: False. Destination: True.
> Forwardable: True. Globally Reachable: True. Reserved-by-
> Protocol: False."

**Adherence:** met. `Ip4Address.is_multicast` recognises
224/4. The RX sanity check rejects multicast sources
(`ip4__parser.py:196-200`).

### 240.0.0.0/4 — Reserved for Future Use

> "[240.0.0.0/4 (excluding 255.255.255.255/32)] Source: False.
> Destination: False. Forwardable: False. Globally Reachable:
> False."

**Adherence:** met. `Ip4Address.is_reserved` recognises
240.0.0.0 - 255.255.255.254 (`packages/net_addr/net_addr/ip4_address.py:226-233`).
The RX sanity check rejects reserved sources
(`ip4__parser.py:205-209`).

### 255.255.255.255/32 — Limited Broadcast

> "[255.255.255.255/32] Source: False. Destination: True.
> Forwardable: False. Globally Reachable: False."

**Adherence:** met. `Ip4Address.is_limited_broadcast`
recognises this address; the RX path admits it on dst and
rejects on src (see RFC 919 audit).

### 10.0.0.0/8 + 172.16.0.0/12 + 192.168.0.0/16 — Private

**Adherence:** met. See RFC 1918 audit
(`docs/rfc/ip4/rfc1918__private_addresses/adherence.md`).

### 100.64.0.0/10 — Shared Address Space (CGN)

> "Source: True. Destination: True. Forwardable: True.
> Globally Reachable: False. Reserved-by-Protocol: False."

**Adherence:** **partial — no dedicated predicate.** PyTCP
classifies 100.64.0.0/10 as a globally reachable address.
This means a host stack will not refuse to accept or send
to this range, which is operationally correct for CGN
deployments (CGN is invisible to the host CPE). The
"Globally Reachable: False" attribute matters for
forwarders, which is Phase 2.

### 192.0.2.0/24 (TEST-NET-1), 198.51.100.0/24 (TEST-NET-2), 203.0.113.0/24 (TEST-NET-3)

> "Documentation. Source: False. Destination: False.
> Forwardable: False. Globally Reachable: False."

**Adherence:** **partial — no predicate.** These ranges are
treated as ordinary global addresses. A documentation block
appearing on the wire is unusual but PyTCP would accept it
and try to deliver. RFC 5737 (the originator of these blocks)
permits hosts to be liberal on receive — the strict "Source:
False / Destination: False" is intended for routers /
firewalls (Phase 2). When PyTCP gains a firewall plane these
predicates become candidates for explicit classification.

### 198.18.0.0/15 — Benchmark

> "[198.18.0.0/15] Source: True. Destination: True.
> Forwardable: True. Globally Reachable: False. Reserved-by-
> Protocol: True."

**Adherence:** **partial — no predicate.** Same treatment as
the documentation blocks above; PyTCP treats it as global.

### 192.0.0.0/24, 192.0.0.0/29, 192.88.99.0/24

**Adherence:** **partial — no predicate.** IETF protocol
assignment block, DS-Lite, and 6to4 relay anycast
respectively. None has consumer-significant host-side
behaviour; 192.88.99.0/24 is deprecated by RFC 7526.

---

## Test coverage audit

### Per-block predicate correctness

- **Unit:**
  `packages/net_addr/net_addr/tests/unit/test__ip4_address.py`
  Parametric matrix covering each predicate
  (`is_loopback`, `is_link_local`, `is_multicast`,
  `is_private`, `is_reserved`, `is_limited_broadcast`,
  `is_invalid`, `is_unspecified`) at multiple sample
  addresses inside and outside each block.

**Status:** locked in.

### Source-sanity rules at parser level

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/ip4/test__ip4__parser__sanity_checks.py`
  Per-branch rejection for multicast / reserved / limited-
  broadcast sources.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__rx.py`
  ICMP Parameter Problem emission verification.

**Status:** locked in.

### Phase-2 / partial blocks (documentation, benchmark, CGN, IETF)

**No test surface — partial.** When PyTCP gains a firewall /
classification plane the natural pattern is one predicate per
block (e.g. `is_documentation`, `is_benchmark`, `is_cgn`)
plus a sysctl `ip4.special_purpose_filter` that the operator
can flip on.

### Test coverage summary

| Aspect                                              | Coverage |
|-----------------------------------------------------|----------|
| Loopback / link-local / multicast / private / reserved / limited-broadcast | locked in |
| Unspecified / invalid (0.0.0.0/8 split)              | locked in |
| Documentation / Benchmark / CGN / IETF blocks       | n/a (partial; no Phase-1 consumer) |

---

## Overall assessment

| Aspect                                              | Status |
|-----------------------------------------------------|--------|
| §2.2.2 Loopback (127/8)                             | met    |
| §2.2.2 Link-Local (169.254/16)                      | met    |
| §2.2.2 Multicast (224/4)                            | met    |
| §2.2.2 Private (RFC 1918 blocks)                    | met    |
| §2.2.2 Reserved (240/4 except 255.255.255.255)      | met    |
| §2.2.2 Limited Broadcast (255.255.255.255)          | met    |
| §2.2.2 Unspecified + 0/8 invalid                    | met    |
| §2.2.2 CGN / Documentation / Benchmark / IETF       | partial (no predicate; treated as global) |
| §2.2.2 6to4 relay anycast (192.88.99.0/24)          | n/a (deprecated by RFC 7526) |

The high-value classifications are met. The remaining partial
classifications are operationally low-impact for a host stack
(a Documentation or Benchmark address rarely appears on the
wire in real deployments) and become relevant when PyTCP
grows a firewall / packet-filter plane.
