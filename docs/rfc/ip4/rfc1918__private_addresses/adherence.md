# RFC 1918 — Address Allocation for Private Internets

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 1918                                           |
| Title       | Address Allocation for Private Internets       |
| Category    | Best Current Practice (BCP 5)                  |
| Date        | February 1996                                  |
| Updated by  | RFC 6761                                       |
| Source text | [`rfc1918.txt`](rfc1918.txt)                   |

This document records the PyTCP codebase's adherence to RFC 1918
clause by clause. RFC 1918 is **a definitional / operational BCP**
— it reserves three IPv4 address blocks for private use and
provides operator guidance for handling those blocks. There is
no host-stack wire-format normative content. PyTCP's only
RFC 1918 surface is the `Ip4Address.is_private` predicate.

The audit was performed by reading the RFC text fresh and
inspecting `packages/net_addr/net_addr/ip4_address.py` directly. Non-normative
content (§1 Introduction, §2 Motivation, §4 Advantages, §5
Operational, §6/§7/§8/§9/§10) is omitted.

---

## Top-line adherence

PyTCP **meets** the RFC 1918 surface relevant to a host stack:
the three reserved blocks (10/8, 172.16/12, 192.168/16) are
recognised by `Ip4Address.is_private`. The non-propagation /
non-leakage operational requirements are router-side; PyTCP
does not forward and so cannot leak. The DNS / RIR / NAT
guidance is out of scope for a stack-level audit.

| Section | Topic                                                | Status |
|---------|------------------------------------------------------|--------|
| §3      | Three reserved blocks (10/8, 172.16/12, 192.168/16)  | met (predicate exists) |
| §3      | Private addresses MUST NOT propagate inter-enterprise | n/a (no forwarding) |
| §3      | Packets with private src/dst MUST NOT be forwarded   | n/a (no forwarding) |
| §5      | ISP filtering / DNS leakage                          | n/a (operator) |

---

## §3 Private Address Space

> "The Internet Assigned Numbers Authority (IANA) has reserved
> the following three blocks of the IP address space for
> private internets:
> 10.0.0.0 - 10.255.255.255 (10/8 prefix)
> 172.16.0.0 - 172.31.255.255 (172.16/12 prefix)
> 192.168.0.0 - 192.168.255.255 (192.168/16 prefix)"

**Adherence:** met. `Ip4Address.is_private` predicate at
`packages/net_addr/net_addr/ip4_address.py:214-223`:

```python
@property
def is_private(self) -> bool:
    return (
        self._address & 0xFF_00_00_00 == 0x0A_00_00_00  # 10.0.0.0/8
        or self._address & 0xFF_F0_00_00 == 0xAC_10_00_00  # 172.16.0.0/12
        or self._address & 0xFF_FF_00_00 == 0xC0_A8_00_00  # 192.168.0.0/16
    )
```

All three RFC 1918 blocks are recognised. The predicate is
exposed on every `Ip4Address` instance and is consumed by the
`is_global` classifier (`ip4_address.py:180` — an address is
global only if it is not private/loopback/link-local/etc.) and
by the shared `IpAddress.is_unicast` classifier
(`ip_address.py:80`).

> "Routing information about private networks shall not be
> propagated on inter-enterprise links, and packets with
> private source or destination addresses should not be
> forwarded across such links."

**Adherence:** n/a (PyTCP does not forward). When PyTCP gains
a router plane, the natural gating point is the FIB lookup —
the `Ip4Address.is_private` predicate is already in place for
the policy check.

## §5 Operational Considerations

> "Internet service providers should take measures to prevent
> such leakage."
> "An enterprise should also filter any private network
> routing information."

**Adherence:** n/a (operator / ISP scope). Not a host-stack
concern.

---

## Test coverage audit

### Ip4Address.is_private predicate

- **Unit:**
  `packages/net_addr/net_addr/tests/unit/test__ip4_address.py`
  Parametric matrix covering at least one address inside each
  of the three blocks plus boundary addresses just outside
  each (e.g., 11.0.0.0, 172.32.0.0, 192.169.0.0) to verify
  the mask-and-compare correctness.

**Status:** locked in.

### Test coverage summary

| Aspect                                              | Coverage |
|-----------------------------------------------------|----------|
| 10/8 block recognised as private                    | locked in |
| 172.16/12 block recognised as private               | locked in |
| 192.168/16 block recognised as private              | locked in |
| Boundary addresses outside each block               | locked in |
| Forwarding policy on private src/dst                | n/a (no forwarding) |

---

## Overall assessment

| Aspect                                              | Status |
|-----------------------------------------------------|--------|
| §3 Three RFC 1918 blocks recognised by predicate    | met    |
| §3 Non-propagation / non-forwarding requirements    | n/a (Phase 2 router) |
| §5 Operator-side filtering guidance                 | n/a    |

RFC 1918 is fully covered for what is in scope at the host-
stack level. The Phase-2 router plane will need to consume
`is_private` for routing-table install / filter / NAT
classification; the predicate is ready when the consumer
materialises.
