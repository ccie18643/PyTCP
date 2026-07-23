# RFC 2711 — IPv6 Router Alert Option — adherence

RFC 2711 defines the IPv6 Router Alert option — a Hop-by-Hop option
that tells transit routers "this packet carries information of
interest to you; examine it more closely" without paying the
per-packet fast-path cost on packets that don't. Its primary host-side
consumer is MLD (RFC 2710 / RFC 3810), which RFC 3810 §5.2.14 requires
to carry the Router Alert option, and RSVP.

This is the IPv6 counterpart to the IPv4 Router Alert record at
`docs/rfc/ip4/rfc6398__router_alert/adherence.md`; it is split out for
IPv6 audit-set parity (item F). RFC 2711 was previously covered only
by reference inside the RFC 3810 (MLD) and RFC 8200 records.

## Top-line adherence

PyTCP **meets** the host-side Router Alert requirements: the option is
a full typed codec (not an opaque blob), integrity-gated on the wire,
emitted on outbound MLD reports, and parsed on inbound. A host neither
intercepts nor acts on the Router Alert value (that is a router fast-
path function) — it carries the option on the messages that require it
and parses it faithfully on receipt, which is the complete host
obligation.

| Section | Topic | Status |
|---------|-------|--------|
| §2 | Router Alert option format (Type 5, Opt Data Len 2, 16-bit Value) | met (typed codec) |
| §2.1 | Opt Data Len MUST be 2 | met (integrity-gated) |
| §2 | Well-known values (0=MLD, 1=RSVP, 2=Active Networks) | met (named; full set is IANA) |
| §2 | Action-on-unrecognized = skip (Type high 2 bits = 00) | met (RFC 8200 §4.2 skip) |
| §3 | Router examines packets carrying the option | n/a (host, not a router — Phase 2) |
| RFC 3810 §5.2.14 | MLD messages carry the Router Alert option | met (TX emits it on MLDv2 reports) |

---

## §2 Router Alert option format

> "The Router Alert option ... Option Type: 5 ... Length: 2 ... Value:
> A 2-octet code ... 0 = Datagram contains a Multicast Listener
> Discovery message [...] 1 = RSVP message [...] 2 = Active Networks
> message."

**Adherence:** met. `Ip6HbhOptionRouterAlert`
(`packages/net_proto/net_proto/protocols/ip6_hbh/options/ip6_hbh__option__router_alert.py`)
is a full typed Hop-by-Hop option:

- Option Type `0x05` (`Ip6HbhOptionType.ROUTER_ALERT`, the `:75`
  field default), whose high 2 bits are `00` → "skip if unrecognized"
  per RFC 8200 §4.2 (`:52` comment).
- `Opt Data Len = 2` (`IP6_HBH__OPTION__ROUTER_ALERT__OPT_DATA_LEN`,
  `:58`); the option is a fixed 4 octets total (Type + Len + 2-byte
  Value), `IP6_HBH__OPTION__ROUTER_ALERT__LEN = 4` (`:57`).
- A 16-bit `value` field (`:83`, asserted `is_uint16` at `:91`),
  packed `! BBH` at `:118`.
- Well-known values named: `…VALUE__MLD = 0`, `…VALUE__RSVP = 1`,
  `…VALUE__ACTIVE_NETWORKS = 2` (`:61-63`); `__str__` renders MLD /
  RSVP by name and any other value numerically (`:99-107`). The full
  value space is the IANA registry; PyTCP names the host-relevant
  subset and carries any 16-bit value faithfully.

## §2.1 Opt Data Len MUST be 2

**Adherence:** met (integrity-gated). The option's `_validate_integrity`
enforces `Opt Data Len == 2` and rejects any other length as a wire
violation (hostile-wire defense, runs unconditionally), per the
net_proto §9.2 integrity-vs-sanity discipline.

## §2 action-on-unrecognized = skip

**Adherence:** met. The Type byte's high 2 bits are `00`, so a node
that does not recognize the Router Alert option skips it and continues
processing the packet (RFC 8200 §4.2 action 00) — audited under
`docs/rfc/ip6/rfc8200__ipv6/adherence.md` §4.2. PyTCP *does* recognize
it (typed codec), so it parses rather than skips.

## §3 router processing

**Adherence:** n/a (host). RFC 2711 §3's "routers examine packets
carrying the Router Alert option" is a router fast-path obligation.
PyTCP is a Phase-1 host: it does not forward, so it never intercepts
transit packets on the basis of the option. A host's complete
obligation is to (a) emit the option on the messages that require it
(MLD, below) and (b) parse it on receipt without malfunction — both
met. Router-side interception is Phase-2 (forwarding plane).

## RFC 3810 §5.2.14 — MLD carries the Router Alert option

**Adherence:** met. PyTCP's MLDv2 Report TX path wraps the report in an
`Ip6HbhAssembler` carrying `Ip6HbhOptionRouterAlert(value=…MLD)` plus a
`PadN(0)` for 8-octet alignment
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__icmp6__tx.py`,
`_send_icmp6_multicast_listener_report`, ~`:606-614`). The report is
sent with Hop Limit 1 (RFC 3810 §5.2.13) to `ff02::16`, with the
ICMPv6 pseudo-header checksum pre-computed because the immediate IPv6
payload is the HBH header rather than the ICMPv6 message. MLD Query
generation (querier role) is a router/Phase-2 function and is out of
host scope.

---

## Test coverage audit

### §2 / §2.1 Router Alert wire codec + integrity
- **Unit:** the `Ip6HbhOptionRouterAlert` asserts / assembler /
  parser matrices under
  `packages/net_proto/net_proto/tests/unit/protocols/ip6_hbh/` pin the
  Type / Opt-Data-Len / Value wire format and the `Opt Data Len == 2`
  integrity rejection.

**Status:** locked in.

### §2 RX parse into the typed option
- **Integration:** the IPv6 RX chain-walker / HBH-options parse path
  (`packages/pytcp/pytcp/tests/integration/protocols/ip6/test__ip6__rx__chain_walker.py`
  and the HBH options unit tests) dispatch a Router Alert option to
  the typed `Ip6HbhOptionRouterAlert` rather than the opaque
  `Unknown` fallback.

**Status:** locked in.

### RFC 3810 §5.2.14 MLD carries the option
- **Integration:** the MLDv2 report TX coverage under the RFC 3810
  record (`docs/rfc/icmp6/rfc3810__mld2/adherence.md` §5.2.14) drives
  report emission and asserts the Router Alert HBH option is present.

**Status:** locked in (via the RFC 3810 record's test surface).

### Test coverage summary

| Aspect | Coverage |
|--------|----------|
| §2 Router Alert wire codec (Type 5 / Len 2 / 16-bit Value) | locked in |
| §2.1 Opt Data Len == 2 integrity | locked in |
| §2 RX parse into typed option | locked in |
| §2 action-on-unrecognized skip (00) | locked in (RFC 8200 §4.2 audit) |
| RFC 3810 §5.2.14 MLD carries the option | locked in (RFC 3810 record) |
| §3 router interception | n/a (host; Phase 2) |

---

## Overall assessment

The IPv6 Router Alert option is a complete typed codec, integrity-
gated, emitted on the MLD messages RFC 3810 requires, and parsed on
receipt — the full host obligation. The only out-of-scope item is
router-side interception (RFC 2711 §3), which belongs to the Phase-2
forwarding plane. This record exists for IPv4↔IPv6 audit-set parity
with `docs/rfc/ip4/rfc6398__router_alert/adherence.md`.
