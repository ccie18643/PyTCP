# RFC 8201 — Path MTU Discovery for IP version 6

| Field       | Value                                              |
|-------------|----------------------------------------------------|
| RFC number  | 8201                                               |
| Title       | Path MTU Discovery for IP version 6                |
| Category    | Internet Standard (STD 87)                         |
| Date        | July 2017                                          |
| Source text | [`rfc8201.txt`](rfc8201.txt)                       |

---

## Top-line adherence

After Phases 4 + 6 of the ICMP demux + PMTUD refactor,
PyTCP **partially implements** RFC 8201:

- Inbound ICMPv6 Type 2 (Packet Too Big) is parsed,
  demuxed to the matching TCP/UDP socket, and lands
  in the per-destination `stack.pmtu_cache`.
- TCP recomputes `snd_mss` from the new path MTU
  (1280 minimum floor enforced).
- UDP records the new MTU on the socket via
  `notify_pmtu`.
- The 1280-byte IPv6 minimum MTU floor is enforced
  in `TcpSession._apply_pmtu_update`.
- TCP performs the RFC 1191 §6.5 retransmit walkback
  on an MSS shrink: when an in-flight segment exceeds
  the new MSS, all in-flight segments are marked lost
  and `snd_nxt` is rewound to `snd_una` so the next
  timer tick re-emits from `snd_una` at the smaller
  MSS (without halving cwnd / ssthresh — the path
  narrowed but did not congest).

What still **does not happen**:

- Per-destination MTU aging — classical
  `stack.pmtu_cache` entries never expire. Active
  re-probing to *raise* the PMTU is available through
  the shipped RFC 8899 DPLPMTUD engine (opt-in via
  `tcp.mtu_probing`), but the classical cache itself
  has no timer-driven expiry.

---

## §4 Mechanisms

### §4 ICMPv6 Packet Too Big reception with MTU field

> "Upon receiving a Packet Too Big message, the
> source node reduces the path MTU value for the
> destination if the message's MTU field value is
> less than the current cached PMTU."

**Adherence:** **shipped** (Phases 4 + 6). The
ICMPv6 RX handler at
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__icmp6__rx.py`
includes `__phrx_icmp6__packet_too_big` which
parses the embedded IPv6+L4 4-tuple via the shared
`parse_embedded_l4` helper, demuxes to UDP via
`UdpSocket.notify_pmtu` or to TCP via
`TcpSession._apply_pmtu_update`. RFC 5927 §4 sequence-in-window
guard applies on the TCP path.

### §4 ICMPv6 Packet Too Big emission (transit forwarder)

> "A router that cannot forward a packet because it is larger
> than the outgoing link MTU MUST send an ICMPv6 Packet Too Big
> message with the MTU of that link (routers never fragment
> IPv6 — RFC 8200 §5)."

**Adherence:** **shipped (Phase-2 M2)** — the *emission* side, the
router counterpart of the reception clause above. When
forwarding is enabled and a transit datagram exceeds the egress
interface MTU, `Ip6ForwardHandler._emit_packet_too_big`
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip6__forward.py`)
discards it (routers never fragment IPv6) and emits ICMPv6 Packet
Too Big (Type 2) carrying the egress interface MTU, back to the
datagram's source; the ICMPv6 TX handler bumps
`icmp6__packet_too_big__send`. Audited alongside the IPv4
transit-PMTU counterpart under
[`../../ip4/rfc1812__router_requirements/adherence.md`](../../ip4/rfc1812__router_requirements/adherence.md)
and tested in
`packages/pytcp/pytcp/tests/integration/router/test__router__ip6__forwarding.py`.

### §4 Minimum MTU = 1280 bytes

> "An implementation MUST NOT reduce its estimate
> of the Path MTU below the IPv6 minimum link MTU
> [RFC 8200 §5]."

**Adherence:** **shipped**. `TcpSession._apply_pmtu_update`
applies the floor: `floor = 1280 - 40 - 20` for
IPv6, where 40 is the IPv6 header and 20 is the
TCP header. `snd_mss` never drops below the floor.

### §4 PMTU only shrinks on PTB; never grows

> "An implementation MUST NOT increase its
> estimate of the Path MTU in response to a
> Packet Too Big message."

**Adherence:** **shipped**. `TcpSession._apply_pmtu_update`
contains an explicit `if new_mss < self._win.snd_mss`
guard so MSS only shrinks on a Packet Too Big.

### §4 Path MTU Aging

> "Note that increasing the cached PMTU
> requires periodic probing — see RFC 8201 §4
> 'Aging the Path MTU'."

**Adherence:** not implemented. `stack.pmtu_cache`
is process-lifetime; classical entries do not expire.
The RFC 4821 / 8899 PLPMTUD engine that performs
active re-probing (including raising the PMTU) is now
shipped and operator-reachable via `tcp.mtu_probing`;
what remains absent is timer-driven expiry of the
classical `stack.pmtu_cache` entries themselves.

---

## Test coverage audit

| Aspect                                              | Coverage |
|-----------------------------------------------------|----------|
| §4 ICMPv6 Packet Too Big MTU update for UDP         | shipped — `packages/pytcp/pytcp/tests/integration/protocols/icmp6/test__icmp6__pmtud.py` |
| §4 ICMPv6 Packet Too Big MTU update for TCP         | shipped (substrate) — TCP path goes through the same `TcpSession._apply_pmtu_update` covered by `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__icmp__pmtu.py` (the v4 Frag-Needed test exercises the shared callback) |
| §4 1280-byte minimum MTU floor                      | shipped — `TcpSession._apply_pmtu_update` floor logic |
| §4 PMTU only shrinks                                | shipped — `test__tcp__session__icmp__pmtu.py::test__icmp4__frag_needed__never_grows_snd_mss` |
| RFC 1191 §6.5 retransmit walkback on MSS shrink     | shipped — `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__pmtu_walkback.py` |
| §4 Path MTU Aging                                   | n/a (gap) |

---

## Overall assessment

| Aspect                                       | Status          |
|----------------------------------------------|-----------------|
| §4 ICMPv6 PTB consumption                    | **shipped**     |
| §4 1280 minimum MTU floor                    | **shipped**     |
| §4 PMTU shrink-only semantics                | **shipped**     |
| §4 Path MTU Aging                            | not implemented |

The substrate (`stack.pmtu_cache`, embedded-header
demux, ICMPv6 PacketTooBig message class, TCP/UDP
_apply_pmtu_update callbacks, and the RFC 1191 §6.5
retransmit walkback) is shipped; active MTU re-probing
lands through the RFC 8899 DPLPMTUD engine
(`tcp.mtu_probing`). The remaining gap is timer-driven
expiry of classical `stack.pmtu_cache` entries — a
focused follow-up commit.
