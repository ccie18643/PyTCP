# RFC 1191 — Path MTU Discovery

| Field       | Value                                |
|-------------|--------------------------------------|
| RFC number  | 1191                                 |
| Title       | Path MTU Discovery                   |
| Category    | Standards Track                      |
| Date        | November 1990                        |
| Source text | [`rfc1191.txt`](rfc1191.txt)         |

This document records, paragraph by paragraph, how
the current PyTCP codebase relates to each normative
statement in RFC 1191.

---

## Top-line adherence

After the ICMP demux + PMTUD refactor (commits in
`docs/refactor/icmp_demux_pmtud_plan.md` Phases 1-8),
PyTCP **partially implements** classic RFC 1191:

- Outbound TCP and UDP set DF=1 on the IP4 header.
- Inbound ICMPv4 Type 3 Code 4 (Frag-Needed) carrying
  a Next-Hop MTU is parsed, demuxed to the matching
  TCP/UDP socket, and lands in the per-destination
  `stack.pmtu_cache`.
- TCP recomputes `snd_mss` from the new path MTU.
- UDP records the new MTU on the socket via
  `notify_pmtu`.

What still **does not happen**:

- Per-destination MTU aging (RFC 1191 §7) — entries
  never expire.
- Plateau-search fallback for non-RFC-1191 routers
  whose ICMP error has no Next-Hop MTU (§6.5).

---

## §3 Mechanisms

### §3 IP DF flag set on outbound IPv4

> "When an IP datagram is sent with DF=1 ('Don't
> Fragment'), routers that cannot fit it through the
> next link MUST drop it and return an ICMP
> Destination Unreachable / Fragmentation Needed
> message."

**Adherence:** **shipped** (Phase 8). The TCP TX
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__tcp__tx.py`)
and UDP TX
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__udp__tx.py`)
paths now pass `ip4__flag_df=True` to `_phtx_ip4`. ICMPv4
TX paths and other internally-generated v4 frames keep
`ip4__flag_df=False` so error replies preserve the
inbound DF semantics.

### §3 ICMP "Fragmentation Needed" reception with Next-Hop MTU field

> "Upon receipt of an ICMP Destination Unreachable /
> Fragmentation Needed message, the host MUST reduce
> its estimate of the path MTU to the value indicated
> in the Next-Hop MTU field (RFC 1191 §4)."

**Adherence:** **shipped**. The ICMPv4 RX handler at
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__icmp4__rx.py`
demuxes Type 3 Code 4 (Frag-Needed) on the embedded
4-tuple. UDP sockets see the update via
`UdpSocket.notify_pmtu`; TCP sessions see it via
`TcpSession.tcp_fsm(icmp=IcmpMetadata(category=PMTU,
...))`, which routes through the per-state ICMP
handlers in
`packages/pytcp/pytcp/protocols/tcp/fsm/tcp__fsm__<state>.py` to the
session's private `_apply_pmtu_update` helper. The
helper records the Next-Hop MTU into `stack.pmtu_cache`
keyed by remote address, shrinks `self._win.snd_mss`,
and (per RFC 1191 §6.5 below) walks back any in-flight
oversized segments. The RFC 5927 §4
sequence-in-window guard is applied before notifying
TCP.

### §6.5 TCP retransmit walkback on PMTU shrink

> "If TCP responds to the receipt of an ICMP Datagram
> Too Big message by retransmitting the segment that
> caused the message, it MUST take care to choose new
> IP-level segment boundaries such that the new
> segments are smaller than the new path MTU."

**Adherence:** **shipped**.
`TcpSession._apply_pmtu_update` (in
`packages/pytcp/pytcp/protocols/tcp/session/tcp__session.py:1508`) detects the
case where the inbound Frag-Needed shrinks `snd_mss`
AND in-flight RACK segments exceed the new MSS. When
both conditions hold, it marks every in-flight RACK
segment lost and rewinds `snd_nxt` to `snd_una`, so
the next timer tick re-emits from `snd_una` at the
new (smaller) MSS rather than waiting for RTO
(typically ≥ 1 second).

Crucially, the walkback path does NOT halve `cwnd` /
`ssthresh`, does NOT bump `_retransmit_count`, and
does NOT back off RTO — a path that narrowed is not
a congestion event. This matches Linux's
`tcp_simple_retransmit` behaviour. The RFC requires
"new IP-level segment boundaries"; PyTCP's TX path
re-fragments naturally from the byte-oriented
`_tx.buffer` at the current `snd_mss`, so the rewind
is sufficient.

### §6.5 Old-style ICMP detection (non-RFC-1191 routers)

> "Hosts MUST be prepared to fall back to a
> conservative MTU value when the ICMP response does
> not carry the Next-Hop MTU field (i.e. older
> routers without RFC 1191 support)."

**Adherence:** not implemented. The codebase only
honors Frag-Needed messages that carry a Next-Hop MTU
field. Older routers' "ICMP-without-Next-Hop-MTU"
fallback to a plateau-table search (576, 1280, ...) is
out of scope for this refactor and deferred alongside
RFC 4821 PLPMTUD.

### §7 Path MTU Aging

> "The host's path MTU estimate MUST be aged out
> periodically so that increases in the path MTU
> can be detected."

**Adherence:** not implemented. `stack.pmtu_cache`
is process-lifetime; entries do not expire. A
process restart purges the cache. Periodic
re-discovery is left for the RFC 4821 PLPMTUD
follow-up.

---

## Test coverage audit

| Aspect                                              | Coverage |
|-----------------------------------------------------|----------|
| §3 outbound DF=1 on TCP segments                    | shipped — `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__tcp__tx.py` golden frames |
| §3 outbound DF=1 on UDP datagrams                   | shipped — `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__udp__tx.py` golden frames |
| §4 ICMP Frag-Needed Next-Hop MTU update for UDP     | shipped — `packages/pytcp/pytcp/tests/integration/protocols/icmp4/test__icmp4__pmtud.py` |
| §4 ICMP Frag-Needed Next-Hop MTU update for TCP     | shipped — `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__icmp__pmtu.py` |
| §6.5 retransmit walkback (snd_nxt rewind on shrink) | shipped — `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__pmtu_walkback.py` |
| §6.5 fallback for non-RFC-1191 routers              | n/a (gap) |
| §7 PMTU aging                                       | n/a (gap) |

---

## Overall assessment

| Aspect                                       | Status          |
|----------------------------------------------|-----------------|
| §3 outbound DF=1 + ICMP-driven discovery     | **shipped**     |
| §4 Next-Hop MTU field consumption            | **shipped**     |
| §6.5 TCP retransmit walkback                 | **shipped**     |
| §6.5 plateau-search fallback                 | not implemented |
| §7 path-MTU aging                            | not implemented |

PyTCP now sets DF=1 on outbound TCP/UDP, consumes
ICMPv4 Frag-Needed Next-Hop MTU updates, and shrinks
both the per-destination MTU cache and the TCP
session's `snd_mss`. The two remaining RFC 1191 gaps
(plateau-search fallback and path-MTU aging) are
substrate-completable: the substrate added by this
refactor (`stack.pmtu_cache`, embedded-header demux,
`on_pmtu` callback) makes both follow-ups tractable
as separate feature commits, ideally alongside RFC
4821 / 8899 active probing.
