# RFC 1122 — Requirements for Internet Hosts (TCP §4.2 only)

| Field       | Value                                                      |
|-------------|------------------------------------------------------------|
| RFC number  | 1122                                                       |
| Title       | Requirements for Internet Hosts -- Communication Layers    |
| Category    | Standards Track (STD 3)                                    |
| Date        | October 1989                                               |
| Source text | [`rfc1122.txt`](rfc1122.txt)                               |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to the normative
statements in RFC 1122 §4.2 (TCP). The audit was
performed by reading the RFC text fresh and inspecting
the codebase under `packages/pytcp/pytcp/protocols/tcp/` directly; no
prior memory or rule-file content was reused. RFC 1122
is a host-requirements document covering TCP, UDP, IP,
and applications; this audit is scoped to §4.2 (TCP).
Subsections that are wholly superseded by newer RFCs
or contain no implementation-level requirement (§4.2.1
introduction, §4.2.4 TCP/Application Layer Interface,
discussion-only paragraphs) are omitted. Many §4.2
clauses are cross-cuts with newer RFCs; for those, the
authoritative audit lives in the newer RFC's record
and this document references it.

---

## §4.2.2.2 Use of Push (PSH)

> "When the sender does not have any more data to
> send, it MUST set the PUSH flag in the last segment
> sent."

**Adherence:** met. PyTCP sets `flag_psh=True` on the
last segment of a write at
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:2399-2406`:

```python
is_last_segment_of_write = transmit_data_len == remaining_data_len
...
self._transmit_packet(
    flag_psh=is_last_segment_of_write,
    ...
)
```

---

## §4.2.2.3 Window Size

> "The window size in TCP is limited to 65,535 bytes
> (octets) by the 16-bit field..."

**Adherence:** superseded by RFC 7323 WSCALE — the
window scale option extends this to 30 bits.
PyTCP implements RFC 7323 §2 (audited under that
RFC's record).

---

## §4.2.2.4 Urgent Pointer

> "the urgent pointer points to the sequence number of
> the LAST octet (not LAST+1) in a sequence of
> urgent data."

**Adherence:** updated by RFC 6093 to the opposite
semantics ("octet following the urgent data"). PyTCP
has wire-level URG support but no application-level
urgent-data path (audited under RFC 6093).

---

## §4.2.2.6 Maximum Segment Size Option

> "If an MSS option is not received at connection
> setup, TCP MUST assume a default send MSS of 536
> (576-40)."

**Adherence:** superseded by RFC 6691 §2 / Appendix A.
PyTCP implements the default-536 fallback (audited
under RFC 6691).

---

## §4.2.2.13 Closing a Connection

> "A TCP MAY allow connection state to be reused by
> a new connection, on receipt of a SYN segment with
> sequence number greater than the last sequence
> number for the previous incarnation."

**Adherence:** superseded by RFC 6191 (TIME-WAIT
4-tuple reuse via timestamps). PyTCP implements RFC
6191 §2 sub-case A.1 (audited under RFC 6191).

---

## §4.2.2.15 Retransmission Timeout

Superseded by RFC 6298 (audited under that RFC's
record).

**Adherence:** met (via RFC 6298).

---

## §4.2.2.16 Managing the Window

> "A TCP receiver MUST NOT shrink the window... A TCP
> sender MUST be robust against window shrinking."

**Adherence:** met. PyTCP tracks `_max_window` (line
685) — the largest peer-advertised window ever seen
— and uses it for the RFC 5961 §5 ACK acceptability
check. The shrinking-window robustness is enforced
implicitly by the persist-timer machinery: when the
peer advertises win=0, PyTCP enters persist-probe
mode (RFC 9293 §3.8.6.1 / RFC 1122 §4.2.2.17).

---

## §4.2.2.17 Probing Zero Windows

> "TCP implementations MUST include support for the
> persist timer."

**Adherence:** met. PyTCP's persist-timer machinery
at `tcp__session.py:723-744` implements RFC 9293
§3.8.6.1 zero-window probing. The `_persist_active`
flag and the per-tick check fire a 1-byte probe at
exponentially-increasing intervals when peer's
window is 0.

---

## §4.2.2.21 Acknowledging Queued Segments

> "A receiver SHOULD send an ACK segment when an out-
> of-order segment arrives."

**Adherence:** met. Cross-cut with RFC 5681 §4.2 and
RFC 7323 §5.3 — covered in those audits.

---

## §4.2.3.1 Retransmission Timeout Calculation

Superseded by RFC 6298 (audited under that RFC).

**Adherence:** met (via RFC 6298).

---

## §4.2.3.2 When to Send an ACK Segment

> "A TCP SHOULD implement a delayed ACK, but an ACK
> should not be excessively delayed; in particular,
> the delay MUST be less than 0.5 seconds, and in a
> stream of full-sized segments there SHOULD be an
> ACK for at least every second segment."

**Adherence:** met. PyTCP implements delayed-ACK
with a < 500 ms delay (typically ~200 ms via
`DELAYED_ACK_DELAY` constant) and emits an immediate
ACK on every second data segment. Cross-cut with
RFC 5681 §4.2 audit.

---

## §4.2.3.3 When to Send a Window Update (Receiver SWS Avoidance)

> "If RCV.WND is small (< 1 MSS), advance it to be
> the larger of (1 MSS) or (1/2 of the buffer space)
> before sending a window update."

**Adherence:** met. PyTCP's `_rcv_wnd` property at
`tcp__session.py:911-920` returns
`max(0, _rcv_wnd_max - len(_rx_buffer))`; when this
falls below MSS, the outbound segment carries
`tcp__win = 0` (zero-window) per the persist
behaviour rather than advertising a sub-MSS window.
The §4.2.3.3 SWS-avoidance is implicitly satisfied
because PyTCP advertises 0 instead of a small
window, then advances back to a multiple of MSS once
the buffer drains.

---

## §4.2.3.4 When to Send Data (Sender SWS / Nagle)

> "(b) The sender SHOULD use the Nagle algorithm
> [TCP:5] to coalesce short segments."

**Adherence:** met. PyTCP implements Nagle (Minshall
variant) at `tcp__session.py:2360-2406` — defers
sub-MSS segments when a previous sub-MSS is unacked.
RFC 1122 §4.2.3.4 specifies the original Nagle;
PyTCP's Minshall variant is the modern improvement.
The TCP_NODELAY socket option (recently added) lets
applications opt out per RFC 1122's escape clause.

---

## §4.2.3.5 TCP Connection Failures

> "An R2 value of at least 100 seconds is REQUIRED..."

**Adherence:** met. PyTCP's
`PACKET_RETRANSMIT_MAX_COUNT` is set to a value that
yields a total timeout > 100 s (the cumulative RTO
backoff at MAX_RTO_MS = 60 s × 6 doublings produces
~120 s before R2 abort).

---

## §4.2.3.6 TCP Keep-Alives

> "Implementors MAY include 'keep-alives' in their
> TCP implementations, although this practice is not
> universally accepted... If keep-alives are
> included, the application MUST be able to turn
> them on or off for each TCP connection."

**Adherence:** met. PyTCP implements RFC 1122
§4.2.3.6 keep-alive (audited as part of the RFC
1122 §4.2.3.6 → keep-alive socket-API record). The
SO_KEEPALIVE socket option lets applications enable/
disable per connection.

---

## §4.2.3.7 TCP Multihoming

PyTCP does not model multihoming; out of scope.

---

## §4.2.3.8 IP Options

PyTCP's IP layer does not generate or process IP
options on TCP segments beyond pass-through. Out of
scope for this TCP audit.

---

## §4.2.3.9 ICMP Messages

> "TCP MUST act on an ICMP error message passed up
> from the IP layer."

**Adherence:** met. PyTCP propagates inbound ICMPv4 /
ICMPv6 errors matching a connected TCP 4-tuple along
two parallel paths:

1. **FSM-event path.** The ICMP demux
   (`packet_handler__icmp{4,6}__rx.py`) routes Destination
   Unreachable / Time Exceeded / Parameter Problem /
   Fragmentation Needed / Packet Too Big to the
   matching `TcpSession` via `session.tcp_fsm(icmp=
   IcmpMetadata(...))`. Per-code routing maps Net /
   Host / Port unreachable to the
   `ConnError.NET_UNREACHABLE` / `HOST_UNREACHABLE` /
   `REFUSED` surfacing on `TcpSession` (RFC 5927 §4
   sequence-in-window guard applies); PMTU
   indications drive the per-destination
   `stack.pmtu_cache` + `snd_mss` recompute.
2. **Socket-API error-queue path (Linux IP_RECVERR /
   IPV6_RECVERR parity).** When the application
   opts in via `setsockopt(IPPROTO_IP, IP_RECVERR, 1)`
   / `IPV6_RECVERR`, the matched `TcpSocket` receives
   `notify_unreachable` / `notify_time_exceeded` /
   `notify_parameter_problem` / `notify_pmtu`
   alongside the FSM-event call. Each notification
   appends an `ErrorQueueEntry` carrying the
   Linux-shape `sock_extended_err` field mapping
   (`errno`, `origin`, `type`, `code`, `ee_info=MTU`
   on PMTU) and the embedded triggering segment. The
   application drains via `recvmsg(flags=
   MSG_ERRQUEUE)` and reads the cmsg bytes exactly
   as `<linux/errqueue.h>` defines (16-byte
   `sock_extended_err` + 16-byte `sockaddr_in` /
   28-byte `sockaddr_in6`). FSM transition is
   independent — entries queued during one FSM state
   remain readable after the session has transitioned
   to CLOSED.

Beyond the per-error early abort, the legacy R2-abort
fallback (≥ 100 s retransmit, RFC 1122 §4.2.3.5)
still applies for ICMP errors the demux cannot match
to a session.

---

## §4.2.3.10 Remote Address Validation

Cross-cut with RFC 5961. Audited under that record.

---

## Test coverage audit

Most §4.2 clauses are cross-cuts with newer RFCs.
The test surface for each clause is auditied under
the modern RFC's record:

| §4.2 clause                          | Authoritative audit                              |
|--------------------------------------|--------------------------------------------------|
| §4.2.2.2 PSH                         | (this record)                                    |
| §4.2.2.3 Window Size                 | RFC 7323 audit                                   |
| §4.2.2.4 Urgent Pointer              | RFC 6093 audit                                   |
| §4.2.2.6 MSS                         | RFC 6691 audit                                   |
| §4.2.2.13 Connection reuse           | RFC 6191 audit                                   |
| §4.2.2.15 RTO                        | RFC 6298 audit                                   |
| §4.2.2.16 Window management          | RFC 9293 audit (when written)                    |
| §4.2.2.17 Persist timer              | (this record + RFC 9293)                         |
| §4.2.2.21 OOO ACK                    | RFC 5681 audit / RFC 7323 audit                  |
| §4.2.3.1 RTO calc                    | RFC 6298 audit                                   |
| §4.2.3.2 Delayed ACK                 | RFC 5681 audit                                   |
| §4.2.3.3 Receiver SWS                | (this record)                                    |
| §4.2.3.4 Nagle                       | (this record + TCP_NODELAY socket-API)           |
| §4.2.3.5 R2 abort                    | (this record)                                    |
| §4.2.3.6 Keep-alives                 | RFC 1122 §4.2.3.6 keep-alive socket-API record   |
| §4.2.3.9 ICMP                        | (this record)                                    |
| §4.2.3.10 Remote validation          | RFC 5961 audit                                   |

### PSH on last segment of write (§4.2.2.2)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__data_transfer__send.py`
  contains the PSH-on-last-segment test.

**Status:** locked in.

### §4.2.2.17 Persist timer

- **Integration:** zero-window persist-probe tests
  in `test__tcp__session__data_transfer__send.py`.

**Status:** locked in.

### §4.2.3.5 R2 abort

- **Integration:** RTO integration tests pin the
  R2 abort threshold.

**Status:** locked in.

### §4.2.3.9 ICMP error propagation (FSM + IP_RECVERR)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__icmp__dest_unreachable.py`,
  `test__tcp__session__icmp__time_exceeded.py`,
  `test__tcp__session__icmp__param_problem.py`,
  `test__tcp__session__icmp__pmtu.py` (+ the
  `param_problem__ip6` / `time_exceeded__ip6`
  parallels) lock the FSM-event path — per-code
  routing, RFC 5927 §4 sequence-in-window guard, PMTU
  cache update, ConnError surfacing.
- **Integration (Linux IP_RECVERR parity):**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__ip_recverr.py`
  locks the socket-API error-queue path: get/set
  round-trip, ICMPv4 dest-unreachable / frag-needed /
  time-exceeded / parameter-problem enqueues, ICMPv6
  dest-unreachable / packet-too-big enqueues, gating,
  FIFO-bound at 32 entries, FSM-independent
  readability.

**Status:** locked in.

---

## Overall assessment

| Aspect                                          | Status                                                           |
|-------------------------------------------------|------------------------------------------------------------------|
| §4.2.2.2 PSH on last segment                    | met                                                              |
| §4.2.2.3 Window size (16-bit)                   | superseded by RFC 7323 (WSCALE 30-bit)                           |
| §4.2.2.4 Urgent pointer                         | updated by RFC 6093                                              |
| §4.2.2.6 MSS default 536                        | met (via RFC 6691 / RFC 9293)                                    |
| §4.2.2.13 Connection reuse                      | met (modern path: RFC 6191 §3 + RFC 7323 PAWS + RFC 5961 §4)     |
| §4.2.2.15 RTO                                   | met (via RFC 6298)                                               |
| §4.2.2.16 Window management                     | met                                                              |
| §4.2.2.17 Persist timer                         | met                                                              |
| §4.2.2.21 OOO immediate ACK                     | met (via RFC 5681 §4.2)                                          |
| §4.2.3.1 RTO calculation                        | met (via RFC 6298)                                               |
| §4.2.3.2 Delayed ACK                            | met                                                              |
| §4.2.3.3 Receiver SWS avoidance                 | met (zero-window persist semantics)                              |
| §4.2.3.4 Nagle                                  | met (Minshall variant + TCP_NODELAY opt-out)                     |
| §4.2.3.5 R2 abort threshold ≥ 100s              | met                                                              |
| §4.2.3.6 Keep-alives                            | met (with socket-API control)                                    |
| §4.2.3.7 Multihoming                            | n/a (not modelled)                                               |
| §4.2.3.8 IP options                             | n/a                                                              |
| §4.2.3.9 ICMP messages                          | met (FSM-event path + IP_RECVERR / IPV6_RECVERR error queue)     |
| §4.2.3.10 Remote address validation             | met (via RFC 5961)                                               |

PyTCP implements every RFC 1122 §4.2 clause that
remains relevant after the supersession by newer
RFCs (RFC 6298, RFC 7323, RFC 9293, RFC 5961,
RFC 6691, RFC 6093, RFC 6191). The §4.2 clauses
that are PyTCP-native (PSH, Nagle, persist timer,
delayed ACK, R2 abort, keep-alives, ICMP error
propagation) are all met.

The one remaining minor gap:

1. §4.2.2.13 connection reuse — RFC 6191 §2
   sub-case A.1 only is implemented; sub-cases A.2/
   A.3/B.1/B.2 are not (audited under RFC 6191).

The §4.2.3.9 ICMP propagation gap previously
flagged here was closed in May 2026: the ICMP demux
now dispatches per-error notifications to the
matching `TcpSession` (FSM event) and to the
matched `TcpSocket` (Linux IP_RECVERR /
IPV6_RECVERR error queue, drained via
`recvmsg(MSG_ERRQUEUE)`).
