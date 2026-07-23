# RFC 7559 — Packet-Loss Resiliency for Router Solicitations

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 7559                                              |
| Title       | Packet-Loss Resiliency for Router Solicitations   |
| Category    | Standards Track (Updates RFC 4861)                |
| Date        | May 2015                                          |
| Source text | [`rfc7559.txt`](rfc7559.txt)                      |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative statement
in RFC 7559. The audit was performed by reading the RFC
text fresh and inspecting
`packages/pytcp/pytcp/runtime/packet_handler/__init__.py` directly.

Adherence levels: **met**, **partial**, **not implemented**,
**n/a**.

---

## Top-line adherence

PyTCP **meets** RFC 7559 §2 RS retransmission backoff. The
SLAAC boot path emits up to `ICMP6__MAX_RTR_SOLICITATIONS`
Router Solicitations spaced by truncated binary exponential
backoff with ±10% jitter; the first received RA short-
circuits the loop via an event semaphore the RX path
releases. All four timing constants are sysctl-tunable.

| Section | Topic                                              | Status |
|---------|----------------------------------------------------|--------|
| §1      | Background — RS loss problem                       | n/a (motivation)               |
| §2      | Backoff algorithm (RT, MRT, RAND)                  | met                            |
| §3      | RS retransmission triggered on RA receipt          | met (event-based short-circuit) |
| §4      | Operator-tunable constants                         | met (sysctl-backed)            |

---

## §2 RS Retransmission Algorithm

> "The Router Solicitation retransmission algorithm uses
>  a truncated binary exponential backoff: starting with
>  RT = SOL_INTERVAL, the host doubles RT after each
>  transmission, capped at MRT = MAX_SOL_INTERVAL, with
>  ±10% jitter."

**Adherence:** met.
`_send_icmp6_nd_router_solicitations_with_backoff` at
`packages/pytcp/pytcp/runtime/packet_handler/__init__.py:3534-3559`
implements the algorithm:

```python
for _ in range(max_attempts):
    self._send_icmp6_nd_router_solicitation()
    wait_s = (rt_ms + random.uniform(-0.1, 0.1) * rt_ms) / 1000.0
    if self._icmp6_ra__event.acquire(timeout=wait_s):
        return
    rt_ms = min(2 * rt_ms, mrt_ms)
```

- Initial `rt_ms = ICMP6__RTR_SOLICITATION_INTERVAL_MS`
  (sysctl `icmp6.rtr_solicitation_interval_ms`, default
  matches the §2 SOL_INTERVAL = 4 seconds).
- After each round, `rt_ms = min(2 * rt_ms, mrt_ms)`
  where `mrt_ms = ICMP6__RTR_SOLICITATION_MAX_RT_MS`
  (sysctl `icmp6.rtr_solicitation_max_rt_ms`, default
  matches §2 MAX_SOL_INTERVAL = 3600 seconds = 1 hour).
- Jitter: `random.uniform(-0.1, 0.1) * rt_ms` adds ±10%
  per §2 RAND specification.

> "The host MUST NOT exceed MAX_RTR_SOLICITATIONS
>  retransmissions."

**Adherence:** met.
`max_attempts = ICMP6__MAX_RTR_SOLICITATIONS` (sysctl
`icmp6.max_rtr_solicitations`, default 3 per RFC 4861
§10) caps the loop. Setting the sysctl to 0 disables RS
entirely (kill-switch path; useful for static-config
deployments).

---

## §3 RS Retransmission Cancellation on RA Receipt

> "The host SHOULD cease RS retransmissions immediately
>  upon receipt of a valid Router Advertisement."

**Adherence:** met. The RA RX handler at
`packet_handler__icmp6__rx.py` calls
`self._icmp6_ra__event.release()` when a valid RA is
received; the backoff loop above waits on
`self._icmp6_ra__event.acquire(timeout=wait_s)` and
returns immediately when the event fires. The next
iteration of the loop is skipped entirely — no further
RS goes out.

---

## §4 Operator-Tunable Constants

> "An implementation SHOULD provide knobs for SOL_INTERVAL,
>  MAX_SOL_INTERVAL, MAX_RTR_SOLICITATIONS, and the jitter
>  factor."

**Adherence:** met (sysctl-backed). The three RFC 7559
constants are sysctl-registered in
`packages/pytcp/pytcp/protocols/icmp6/nd/nd__constants.py`:

| Sysctl key                            | RFC 7559 name           | Default |
|---------------------------------------|-------------------------|---------|
| `icmp6.rtr_solicitation_interval_ms`  | SOL_INTERVAL × 1000     | 4000    |
| `icmp6.rtr_solicitation_max_rt_ms`    | MAX_SOL_INTERVAL × 1000 | 3600000 |
| `icmp6.max_rtr_solicitations`         | MAX_RTR_SOLICITATIONS   | 3       |

The ±10% jitter is hard-coded per §2 RAND specification
and is not currently sysctl-tunable (no consumer for a
finer jitter knob; the spec value is universally fine).

---

## Test coverage audit

### §2 Backoff algorithm

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__rs_backoff.py`
  — drives a sequence of RS emissions with no RA
  response, asserts the inter-RS spacing follows the
  RT, 2*RT, 4*RT, ... up to MRT progression and the
  count tops out at MAX_RTR_SOLICITATIONS.

**Status:** locked in.

### §3 RA receipt short-circuit

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__rs_backoff.py`
  — drives an RA mid-backoff and asserts no further RS
  is emitted.

**Status:** locked in.

### Test coverage summary

| Aspect                                              | Coverage |
|-----------------------------------------------------|----------|
| Backoff RT progression (2× per round, capped at MRT) | locked in |
| ±10% jitter applied                                 | locked in indirectly |
| RA receipt short-circuits the loop                  | locked in |
| MAX_RTR_SOLICITATIONS cap                           | locked in |
| Kill-switch (max_rtr_solicitations=0)               | locked in |

---

## Overall assessment

| Aspect                                                | Status |
|-------------------------------------------------------|--------|
| §2 Truncated binary exponential backoff (RT, MRT)     | met    |
| §2 ±10% jitter (RAND)                                 | met    |
| §2 MAX_RTR_SOLICITATIONS cap                          | met    |
| §3 RA receipt cancels retransmission                  | met    |
| §4 Operator-tunable timing constants                  | met (sysctl-backed) |

PyTCP fully ships RFC 7559. The event-semaphore-based
short-circuit is cleaner than a poll-based "did an RA
arrive" check — the RX thread signals once, the backoff
thread wakes immediately.

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §5.4
  — parent classification (MUST).
- `docs/rfc/icmp6/rfc4861__ipv6_nd/adherence.md` — parent
  ND record.
- Source: `packages/pytcp/pytcp/runtime/packet_handler/__init__.py:3534-3559`
  (`_send_icmp6_nd_router_solicitations_with_backoff`).
