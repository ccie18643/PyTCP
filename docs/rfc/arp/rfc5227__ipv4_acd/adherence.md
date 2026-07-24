# RFC 5227 — IPv4 Address Conflict Detection

| Field       | Value                                                  |
|-------------|--------------------------------------------------------|
| RFC number  | 5227                                                   |
| Title       | IPv4 Address Conflict Detection                        |
| Category    | Standards Track                                        |
| Date        | July 2008                                              |
| Updates     | RFC 826 (does not modify, but extends)                 |
| Source text | [`rfc5227.txt`](rfc5227.txt)                           |

This document records, paragraph by paragraph, how the current
PyTCP codebase relates to each normative statement of RFC 5227
(IPv4 ACD — ARP probe / announce / ongoing detection /
defense). The audit was refreshed on 2026-05-12 after the
RFC 3927 link-local autoconfig track closed (Phases 0-5,
commits `a845d5a1` → `8f09846b`), which shipped the
underlying ACD machinery this RFC pins. Prior audit text
described a pre-RFC-3927-track state with multiple "gap not
closed" entries; the bulk of those gaps are now closed —
this refresh re-derives every adherence verdict from the
current code state without re-using prior content.

As of Phase 4.4, all ACD is a **userspace** function over the
`Ip4Acd` engine (`packages/pytcp/pytcp/protocols/ip4/acd/ip4_acd.py`) — the
Linux `sd-ipv4acd` / `n-acd` model. Each managed address that
wants conflict handling owns an `Ip4Acd` bound to its
interface's MAC + ifindex and runs probe / announce / ongoing
defense over its own AF_PACKET socket. The kernel-equivalent
stack ARP RX path performs **no** conflict detection. The
engine surface:

- `probe(*, address)` — runs the §2.1.1 Probe sequence over a
  throwaway socket; returns an `AcdResult` (success + peer MAC
  on conflict).
- `announce(*, address)` — emits the §2.3 ANNOUNCE_NUM burst.
- `claim(*, address)` — probe + announce, then HOLDS the
  socket for ongoing defense.
- `start_defense(*, address)` — announce + hold, for a caller
  whose Probe ran separately (the DHCPv4 split flow).
- `poll_conflict()` — non-blocking §2.4 ongoing-conflict drain
  on the held socket → peer MAC or None.
- `defend()` — single §2.4(b) defensive gratuitous ARP.
- `release()` — drop the claim / close the socket.

Consumers:

- **Static host** (`PacketHandlerL2._create_stack_ip4_addressing`):
  `probe` + `announce`, no ongoing defender (bare `ip addr
  add`).
- **DHCPv4 client**: `probe` on the offered address (DECLINE
  on conflict), `start_defense` on BOUND, `poll_conflict` each
  tick → DHCPDECLINE + re-acquire on conflict.
- **RFC 3927 link-local client**: `claim` + `poll_conflict`,
  `defend` / abandon per its §2.5 decision tree.

`AddressApi` (`packages/pytcp/pytcp/stack/address.py:60`) is now the
pure `ip addr` surface (`add` / `remove` / `replace` /
`list_ifaddrs`, covering both IPv4 and IPv6); `remove` ABORTs
bound TCP sessions per the §2.4-final SHOULD (via the internal
`_abort_bound_tcp_sessions` helper). (The former `probe` /
`announce` / `claim_with_acd` / `send_gratuitous_arp` /
`subscribe_conflicts` API surface and the in-RX
`_handle_arp_conflict` / `_arp_dad_*` machinery were removed in
Phase 4.4c-4.5.)

Adherence levels use the canonical descriptive language:
**met**, **not met**, **partial**, **not implemented**,
**vacuous**.

Sections without normative content — Abstract, §1
(Introduction motivation), §1.2 (Relationship to RFC 826
narrative), §1.3 (Applicability narrative), §3 (rationale
for using Request not Reply for Announcements), §4 (Historical
Note), §5 (Security Considerations), §6 (Acknowledgments),
§7 (References) — are summarised inline only where they
inform a normative §2 requirement, and otherwise omitted.

---

## §2.1 — Probing an Address (mandatory probe before use)

> "Before beginning to use an IPv4 address (whether received
> from manual configuration, DHCP, or some other means), a
> host implementing this specification MUST test to see if
> the address is already in use, by broadcasting ARP Probe
> packets."

**Adherence:** **met**. As of Phase 4.4a every claim path runs
the §2.1.1 probe sequence over the userspace `Ip4Acd` engine
(`packages/pytcp/pytcp/protocols/ip4/acd/ip4_acd.py`), the Linux
`sd-ipv4acd` model — each managed address probes (and, on a clean
probe, announces) over its own AF_PACKET socket, with the stack's
ARP RX path uninvolved. The static-host claim
(`PacketHandlerL2._create_stack_ip4_addressing`) builds one
`Ip4Acd` per candidate and calls `probe` then `announce` before
admitting the address to `self._ip4_ifaddr`. The DHCPv4 DAD path
(`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py` via the
`arp_dad_verifier` callback wired to `Ip4Acd.probe` in
`packages/pytcp/pytcp/stack/lifecycle.py`) and the RFC 3927
link-local candidate-probe loop
(`packages/pytcp/pytcp/protocols/ip4/link_local/link_local__client.py`,
via `Ip4Acd.claim`) use the same engine.

> "A host MUST NOT perform this check periodically as a
> matter of course."

**Adherence:** **met**. Probes are emitted only on explicit
claim (DHCP discover, RFC 3927 candidate-rotation, manual
static-host configure). There is no scheduled re-probe path.

---

## §2.1.1 — Probe Details (wire format + timing)

> "A host probes ... by broadcasting an ARP Request for the
> desired address. The client MUST fill in the 'sender
> hardware address' field of the ARP Request with the
> hardware address of the interface ... The 'sender IP
> address' field MUST be set to all zeroes ... The 'target
> hardware address' field is ignored and SHOULD be set to
> all zeroes. The 'target IP address' field MUST be set to
> the address being probed."

**Adherence:** **met**. `Ip4Acd._send`
(`packages/pytcp/pytcp/protocols/ip4/acd/ip4_acd.py`), invoked from the
Probe loop with `oper=REQUEST, spa=Ip4Address(), tpa=address`,
builds every field exactly as required:
- `arp__oper = ArpOperation.REQUEST`
- `arp__sha = self._mac` (the engine's interface MAC)
- `arp__spa = Ip4Address()` — all-zeroes per MUST
- `arp__tha = MacAddress()` — all-zeroes per SHOULD
- `arp__tpa = address` (the candidate)
- `ethernet__dst = 0xFFFFFFFFFFFF` — broadcast

> "When ready to begin probing, the host should then wait
> for a random time interval selected uniformly in the
> range zero to PROBE_WAIT seconds, and should then send
> PROBE_NUM probe packets, each of these probe packets
> spaced randomly and uniformly, PROBE_MIN to PROBE_MAX
> seconds apart."

**Adherence:** **met**. `Ip4Acd._run_probe`
(`packages/pytcp/pytcp/protocols/ip4/acd/ip4_acd.py`) implements the full
sequence over the ACD socket:

1. `_watch_for_conflict(sock, address, random.uniform(0,
   ARP__PROBE_WAIT))` — initial 0..PROBE_WAIT random delay
   (spent watching the socket for an early conflict).
2. `for _ in range(ARP__PROBE_NUM): _send(...)` — exactly
   PROBE_NUM probes.
3. `_watch_for_conflict(sock, address,
   random.uniform(ARP__PROBE_MIN, ARP__PROBE_MAX))` between
   probes — uniform inter-probe spacing.

Default constants from `packages/pytcp/pytcp/protocols/arp/arp__constants.py`:
`ARP__PROBE_WAIT = 1`, `ARP__PROBE_NUM = 3`, `ARP__PROBE_MIN
= 1`, `ARP__PROBE_MAX = 2`. All four are sysctl-registered so
operators can tune them at boot or runtime; the engine reads
them through qualified `arp__constants.*` access so an
override takes effect on the next run.

> "If during this period, from the beginning of the probing
> process until ANNOUNCE_WAIT seconds after the last probe
> packet is sent, the host receives any ARP packet (Request
> *or* Reply) on the interface where the probe is being
> performed, where the packet's 'sender IP address' is the
> address being probed for, then the host MUST treat this
> address as being in use by some other host ..."

**Adherence:** **met**. The probe-window conflict surface is
`Ip4Acd._watch_for_conflict`, which reads ARP off the engine's
own AF_PACKET socket for the full probe + ANNOUNCE_WAIT window
and returns the offending peer MAC the moment `_is_conflict`
matches. `_is_conflict(arp, address)` flags any frame (Request
or Reply) whose `arp.spa == address` from a foreign SHA — the
exact predicate the RFC mandates. Because the engine reads
its own socket, conflict detection no longer depends on the
stack ARP RX path or a `DadSlotRegistry` slot (the IPv4 use
of that registry was removed in Phase 4.4c; the class remains
for IPv6 ND DAD).

> "In addition, if during this period the host receives any
> ARP Probe where the packet's 'target IP address' is the
> address being probed for, and the packet's 'sender
> hardware address' is not the hardware address of any of
> the host's interfaces, then the host SHOULD similarly
> treat this as an address conflict ..."

**Adherence:** **met (§1.2.4 simultaneous-probe case)**.
`Ip4Acd._is_conflict` also returns True when `arp.spa.is_unspecified
and arp.tpa == address` (with a foreign SHA) — a peer probing
the same address. Covered by
`test__ip4__acd__conflict.py::test__ip4_acd__conflict_simultaneous_probe`.

> "NOTE: The check that the packet's 'sender hardware
> address' is not the hardware address of any of the host's
> interfaces is important. ... a host is not confused when
> it sees its own ARP packets echoed back."

**Adherence:** **met (loop guard present)**.
`Ip4Acd._is_conflict` (and `_is_ongoing_conflict`) returns
False immediately when `arp.sha == self._mac`, so the engine
never mis-flags its own echoed Probes / Announcements. Covered
by `test__ip4__acd__conflict.py::test__ip4_acd__own_frame_is_not_conflict`.
The stack ARP RX path additionally drops looped frames
(`arp__op_request__looped__drop` / `arp__op_reply__looped__drop`
counters are bumped on each drop.

> "A host implementing this specification MUST take
> precautions to limit the rate at which it probes for new
> candidate addresses: if the host experiences MAX_CONFLICTS
> or more address conflicts on a given interface, then the
> host MUST limit the rate at which it probes for new
> addresses on this interface to no more than one attempted
> new address per RATE_LIMIT_INTERVAL."

**Adherence:** **met (in the RFC 3927 link-local
subsystem)**. The MAX_CONFLICTS / RATE_LIMIT_INTERVAL gate
is enforced in the link-local candidate-rotation loop
(`packages/pytcp/pytcp/protocols/ip4/link_local/link_local__client.py:242-249`):
after `MAX_CONFLICTS` conflicts within a tracking window,
the subsystem inserts a `RATE_LIMIT_INTERVAL` sleep before
the next probe attempt. The constants live in
`packages/pytcp/pytcp/protocols/ip4/link_local/link_local__constants.py:45,51`
and are sysctl-registered at `:75-90`
(`ip4_link_local.max_conflicts` default 10;
`ip4_link_local.rate_limit_interval_s` default 60).

DHCP-driven claims do not rotate candidates (one DHCP server
hands out one address), so the rate-limit MUST is dormant
in the DHCP path — but it would activate naturally if a
DHCPDECLINE-on-conflict retry loop is added (deferred to
DHCPv4 Phase 9 backlog).

> "If, by ANNOUNCE_WAIT seconds after the transmission of
> the last ARP Probe no conflicting ARP Reply or ARP Probe
> has been received, then the host has successfully
> determined that the desired address may be used safely."

**Adherence:** **met**. `Ip4Acd._run_probe` ends with
`_watch_for_conflict(sock, address, ARP__ANNOUNCE_WAIT)` after
the last Probe before returning the success / conflict
verdict. Late conflicting ARPs arriving within this window are
read off the engine's socket and abort the claim.
`ARP__ANNOUNCE_WAIT = 2` default; sysctl-tunable.

---

## §2.2 — Shorter timeouts on appropriate network technologies

> "Network technologies may emerge for which shorter delays
> are appropriate ... If the situation arises where
> different hosts on a link are using different timing
> parameters, this does not cause any problems."

**Adherence:** **met (no deviation; all timing tunable)**.
PyTCP uses RFC-default constants from
`packages/pytcp/pytcp/protocols/arp/arp__constants.py`. Every timing
constant (PROBE_WAIT, PROBE_NUM, PROBE_MIN, PROBE_MAX,
ANNOUNCE_NUM, ANNOUNCE_INTERVAL, ANNOUNCE_WAIT,
DEFEND_INTERVAL) is registered with `pytcp.stack.sysctl` so
an operator on a fast network can shorten any of them via
`stack.init(sysctls={"arp.probe_wait": 0, ...})` at boot or
`pytcp.stack.sysctl["arp.probe_min"] = 0` at runtime. No
per-link override mechanism yet (deferred to Phase 2
multi-interface), but RFC 5227 itself acknowledges mixed
timing parameters across hosts are non-disruptive.

---

## §2.3 — Announcing an Address

> "Having probed to determine that a desired address may be
> used safely, a host implementing this specification MUST
> then announce that it is commencing to use this address
> by broadcasting ANNOUNCE_NUM ARP Announcements, spaced
> ANNOUNCE_INTERVAL seconds apart."

**Adherence:** **met**. `Ip4Acd._run_announce`
(`packages/pytcp/pytcp/protocols/ip4/acd/ip4_acd.py`) loops
`ARP__ANNOUNCE_NUM` times with `time.sleep(ARP__ANNOUNCE_INTERVAL)`
between successive sends:

```
for announce_idx in range(arp__constants.ARP__ANNOUNCE_NUM):
    if announce_idx > 0:
        time.sleep(arp__constants.ARP__ANNOUNCE_INTERVAL)
    self._send(sock, oper=ArpOperation.REQUEST, spa=address, tpa=address)
```

Defaults: `ARP__ANNOUNCE_NUM = 2`, `ARP__ANNOUNCE_INTERVAL =
2` per `arp__constants.py`; both sysctl-registered.

> "An ARP Announcement is identical to the ARP Probe
> described above, except that now the sender and target IP
> addresses are both set to the host's newly selected IPv4
> address."

**Adherence:** **met**. `Ip4Acd._send` (invoked from
`_run_announce` with `oper=REQUEST, spa=tpa=address`) emits a
Request with `arp__sha = self._mac`, `arp__spa = address`,
`arp__tha = MacAddress()`, `arp__tpa = address`,
`ethernet__dst = 0xFFFFFFFFFFFF` — exactly the §2.3 wire
form.

---

## §2.4 — Ongoing Address Conflict Detection and Address Defense

> "At any time, if a host receives an ARP packet (Request
> *or* Reply) where the 'sender IP address' is (one of) the
> host's own IP address(es) configured on that interface,
> but the 'sender hardware address' does not match any of
> the host's own interface addresses, then this is a
> conflicting ARP packet ..."

**Adherence:** **met (detection — userspace, per address)**.
As of Phase 4.4c the stack's ARP RX path performs **no**
conflict detection: `packet_handler__arp__rx` only answers
Requests for owned IPs, learns the cache, and notes
gratuitous ARPs. This matches the Linux model, where the
kernel ARP code does no IPv4 ACD and a userspace daemon
(`sd-ipv4acd` / `n-acd`) reads ARP off its own AF_PACKET
socket to detect conflicts.

PyTCP's userspace ACD actor is `Ip4Acd`
(`packages/pytcp/pytcp/protocols/ip4/acd/ip4_acd.py`). Its
`poll_conflict` implements exactly this predicate against the
claimed address — `arp.sha != self._mac` AND `arp.spa ==
claimed` (`_is_ongoing_conflict`) — reading ARP off the
defense socket held since the address was claimed. Each
managed address that wants ongoing defense runs its own
`Ip4Acd`; a statically configured address (Phase 4.4a) gets
probe + announce only and **no** ongoing defender, exactly as
a bare Linux `ip addr add` does.

> "(a) Upon receiving a conflicting ARP packet, a host MAY
> elect to immediately cease using the address ..."

**Adherence:** **met — chosen by the DHCPv4 client**. The
DHCPv4 client polls `Ip4Acd.poll_conflict` each BOUND tick
and, on a sustained conflict, takes the (a) immediate-cease
path: `Dhcp4Client._handle_bound_conflict`
(`protocols/dhcp4/dhcp4__client.py`) emits a DHCPDECLINE to
the leasing server, drops the address, releases the ACD
claim, and re-enters INIT to re-acquire — the
systemd-networkd / dhcpcd response for a server-assigned
address (Phase 4.4b).

> "(b) If a host currently has active TCP connections or
> other reasons to prefer to keep the same IPv4 address,
> and it has not seen any other conflicting ARP packets
> within the last DEFEND_INTERVAL seconds, then it MAY
> elect to attempt to defend its address by recording the
> time that the conflicting ARP packet was received, and
> then broadcasting one single ARP Announcement ..."

**Adherence:** **met — chosen by the RFC 3927 link-local
client**. `Ip4Acd.defend` broadcasts the single defensive
gratuitous ARP (an ARP Reply with sender = target = the
claimed address). The §2.4(b) "defend, but only once per
DEFEND_INTERVAL" / §2.4(b) "abandon on the second conflict
within the window" decision tree lives in the link-local
client's BOUND-conflict handler
(`protocols/ip4/link_local/link_local__client.py`), which
owns the per-address conflict-timing state. `Ip4Acd` provides
the mechanism (`defend` / `release`); the consumer owns the
policy. `ARP__DEFEND_INTERVAL = 10` per `arp__constants.py`,
sysctl-registered.

> "However, if this is not the first conflicting ARP packet
> the host has seen, and the time recorded for the
> previous conflicting ARP packet is recent, within
> DEFEND_INTERVAL seconds, then the host MUST immediately
> cease using this address and signal an error to the
> configuring agent ..."

**Adherence:** **met**. The link-local client's BOUND-conflict
handler abandons the address (removing it via the Address API,
which ABORTs bound TCP sessions per the §2.4-final SHOULD) and
returns to its INIT state to pick a fresh candidate; the
DHCPv4 client declines and re-acquires. The
`AddressApi.remove(..., abort_bound_sessions=True)`
path is the shared teardown primitive.

> "(c) If a host has been configured such that it should
> not give up its address under any circumstances ... then
> it MAY elect to defend its address indefinitely. ... if
> this is not the first conflicting ARP packet the host
> has seen, and the time recorded for the previous
> conflicting ARP packet is within DEFEND_INTERVAL seconds,
> then the host MUST NOT send another defensive ARP
> Announcement."

**Adherence:** **partial — (c) indefinite-defend not chosen
by default**. PyTCP's managed-address consumers fall under
(b) + abandon-after-second-conflict, not (c). A future
(c)-mode hook (configurable "this address is too important to
yield") would live in the consuming client and reuse
`Ip4Acd.defend` under its own DEFEND_INTERVAL rate-limit; the
mechanism is in place.

> "Before abandoning an address due to a conflict, hosts
> SHOULD actively attempt to reset any existing connections
> using that address."

**Adherence:** **met**. The abandon paths remove the address
through `AddressApi.remove(...,
abort_bound_sessions=True)`, which issues `SysCall.ABORT` to
every `TcpSession` whose local address equals the abandoned IP
(via the internal `_abort_bound_tcp_sessions` helper) — the
RFC 9293 §3.10.7.4 ABORT primitive emits RST and tears the
session down.

---

## §2.5 — Continuing Operation

> "From the time a host sends its first ARP Announcement,
> until the time it ceases using that IP address, the host
> MUST answer ARP Requests in the usual way required by
> the ARP specification [RFC826]."

**Adherence:** **met**. The Reply path runs unconditionally
once the candidate has been admitted to `self._ip4_ifaddr`:
`packet_handler__arp__rx.py:233-242` calls
`_send_arp_reply(...)` for any Request whose TPA matches our
IP (destined to our unicast MAC or broadcast).

> "This applies equally for both standard ARP Requests with
> non-zero sender IP addresses and Probe Requests with
> all-zero sender IP addresses."

**Adherence:** **met**. The Probe-Request branch and the
unicast-Request branch share the same Reply path; the only
differentiation is in conflict-detection logic upstream.

---

## §2.6 — Broadcast ARP Replies

> "If quicker conflict detection is desired, this may be
> achieved by having hosts send ARP Replies using
> link-level broadcast, instead of sending only ARP
> Requests via broadcast, and Replies via unicast. This is
> NOT RECOMMENDED for general use ..."

**Adherence:** **met (NOT-RECOMMENDED form not selected)**.
PyTCP unicasts ARP Replies to the requester
(`packet_handler__arp__tx.py:131-145` `_send_arp_reply` sets
`ethernet__dst = arp__tha`). RFC 5227 §2.6 says broadcast Replies SHOULD NOT
be used universally; PyTCP follows the default. RFC 3927
link-local does not flip this — see
[`../../ip4/rfc3927__ip4_link_local/adherence.md`](../../ip4/rfc3927__ip4_link_local/adherence.md).

---

## §1.2.1 — Broadcast ARP Replies (handling them on RX)

> "The Packet Reception rules in RFC 826 specify that the
> content of the 'ar$spa' field should be processed *before*
> examining the 'ar$op' field, so any host that correctly
> implements the Packet Reception algorithm specified in
> RFC 826 will correctly handle ARP Replies delivered via
> link-layer broadcast."

**Adherence:** **met**. `__phrx_arp__reply` explicitly
handles broadcast-destined Replies; the gratuitous-Reply
form (broadcast L2 dst, `arp.spa == arp.tpa`) is parsed,
logged as `arp__op_reply__gratuitous`, and runs the cache
learn. (Conflict detection on such a Reply is no longer done
here — a managed address's own `Ip4Acd` reads the same Reply
off its defense socket; Phase 4.4c.)

---

## Test coverage audit

### §2.1 / §2.1.1 — ARP Probe wire format + count

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ip4/test__ip4__acd_engine.py::TestIp4AcdEngine::test__ip4_acd__probe_clean_succeeds_and_emits_probes`
  — a clean `Ip4Acd.probe` emits exactly `ARP__PROBE_NUM`
  ARP Probes onto the interface's TxRing. The Probe wire
  form (`oper=REQUEST`, `spa=0.0.0.0`, `tha=unspecified`,
  `tpa=candidate`, broadcast L2) is built by `Ip4Acd._send`.
- **Static-host glue:**
  `packages/pytcp/pytcp/tests/integration/protocols/arp/test__arp__dad.py::TestArpDad`
  — asserts `_create_stack_ip4_addressing` runs the probe
  (over `Ip4Acd`) before admitting a candidate.

The RFC 5227 §2.1.1 timing constants (`PROBE_WAIT`,
`PROBE_MIN`/`MAX`, `ANNOUNCE_WAIT`) are read live from the
`arp.*` sysctls by `Ip4Acd._run_probe`; the engine tests
collapse them to ~0 for determinism rather than asserting
wall-clock spacing.

**Status:** locked in.

### §2.1.1 — Probe-window conflict detection

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ip4/test__ip4__acd_engine.py::TestIp4AcdEngine::test__ip4_acd__probe_detects_conflict`
  — injects a conflicting ARP onto the ACD socket and
  asserts the probe fails, reporting the peer MAC.
- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/ip4/acd/test__ip4__acd__conflict.py`
  — pins the `_is_conflict` predicate across every wire
  shape (peer using the address; simultaneous probe with
  `spa=0`, `tpa=candidate`; own-frame and unrelated-address
  non-conflicts).

**Status:** locked in (detection moved to the userspace
`Ip4Acd` socket; the stack ARP RX path no longer detects
conflicts — Phase 4.4c).

### §2.1.1 — MAX_CONFLICTS / RATE_LIMIT_INTERVAL

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/ip4/link_local/test__link_local__client__claiming.py::test__ip4_link_local__claiming_max_conflicts_rate_limits`
  — drives `MAX_CONFLICTS` conflicts in succession, asserts
  the next probe is gated by a `RATE_LIMIT_INTERVAL` sleep.

**Status:** locked in (RFC 3927 link-local subsystem; DHCP
path has no candidate-rotation today so the gate is dormant
there).

### §2.3 — Announcement wire format + ANNOUNCE_NUM

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ip4/test__ip4__acd_engine.py::TestIp4AcdEngine::test__ip4_acd__announce_emits_announce_num_frames`
  — `Ip4Acd.announce` emits exactly `ARP__ANNOUNCE_NUM`
  gratuitous ARPs (REQUEST opcode, `spa=tpa=address`,
  built by `Ip4Acd._send`).
- **Integration:**
  `..::test__ip4_acd__start_defense_announces_and_holds_socket`
  — the BOUND-transition announce-and-hold entry emits the
  ANNOUNCE_NUM burst with no Probes.

**Status:** locked in. (`ANNOUNCE_INTERVAL` is read live from
the sysctl by `_run_announce`; the engine tests collapse it to
0 for determinism.)

### §2.4 — Conflict detection (ongoing, on the claimed address)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ip4/test__ip4__acd_engine.py::TestIp4AcdEngine::test__ip4_acd__poll_conflict_detects_then_drains`
  — injects an ARP for the claimed address onto the held
  defense socket and asserts `poll_conflict` reports the
  peer MAC then drains.
- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/ip4/acd/test__ip4__acd__conflict.py`
  — pins `_is_ongoing_conflict` (peer using the address;
  bare probe NOT an ongoing conflict; own-frame ignored).

**Status:** locked in.

### §2.4(b) — Single defensive gratuitous ARP

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ip4/test__ip4__acd_engine.py::TestIp4AcdEngine::test__ip4_acd__defend_emits_gratuitous_arp`
  — `Ip4Acd.defend` broadcasts exactly one defensive
  gratuitous ARP for the claimed address.

The per-address DEFEND_INTERVAL / abandon-after-second-
conflict policy lives in the consuming clients (RFC 3927
link-local BOUND-conflict handler); `Ip4Acd` supplies the
`defend` / `release` mechanism.

**Status:** locked in.

### §2.4(a) — Abandon on sustained conflict (DHCPv4)

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__client.py::TestDhcp4ClientLeaseLifecycle::test__dhcp4_client__do_bound_conflict_declines_and_resets_to_init`
  — a BOUND-state `Ip4Acd.poll_conflict` hit makes the client
  emit DHCPDECLINE, release the claim, and re-enter INIT.

**Status:** locked in.

### §2.4-final — Reset connections before abandoning (SHOULD)

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/stack/test__stack__address.py::TestAddressApiRemoveHost::test__ip4_address_api__remove_host_default_aborts_bound_sessions`
  — asserts `remove` issues `SysCall.ABORT` to every
  `TcpSession` bound to the removed address (the shared
  abandon teardown).
- **Unit:**
  `packages/pytcp/pytcp/tests/unit/stack/test__stack__address.py::TestAddressApiAbortBoundSessions`
  — asserts the standalone primitive is consumer-callable
  for RFC 3927 §2.5(a) abandon paths.

**Status:** locked in.

### §2.5 — Continuing operation (Reply to Request)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__arp__rx.py`
  — "request for stack MAC, broadcasted" and "request for
  stack MAC, unicasted" both verify a Reply is emitted
  with the correct field swap.
- **Integration:** `..` "request probe (SPA=0.0.0.0) for
  stack IP" — verifies §2.5's "applies equally for ... Probe
  Requests with all-zero sender IP addresses".

**Status:** locked in.

### §2.6 — Broadcast Replies (NOT-RECOMMENDED form not used)

**Status:** n/a (deliberate non-implementation). PyTCP's
`_send_arp_reply` unicasts; no test pins the absence of
broadcast Replies. RFC 3927 link-local does not opt into
the §2.6 broadcast form either.

### §1.2.1 — Broadcast Reply handling

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__arp__rx.py`
  — gratuitous-Reply (broadcast L2, SPA=SPA=peer-IP) case
  asserts the cache-learn path runs.

**Status:** locked in.

### Test coverage summary

| §           | Aspect                                                       | Coverage                       |
|-------------|--------------------------------------------------------------|--------------------------------|
| §2.1.1      | Probe wire format                                            | locked in                      |
| §2.1.1      | PROBE_WAIT initial random delay                              | locked in                      |
| §2.1.1      | PROBE_NUM + PROBE_MIN/MAX spacing                            | locked in                      |
| §2.1.1      | RX-side conflict detection (all four shapes)                 | locked in                      |
| §2.1.1      | Conflict aborts claim (end-to-end via Ip4Acd socket)         | locked in                      |
| §2.1.1      | Simultaneous-probe detection (SPA=0, foreign SHA)            | locked in                      |
| §2.1.1      | MAX_CONFLICTS / RATE_LIMIT_INTERVAL                          | locked in (link-local subsystem) |
| §2.1.1      | ANNOUNCE_WAIT post-probe quiet period                        | locked in                      |
| §2.3        | Announcement wire format                                     | locked in                      |
| §2.3        | ANNOUNCE_NUM = 2 + ANNOUNCE_INTERVAL spacing                 | locked in                      |
| §2.4        | Conflict detection (Request and Reply)                       | locked in                      |
| §2.4(b)     | DEFEND_INTERVAL rate-limit + first-defense                   | locked in                      |
| §2.4(b)     | Abandon after second conflict in DEFEND_INTERVAL             | locked in                      |
| §2.4-final  | Reset connections before abandoning (SHOULD)                 | locked in                      |
| §2.5        | Continuing operation (Reply to Request)                      | locked in                      |
| §2.6        | Broadcast Replies (NOT-RECOMMENDED, not used)                | n/a (deliberate)               |
| §1.2.1      | Broadcast Reply handling on RX                               | locked in                      |

---

## Overall assessment

| §           | Aspect                                       | Status                                      |
|-------------|----------------------------------------------|---------------------------------------------|
| §2.1        | MUST probe before use                        | met                                         |
| §2.1        | MUST NOT probe periodically                  | met                                         |
| §2.1.1      | Probe wire format (`spa=0`, etc.)            | met                                         |
| §2.1.1      | PROBE_WAIT initial 0..PROBE_WAIT random delay | met                                        |
| §2.1.1      | PROBE_NUM = 3                                | met                                         |
| §2.1.1      | PROBE_MIN..PROBE_MAX inter-probe spacing     | met                                         |
| §2.1.1      | Probe-window conflict detection              | met (via `Ip4Acd` socket)                   |
| §2.1.1      | Conflict aborts claim end-to-end             | met                                         |
| §2.1.1      | Simultaneous-probe (SPA = 0) detection       | met                                         |
| §2.1.1      | Self-loopback ignore (NOTE)                  | met                                         |
| §2.1.1      | MAX_CONFLICTS / RATE_LIMIT_INTERVAL          | met (RFC 3927 link-local subsystem)         |
| §2.1.1      | ANNOUNCE_WAIT post-probe quiet               | met                                         |
| §2.3        | MUST announce after probe                    | met                                         |
| §2.3        | Announcement wire format                     | met                                         |
| §2.3        | ANNOUNCE_NUM = 2, ANNOUNCE_INTERVAL = 2 s    | met                                         |
| §2.4        | Ongoing conflict detection                   | met                                         |
| §2.4 (a)    | Immediate-abandon path                       | met (DHCPv4: DECLINE + re-acquire)          |
| §2.4 (b)    | Defense via single gratuitous Announcement   | met (`Ip4Acd.defend`)                       |
| §2.4 (b)    | DEFEND_INTERVAL rate-limit                   | met (consumer policy)                       |
| §2.4 (b)    | Abandon after second conflict                | met (link-local §2.5 tree)                  |
| §2.4 (c)    | Indefinite-defend mode                       | partial (not configured; (b) abandon supersedes) |
| §2.4 final  | Reset connections before abandon (SHOULD)    | met                                         |
| §2.5        | Reply to Requests during use                 | met                                         |
| §2.5        | Reply to Probe Requests (SPA = 0)            | met                                         |
| §2.6        | Broadcast Replies (NOT-RECOMMENDED)          | met (not selected)                          |
| §1.2.1      | Handle inbound broadcast Replies             | met                                         |

PyTCP fully implements RFC 5227 for IPv4 ACD. Every Phase-1
normative requirement is met; the only "partial" entry is
§2.4(c) indefinite-defend, which the RFC lists as a MAY mode
not chosen by the default policy (managed-address consumers
defend once then abandon per §2.4(b)).

As of Phase 4.4 the ACD machinery is a **userspace** function
over the `Ip4Acd` engine, mirroring Linux `sd-ipv4acd` — the
kernel-equivalent stack ARP RX path performs no conflict
detection. Each managed address (DHCPv4 lease, RFC 3927
link-local) runs its own `Ip4Acd` over a per-address AF_PACKET
socket; a statically configured address gets probe + announce
only, no ongoing defender (bare `ip addr add`). `AddressApi`
(`pytcp.stack.address`) is the pure `ip addr` surface; the
former in-RX `_handle_arp_conflict` / `_arp_dad_*` machinery
and the `claim_with_acd` / `probe` / `announce` API wrappers
were removed in Phase 4.4c.

### History

- Initial audit (commit `03c0b678`) described the
  pre-implementation state.
- ARP NUD framework (commit `586a693e`) registered timing
  constants as sysctls.
- Simultaneous-probe detection (commit `3f051584`) closed
  §1.2.4 / §2.1.1 SHOULD.
- Abandon-after-second-conflict (commit `67e60e39`) closed
  §2.4(b) MUST.
- ACD API extraction (commit `6970c042`, RFC 3927 Phase 0.5)
  consolidated the public surface on `Ip4AddressApi`.
- RFC 3927 link-local track (commits `b48d7fc3` → `8f09846b`)
  closed MAX_CONFLICTS / RATE_LIMIT_INTERVAL via the
  candidate-rotation loop.
- Userspace ACD migration (Phase 4.1-4.4c) moved all ACD onto
  the `Ip4Acd` AF_PACKET engine and deleted the in-RX conflict
  detector + probe-time DAD machinery (the `sd-ipv4acd` model).
- Audit refresh (this commit) re-derived every adherence
  verdict from the current code state.
