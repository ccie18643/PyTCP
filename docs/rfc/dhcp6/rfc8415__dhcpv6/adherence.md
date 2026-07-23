# RFC 8415 — Dynamic Host Configuration Protocol for IPv6 (DHCPv6)

| Field       | Value                                                     |
|-------------|-----------------------------------------------------------|
| RFC number  | 8415                                                      |
| Title       | Dynamic Host Configuration Protocol for IPv6 (DHCPv6)     |
| Category    | Standards Track                                           |
| Date        | November 2018                                             |
| Obsoletes   | RFC 3315, RFC 3633, RFC 3736, RFC 4242, RFC 7083, RFC 7283, RFC 7550 |
| Source text | [`rfc8415.txt`](rfc8415.txt)                              |

This document records, paragraph by paragraph, how the current PyTCP
codebase relates to each normative statement in RFC 8415 that is in
scope for a **host DHCPv6 client**. The audit was performed by reading
the RFC text fresh and inspecting the codebase under
`packages/pytcp/pytcp/` and `packages/net_proto/net_proto/` directly; no
prior memory or rule-file content was reused. Adherence levels are
described in plain language.

**Scope.** PyTCP is a host stack. The DHCPv6 implementation is a client
only — the `Dhcp6Client` at
`packages/pytcp/pytcp/protocols/dhcp6/dhcp6__client.py`, a `Subsystem`
started by `stack.start()` and triggered by a Router Advertisement with
the Managed (M) and/or Other-config (O) flag set. The following RFC 8415
roles and mechanisms are **out of scope** and their normative sections
are omitted wholesale rather than listed as "not met":

- Server behaviour (§18.3), relay-agent behaviour (§19, §20), the
  Relay-forward / Relay-reply messages (§16.13–§16.14, §9). The relay
  agent is a Phase-2 router follow-up — see "Phase-2 follow-ups" below.
- Prefix delegation — IA_PD / IA Prefix (§6.3, §18.2.x prefix arms,
  §21.21–§21.22). PyTCP is a host, not a requesting router; IA_PD is a
  Phase-2 router follow-up — see "Phase-2 follow-ups" below.
- Temporary addresses — IA_TA (§21.5). PyTCP requests only IA_NA.
- The Confirm message and its receipt (§18.2.3, §16.5), the Reconfigure
  message and Reconfigure Accept / Reconfigure Key (§18.2.11, §16.11,
  §21.19–§21.20), and authentication (§20, the Auth option §21.11).

Also omitted, per the audit methodology, are non-normative sections:
the Abstract, §1 Introduction, §2 Terminology, §3–§5 narrative, §22
Security Considerations boilerplate, §23 IANA, and the References /
Authors sections.

The wire codec for every option and message PyTCP uses lives under
`packages/net_proto/net_proto/protocols/dhcp6/` and has its own
exhaustive unit suite; this record cites those tests in the coverage
audit and treats the parse/assemble correctness as established there.

---

## §7.6. Transmission and Retransmission Parameters

> "Table 1 [...] SOL_TIMEOUT 1 sec, SOL_MAX_RT 3600 secs,
> REQ_TIMEOUT 1 sec, REQ_MAX_RT 30 secs, REQ_MAX_RC 10,
> REN_TIMEOUT 10 secs, REN_MAX_RT 600 secs, REB_TIMEOUT 10 secs,
> REB_MAX_RT 600 secs, INF_TIMEOUT 1 sec, INF_MAX_RT 3600 secs,
> INF_MAX_DELAY 1 sec, REL_TIMEOUT 1 sec, REL_MAX_RC 5,
> DEC_TIMEOUT 1 sec, DEC_MAX_RC 5, [...]"

**Adherence:** met. Every parameter the client uses is registered as a
`pytcp.stack.sysctl` policy knob with the Table 1 default at
`packages/pytcp/pytcp/protocols/dhcp6/dhcp6__constants.py` — INF/SOL/REQ
(milliseconds) plus the REN/REB/REL/DEC timers and the T1/T2 derivation
factors. Cross-knob finalize validators enforce IRT ≤ MRT for each
backoff pair. SOL_MAX_DELAY is modelled (`dhcp6.sol_max_delay_ms`, see
§18.2.1); the SOL_MAX_RT-from-the-wire override (§21.24) is not.

---

## §11.1. DUID Contents / §11.4. DUID Based on Link-Layer Address (DUID-LL)

> "Each DHCP client and server has a DUID. DHCP servers use DUIDs to
> identify clients [...] Clients and servers MUST treat DUIDs as opaque
> values [...] A DUID consists of a 2-octet type code [...]"

**Adherence:** met. The client identifies itself with a single stable
host DUID minted by `get_client_duid(mac)` at
`packages/pytcp/pytcp/protocols/dhcp6/dhcp6__uid.py`, a thin wrapper over
the shared `dhcp4__uid` DUID generator (one host DUID governs both DHCP
families; the `dhcp.duid` sysctl selects the form). It is carried as an
opaque byte string in the Client Identifier option
(`_client_id_option`, `dhcp6__client.py:322`) and never interpreted.

---

## §15. Reliability of Client-Initiated Message Exchanges

> "RT for the first message transmission is based on IRT:
> RT = IRT + RAND*IRT. RT for each subsequent message transmission is
> based on the previous value of RT: RT = 2*RTprev + RAND*RTprev. [...]
> if (RT > MRT) RT = MRT + RAND*MRT. [...] RAND [is] a random number
> chosen with a uniform distribution between -0.1 and +0.1."

**Adherence:** met. `_run_exchange` (`dhcp6__client.py:927`) implements
the algorithm verbatim: first `rt = irt + rand*irt`, thereafter
`rt = 2*rt + rand*rt` capped to `mrt + rand*mrt`, with `rand` drawn from
`random.uniform(-0.1, +0.1)` (`DHCP6__RAND_FACTOR`). The "different
sequence per invocation, need not be cryptographically sound" guidance
is satisfied by `random` (non-CSPRNG).

> "MRC specifies an upper bound on the number of times a client may
> retransmit [...] MRD specifies an upper bound on the length of time
> [...] If both MRC and MRD are non-zero, the message exchange fails
> whenever either [...] is met."

**Adherence:** met. `_run_exchange` accepts a `max_attempts` (MRC) bound
and an `mrd_deadline` (MRD, a `time.monotonic` deadline) and terminates
on whichever is reached first; the per-attempt recv window is clamped so
a retransmit never overshoots the MRD deadline. SOLICIT / REQUEST /
INFORMATION-REQUEST use the count bound; RENEW / REBIND use the duration
bound (time to T2 / valid-lifetime expiry).

> "The client MUST update an 'elapsed-time' value within an Elapsed Time
> option in the retransmitted message."

**Adherence:** met. Each exchange captures a `time.monotonic` start
timestamp before its first transmission; every `_send` closure
recomputes the Elapsed Time via `_elapsed_centisecs(start)`
(`dhcp6__client.py`) — the hundredths-of-a-second delta since that
start, clamped to the 16-bit field maximum (0xFFFF) per §21.9 — and
passes it to the message builder. The first message of an exchange
therefore carries 0 and each retransmission carries the (non-decreasing)
elapsed value. SOLICIT and REQUEST are separate exchanges with
independent start timestamps. RELEASE / DECLINE likewise advance the
Elapsed Time across their retransmissions (each captures its own start
timestamp).

---

## §16.1. Use of Transaction IDs / §16.10. Reply Message

> "Clients [...] discard any received DHCP messages with [...] a
> 'transaction-id' field [...] that does not match [...] Clients MUST
> discard the Reply [if it does not match] the originating message's
> transaction ID."

**Adherence:** met. `_recv_within_window` (`dhcp6__client.py`, called
from `_run_exchange`) drops any inbound frame whose `msg_type` is not the
expected type or whose `xid` does not equal the value the client placed
in the originating message, continuing to wait within the same window
rather than treating a mismatch as the response.

---

## §18.2.1. Creation and Transmission of Solicit Messages

> "The client MUST include a Client Identifier option [...] The client
> includes IA options for any IAs [...] The client MUST include an
> Elapsed Time option [...] The client MUST include an Option Request
> option (ORO) [...]"

**Adherence:** met. `_build_solicit` (`dhcp6__client.py:348`) emits
SOLICIT with a generated 24-bit transaction id, the Client Identifier
(DUID), one IA_NA carrying the client's IAID with T1/T2 = 0 (server's
choice), an Elapsed Time option, and an ORO listing the DNS-server
option. Transmitted to All_DHCP_Relay_Agents_and_Servers (ff02::1:2)
with IRT = SOL_TIMEOUT, MRT = SOL_MAX_RT.

> "The first Solicit message [...] SHOULD be delayed by a random amount
> of time between 0 and SOL_MAX_DELAY."

**Adherence:** met. `_delay_first_solicit` (`dhcp6__client.py`) sleeps a
random interval drawn uniformly from [0, SOL_MAX_DELAY] before the first
SOLICIT (the `dhcp6.sol_max_delay_ms` knob, default 1000 ms per §7.6; a
drawn or configured 0 transmits immediately). The jitter is one-shot —
retransmissions are not delayed.

> "A client that wishes to use the Rapid Commit two-message exchange
> includes a Rapid Commit option [...] The client will discard any Reply
> messages that do not contain the Rapid Commit option. [...] At the end
> of the first RT period, if no suitable Reply messages are received but
> the client has valid Advertise messages, then the client processes the
> Advertise [...]"

**Adherence:** met (opt-in). When `dhcp6.rapid_commit` is enabled (a
client MAY, so off by default) `_build_solicit` adds a Rapid Commit
option to the SOLICIT and `_solicit_for_advertise` widens its first-RT
collection window to also accept a valid REPLY: a REPLY carrying the
Rapid Commit option is returned immediately and `acquire_lease` leases
from it directly (the two-message exchange, no REQUEST), while a REPLY
without the option is discarded; if only ADVERTISEs arrive the client
falls back to the four-message exchange. With the knob off the SOLICIT
omits the option and the collection accepts ADVERTISEs only.

---

## §18.2.2. Creation and Transmission of Request Messages

> "The client MUST include a Server Identifier option [...] to identify
> the server to which the Request is directed. [...] MUST include a
> Client Identifier option [...] MUST include an Elapsed Time option
> [...] MUST include an Option Request option [...]"

**Adherence:** met. `_build_request` (`dhcp6__client.py:369`) addresses
the selected server by echoing its DUID in a Server Identifier option,
and carries the Client Identifier, the IA_NA, an Elapsed Time option, and
the ORO. Transmitted with IRT = REQ_TIMEOUT, MRT = REQ_MAX_RT, MRC =
REQ_MAX_RC (after which the client gives up — it does not loop back to
SOLICIT automatically; the next RA trigger restarts acquisition).

---

## §18.2.4. Creation and Transmission of Renew Messages

> "To extend the valid and preferred lifetimes for the leases [...] the
> client sends a Renew message [...] The client sets the 'msg-type'
> field to RENEW [...] includes a Server Identifier option [...] the
> identifier of the server [...] MUST include a Client Identifier option
> [...] The client includes IA options [...] with the addresses [...]
> the client wants extended. [...] The client transmits the message
> [with] IRT REN_TIMEOUT, MRT REN_MAX_RT, MRC 0, MRD Remaining time
> until T2."

**Adherence:** met. `_build_renew` (`dhcp6__client.py:412`) constructs
RENEW with the granting server's Server Identifier, the Client
Identifier, an IA_NA echoing the held address (built by `_ia_na_for_lease`
at `:392`, which nests the leased address in an IA Address sub-option),
an Elapsed Time option, and the ORO. `_renew` (`:631`) transmits it with
IRT = REN_TIMEOUT, MRT = REN_MAX_RT, no MRC, and an MRD deadline equal to
the T2 instant — exactly the §15 duration bound. On a REPLY the refreshed
lease is adopted; if the MRD deadline passes the worker escalates to
REBIND.

---

## §18.2.5. Creation and Transmission of Rebind Messages

> "The client sets the 'msg-type' field to REBIND [...] does not include
> any Server Identifier option [...] includes a Client Identifier option
> [...] includes IA options [...] The client transmits the message [with]
> IRT REB_TIMEOUT, MRT REB_MAX_RT, MRC 0, MRD Remaining time until valid
> lifetimes [...] expire."

**Adherence:** met. `_build_rebind` (`dhcp6__client.py:434`) is RENEW
without the Server Identifier (so any server may answer), carrying the
Client Identifier, the IA_NA with the held address, Elapsed Time, and the
ORO. `_rebind` (`:669`) transmits with IRT = REB_TIMEOUT, MRT =
REB_MAX_RT, MRD = the valid-lifetime-expiry instant; the responding
server's DUID is taken from the REPLY. If the MRD deadline passes the
worker discards the lease and restarts from SOLICIT.

> "If the time at which [...] T2 [is reached] [...] the client begins a
> Rebind message exchange [...] At time T1 [...] the client begins a
> Renew."

**Adherence:** met. `_service_lease` (`dhcp6__client.py:791`) is the
BOUND timer machine: each worker tick compares `time.monotonic` against
the armed T1 / T2 / valid deadlines and runs RENEW at T1 (bounded by T2),
REBIND at T2 (bounded by valid expiry), and discard-and-re-SOLICIT at
valid expiry. `_effective_timers` (`:754`) derives T1 / T2 when the
server sent 0 (a fraction of the preferred lifetime via the
`dhcp6.t1_factor` / `t2_factor` knobs, default 0.5 / 0.8) and treats
0xFFFFFFFF as infinity.

---

## §18.2.6. Creation and Transmission of Information-request Messages

> "The client sets the 'msg-type' field to INFORMATION-REQUEST. The
> client SHOULD include a Client Identifier option [...] MUST include an
> Option Request option [...] SHOULD include an Elapsed Time option
> [...]"

**Adherence:** met. `_build_information_request` (`dhcp6__client.py:329`)
emits INFORMATION-REQUEST with the Client Identifier, an Elapsed Time
option, and an ORO for the DNS-server option, transmitted with IRT =
INF_TIMEOUT, MRT = INF_MAX_RT. `fetch_other_config` (`:518`) runs the
exchange and returns the DNS recursive name-server list (RFC 3646) on a
REPLY. PyTCP bounds the otherwise-unbounded (MRC = MRD = 0) retransmission
with a `dhcp6.retrans_max_attempts` recv budget so a missing server does
not pin the worker forever.

---

## §18.2.7. Creation and Transmission of Release Messages

> "To release one or more leases, a client sends a Release message [...]
> The client sets the 'msg-type' field to RELEASE [...] MUST include a
> Server Identifier option [...] MUST include a Client Identifier option
> [...] include[s] the IA options [...] for the leases it is releasing
> [...] IRT REL_TIMEOUT, MRC REL_MAX_RC."

**Adherence:** met. `_build_release` / `_build_teardown`
(`dhcp6__client.py`) build a RELEASE with the Server Identifier, Client
Identifier, and the IA_NA carrying the released address. `release` (via
`_teardown_exchange`, called from the `_stop` shutdown hook) retransmits
it up to REL_MAX_RC times at REL_TIMEOUT spacing and stops on the
server's REPLY — so the common case is a single send + a quick
acknowledgement. The §15 MRT is pinned to REL_TIMEOUT (flat spacing
rather than unbounded doubling) so the silent-server worst case is
bounded to roughly REL_MAX_RC × REL_TIMEOUT and a graceful shutdown is
never wedged; the REPLY is advisory and its content is discarded. The
client also stops using the address (removes it via the Address API).

---

## §18.2.8. Creation and Transmission of Decline Messages

> "If a client detects that one or more addresses assigned to it [...]
> are already in use [...] the client sends a Decline message [...] sets
> the 'msg-type' field to DECLINE [...] MUST include a Server Identifier
> option [...] MUST include a Client Identifier option [...] include[s]
> [...] IA options [...] containing the addresses [...] that it is
> declining [...] IRT DEC_TIMEOUT, MRC DEC_MAX_RC."

**Adherence:** met (message contents) / partial (retransmission). The
leased address is vetted by Duplicate Address Detection: `_assign_lease`
installs it through `AddressApi.add(..., dad_conflict_callback=...)`,
which claims it via the ND DAD engine
(`PacketHandler._claim_ip6_address_async`, the `on_conflict` arm). On a
DAD collision the engine calls `notify_dad_conflict`
(`dhcp6__client.py:206`); the worker's `_handle_dad_conflict` (`:270`)
then DECLINEs the address, removes it, and restarts the exchange for a
fresh one. `_build_decline` (`:484`) carries the Server Identifier,
Client Identifier, and the IA_NA with the declined address. Like RELEASE,
`decline` (via `_teardown_exchange`) retransmits up to DEC_MAX_RC times at
DEC_TIMEOUT spacing and stops on the server's REPLY (MRT pinned to
DEC_TIMEOUT to bound the silent-server worst case) before the conflict
handler re-solicits.

---

## §18.2.9. Receipt of Advertise Messages

> "Those Advertise messages with the highest server preference value
> SHOULD be preferred over all other Advertise messages. [...] A client
> MUST collect valid Advertise messages for the first RT seconds, unless
> it receives a valid Advertise message with a preference value of 255.
> [...] Any valid Advertise that does not include a Preference option is
> considered to have a preference value of 0. [...] The client MUST ignore
> any Advertise message that contains no addresses [...]"

**Adherence:** met (selection + alternate-server) / partial (rest).
`_solicit_for_advertise` (`dhcp6__client.py`) implements the §18.2.1
collection modification: after the SOLICIT it collects every valid
ADVERTISE (matching xid, with a Server Identifier) for the first
retransmission window via `_collect_advertises`, returning early the
instant a preference-255 ADVERTISE arrives, and `_sort_advertises` orders
them highest-Preference first (an absent Preference option counts as 0,
per the net_proto `preference` lookup returning None → 0). `acquire_lease`
then walks that ordered list — `_request_from_server` REQUESTs the head
server, and on no REPLY (REQ_MAX_RC exhausted) or an unusable REPLY it
falls back to the next-best ADVERTISE (§18.2.9 alternate-server /
§18.2.10.1). If no ADVERTISE arrives in the first window it falls back to
the §15 retransmission and acts on the first ADVERTISE received. The
Preference codec is the net_proto `Dhcp6OptionPreference` (§21.8). Still
partial: the SOL_MAX_RT / INF_MAX_RT wire override is not consumed, and
the "ignore no-address Advertise" sub-rule is enforced only as the
REPLY-side IA_NA validation.

---

## §18.2.10 / §18.2.10.1. Receipt of Reply Messages

> "If the Reply was received in response to a Solicit (with Rapid
> Commit), Request, Renew, or Rebind message, the client updates the
> information it has recorded about IAs [...] Calculate T1 and T2 times
> [...] Update lifetimes [...] Discard any leases [...] that have a valid
> lifetime of 0 [...]"

**Adherence:** met (top-level status + IA extraction) / partial (the
rest). `_extract_lease` (`dhcp6__client.py`) first inspects the REPLY's
top-level (message-level) Status Code: an UnspecFail, UseMulticast, or
NotOnLink (`_TOP_LEVEL_REJECT_STATUS`) discards the REPLY outright and
yields no lease, so the client re-solicits later via the RA trigger /
lease-lifecycle timers (UseMulticast is moot — PyTCP only ever multicasts;
NotOnLink restarting discovery and UnspecFail's rate-limited retry both
collapse to "this REPLY grants nothing, retry on the next trigger" given
the client never unicasts and re-solicits on a coarse schedule). Any
other top-level code (or none) proceeds to the IA. It then parses the
IA_NA sub-option block for the IA Address and any nested Status Code,
returning a `Dhcp6Lease` carrying the address, preferred / valid
lifetimes, T1, T2, IAID, and server DUID; the worker arms the timers from
those values (§18.2.4/5 above). A non-Success IA_NA Status Code, a
missing IA_NA, or a missing IA Address all yield no lease. The
single-address model makes the per-lease "leave unchanged / discard
valid-lifetime-0" set algebra trivial; the explicit valid-lifetime-0
discard is not separately modelled.

> "The client MUST perform duplicate address detection [...] on each of
> the received addresses [...] before using the received addresses for
> any traffic. If any of the addresses are found to be in use [...] the
> client sends a Decline message [...] Addresses obtained from an IA_NA
> [...] MUST NOT be used to form an implicit prefix with a length other
> than 128."

**Adherence:** met. DAD-before-use is wired end-to-end (see §18.2.8): the
leased address is claimed through the ND DAD engine and only installed
once DAD passes; a duplicate drives DECLINE. The address is installed as
a /128 host (`_DHCP6__LEASE_PREFIX_LEN = 128`, `dhcp6__client.py:91`) — no
implicit on-link prefix is assumed, matching the MUST.

---

## Test coverage audit

### §7.6 / §15 parameters and finalize validators

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/dhcp6/test__dhcp6__constants.py::TestDhcp6ConstantsDefaults`
  pins every Table 1 default (INF/SOL/REQ/REN/REB/REL/DEC timers,
  T1/T2 factors); `...::TestDhcp6ConstantsFinalize` pins the IRT ≤ MRT
  and t1 ≤ t2 cross-knob checks.

**Status:** locked in.

### §15 retransmission backoff + MRC / MRD bounds

- **Unit:**
  `...::test__dhcp6__client.py::TestDhcp6ClientFetch` and
  `::TestDhcp6ClientAcquireLease::test__dhcp6_client__acquire_lease_silent_server_returns_none`
  assert the count-bounded backoff retransmits to budget on a silent
  server.
- **Unit:**
  `::TestDhcp6ClientRenewRebind::test__dhcp6_client__renew_retransmits_then_succeeds`
  and `::..._renew_gives_up_at_deadline` assert the MRD-bounded backoff
  retransmits and then stops at the deadline.

**Status:** locked in.

### §15 / §21.9 Elapsed Time advances on retransmit

- **Unit:**
  `::TestDhcp6ClientElapsedTime::test__dhcp6_client__elapsed_time_first_message_is_zero`,
  `..._advances_on_retransmit`, and `..._caps_at_uint16_max` drive a
  controllable clock and assert the first message carries 0, a
  retransmission carries the elapsed hundredths-of-a-second, and an
  over-large value clamps to 0xFFFF.

**Status:** locked in.

### §16.1 transaction-id / msg-type validation

- **Unit:**
  `::TestDhcp6ClientFetch` cases driving mismatched-xid and
  wrong-msg-type frames assert they are dropped and the wait continues.

**Status:** locked in.

### §18.2.1 SOLICIT contents

- **Unit:**
  `::TestDhcp6ClientAcquireLease::test__dhcp6_client__acquire_lease_solicit_contents`
  asserts the SOLICIT carries the Client Identifier, an IA_NA, and the
  ORO.

**Status:** locked in.

### §18.2.1 SOL_MAX_DELAY first-SOLICIT jitter

- **Unit:**
  `::TestDhcp6ClientSolicitDelay::test__dhcp6_client__solicit_delay_waits_random_interval`
  and `..._solicit_delay_zero_does_not_wait` assert the first SOLICIT is
  preceded by a [0, SOL_MAX_DELAY] wait (and that a drawn 0 transmits
  immediately).
- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/dhcp6/test__dhcp6__constants.py::TestDhcp6ConstantsDefaults::test__dhcp6_constants__sol_max_delay_ms_default`
  pins the `dhcp6.sol_max_delay_ms` default and validator.

**Status:** locked in.

### §18.2.1 Rapid Commit two-message exchange

- **Unit:**
  `::TestDhcp6ClientRapidCommit::test__dhcp6_client__solicit_omits_rapid_commit_by_default`,
  `..._solicit_includes_rapid_commit_when_enabled`,
  `..._rapid_commit_two_message_lease` (lease without a REQUEST),
  `..._rapid_commit_reply_without_option_discarded`, and
  `..._rapid_commit_disabled_ignores_rapid_reply`.
- **Unit:**
  `test__dhcp6__constants.py::...::test__dhcp6_constants__rapid_commit_default_off`
  and `..._rapid_commit_rejects_out_of_range` pin the knob default /
  validator.
- **Unit (net_proto):**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp6/test__dhcp6__option__rapid_commit.py`
  pins the Rapid Commit option wire codec.

**Status:** locked in.

### §18.2.2 REQUEST addresses the selected server

- **Unit:**
  `::TestDhcp6ClientAcquireLease::test__dhcp6_client__acquire_lease_request_addresses_advertised_server`
  asserts the REQUEST echoes the advertised Server DUID.

**Status:** locked in.

### §18.2.4 / §18.2.5 RENEW / REBIND contents and lifecycle

- **Unit:**
  `::TestDhcp6ClientRenewRebind` asserts RENEW carries the server DUID
  and an IA_NA echoing the leased address, REBIND omits the server DUID,
  and both adopt the refreshed lease.
- **Unit:**
  `::TestDhcp6ClientLifecycle::test__dhcp6_client__lifecycle_renew_at_t1`,
  `..._rebind_at_t2`, `..._idle_before_t1`,
  `..._renew_failure_defers_to_rebind` drive a controllable clock across
  the T1 / T2 deadlines and assert the right message fires and the timers
  re-arm.

**Status:** locked in.

### §18.2.6 INFORMATION-REQUEST (stateless other-config)

- **Unit:**
  `::TestDhcp6ClientFetch` asserts the INFORMATION-REQUEST contents and
  that a REPLY's DNS-server list is returned.

**Status:** locked in.

### §18.2.7 RELEASE on shutdown

- **Unit:**
  `::TestDhcp6ClientRelease` asserts RELEASE contents, that it stops on
  the server's REPLY (one send) and retransmits to the REL_MAX_RC budget
  against a silent server, and that `_stop` releases + removes the
  address.

**Status:** locked in.

### §18.2.8 / §18.2.10.1 DECLINE on DAD failure + DAD-before-use

- **Unit:**
  `::TestDhcp6ClientDecline` asserts DECLINE contents, that it stops on
  the server's REPLY, and that a DAD-conflict notification declines +
  removes + re-solicits (and is ignored for a non-held / no-lease
  address).
- **Unit:**
  `::TestDhcp6ClientLeaseAssignment::test__dhcp6_client__acquire_lease_assigns_address_as_128`
  asserts the leased address is installed as a /128 through the Address
  API with `dad_conflict_callback=notify_dad_conflict`.
- **Unit:**
  `packages/pytcp/pytcp/tests/unit/stack/test__stack__address.py::TestAddressApiIp6::test__address_api__add_ip6_with_dad_callback_delegates_to_dad_claim`
  asserts `add` with a callback delegates to the ND DAD engine as
  `on_conflict` instead of direct-installing.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__dad_conflict_callback.py`
  drives a real DAD collision and asserts `on_conflict` fires with the
  conflicting address (and stays silent on DAD success).

**Status:** locked in end-to-end.

### §18.2.9 ADVERTISE Preference selection

- **Unit:**
  `::TestDhcp6ClientAdvertiseSelection::test__dhcp6_client__advertise_selection_prefers_highest_preference`,
  `..._absent_preference_is_zero`, and `..._preference_255_selected`
  assert the client collects multiple ADVERTISEs and addresses its
  REQUEST to the highest-preference server (absent option = 0; 255
  selected).
- **Unit:**
  `::TestDhcp6ClientAcquireLease::test__dhcp6_client__acquire_lease_advertise_without_server_id`
  pins that an ADVERTISE without a Server Identifier is ignored.
- **Unit:**
  `::TestDhcp6ClientAdvertiseSelection::test__dhcp6_client__advertise_selection_falls_back_to_next_server`
  asserts that when the highest-preference server ignores the REQUEST the
  client REQUESTs the next-best advertised server.
- **Unit (net_proto):**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp6/test__dhcp6__option__preference.py`
  pins the Preference option wire codec.

**Status:** locked in (selection + alternate-server fallback).

### §18.2.10 top-level Reply Status Code handling

- **Unit:**
  `::TestDhcp6ClientAcquireLease::test__dhcp6_client__acquire_lease_top_level_not_on_link_yields_no_lease`,
  `..._top_level_use_multicast_yields_no_lease`, and
  `..._top_level_unspec_fail_yields_no_lease` assert a REPLY carrying a
  top-level NotOnLink / UseMulticast / UnspecFail Status Code yields no
  lease even when it also carries a usable IA_NA address.

**Status:** locked in.

### RA M/O trigger (the §4 entry point)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__ra_dhcp6_trigger.py`
  drives RA frames with the M / O flags and asserts the client `trigger`
  is called with the right managed / other arguments.

**Status:** locked in.

### Test coverage summary

| Aspect                                   | Coverage                                  |
|------------------------------------------|-------------------------------------------|
| §7.6 / §15 parameters + validators       | locked in                                 |
| §15 backoff (MRC + MRD bounds)           | locked in                                 |
| §15 / §21.9 elapsed-time update          | locked in                                 |
| §16.1 transaction-id validation          | locked in                                 |
| §18.2.1 SOLICIT contents                 | locked in                                 |
| §18.2.1 SOL_MAX_DELAY jitter             | locked in                                 |
| §18.2.2 REQUEST contents                 | locked in                                 |
| §18.2.4 / §18.2.5 RENEW / REBIND         | locked in                                 |
| §18.2.6 INFORMATION-REQUEST              | locked in                                 |
| §18.2.7 RELEASE                          | locked in                                 |
| §18.2.8 DECLINE + DAD-before-use         | locked in end-to-end                      |
| §18.2.9 Preference selection             | locked in                                 |
| §18.2.10 top-level status handling       | locked in                                 |
| RA M/O trigger                           | locked in                                 |

---

## Overall assessment

| Aspect                                   | Status                                    |
|------------------------------------------|-------------------------------------------|
| DUID identity (§11)                       | met                                       |
| §15 retransmission algorithm             | met                                       |
| §15 / §21.9 elapsed-time update          | met                                       |
| Transaction-id / msg-type validation     | met                                       |
| SOLICIT / REQUEST (§18.2.1–2)            | met (Rapid Commit opt-in)                 |
| RENEW / REBIND lifecycle (§18.2.4–5)     | met                                       |
| INFORMATION-REQUEST (§18.2.6)            | met                                       |
| RELEASE (§18.2.7)                        | met                                       |
| DECLINE + DAD-before-use (§18.2.8/10.1)  | met                                       |
| ADVERTISE Preference selection (§18.2.9) | met (incl. alternate-server fallback)     |
| Reply top-level status handling (§18.2.10)| met (UnspecFail/UseMulticast/NotOnLink)  |
| Address installed as /128 (§18.2.10.1)   | met                                       |

The client implements the full RFC 8415 host lease lifecycle —
SOLICIT/ADVERTISE/REQUEST/REPLY acquisition (with Preference-based and
alternate-server selection and the optional Rapid Commit two-message
exchange), INFORMATION-REQUEST stateless config, T1 RENEW, T2 REBIND,
valid-lifetime expiry restart, graceful RELEASE on shutdown, and DECLINE
on a DAD-detected duplicate with re-solicitation — all driven by the RA
Managed / Other-config flags and all address mutation routed through the
Address API and the ND DAD engine.

Every in-scope host-client requirement is met. The only liberties taken
are two bounded, documented choices: RELEASE / DECLINE pin their §15 MRT
to the per-message TIMEOUT (flat spacing rather than unbounded doubling)
so a silent server cannot wedge shutdown or delay re-acquisition — they
still retransmit to REL_MAX_RC / DEC_MAX_RC and stop on the server's
REPLY. The only wire signals not consumed are two a host that always
multicasts never needs: the SOL_MAX_RT / INF_MAX_RT override (§21.24 /
§21.25) and the Server Unicast option (§21.12). Rapid Commit is on-by-knob
(default off, a client MAY). The Confirm message, Reconfigure, IA_TA, and
IA_PD are out of scope for a host client and intentionally absent.

---

## Phase-2 follow-ups (the router track)

Two RFC 8415 mechanisms are deliberately out of scope for the host client
above but become relevant once PyTCP grows the Phase-2 router forwarding
plane (multi-interface, IP forwarding, RA generation). Both are **gated on
that plane** — implementing them earlier would ship a component with no
consumer — so they are tracked here, not built. The natural ordering is
forwarding-plane first, then these land on top with real consumers.

- **DHCPv6 relay agent (§19, §20; Relay-forward / Relay-reply
  §16.13–§16.14, §9).** A router on a client-facing link with no local
  server wraps inbound client messages in a Relay-forward and unwraps the
  Relay-reply back toward an upstream server / relay. *Depends on:* the
  downstream/upstream multi-interface forwarding plane the relay sits
  between. *New work:* the net_proto Relay-forward (12) / Relay-reply (13)
  message structure (hop-count, link-address, peer-address — the
  `RELAY_FORW` / `RELAY_REPL` message-type enum members already exist),
  plus the Relay Message (option 9) and Interface-ID (option 18) option
  codecs, and the relay RX/TX path. *No client-code change:* the relay
  forwards verbatim; the server still originates Server Unicast /
  SOL_MAX_RT.

- **Prefix delegation — IA_PD (§6.3; IA_PD option 25, IA Prefix option
  26).** A requesting router acquires a delegated prefix from an upstream
  delegating router and sub-delegates it to its downstream links.
  *Acquisition half:* a moderate extension of `Dhcp6Client` — add an IA_PD
  to the SOLICIT / REQUEST / RENEW / REBIND alongside (or instead of) the
  IA_NA, and extract the delegated prefix — plus the IA_PD / IA Prefix
  option codecs. *Consuming half:* assigning sub-prefixes to interfaces
  and advertising them via generated RAs, which needs the router plane.
  *Reuses:* the BOUND lease lifecycle and the now-faithful (retransmitting)
  RELEASE path apply unchanged to a delegated prefix — and RELEASE-on-
  shutdown gains real value here (the ISP reclaims the prefix promptly
  instead of waiting for valid-lifetime expiry), which is the one place
  the §18.2.7 retransmission earns its keep beyond the host IA_NA case.
