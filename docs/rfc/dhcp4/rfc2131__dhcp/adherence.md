# RFC 2131 — Dynamic Host Configuration Protocol

| Field       | Value                                |
|-------------|--------------------------------------|
| RFC number  | 2131                                 |
| Title       | Dynamic Host Configuration Protocol  |
| Category    | Standards Track                      |
| Date        | March 1997                           |
| Obsoletes   | RFC 1541                             |
| Source text | [`rfc2131.txt`](rfc2131.txt)         |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative statement
in RFC 2131. The audit was performed by reading the RFC
text fresh and inspecting the codebase under `packages/pytcp/pytcp/` and
`packages/net_proto/net_proto/` directly; no prior memory or rule-file content
was reused. Adherence levels are described in plain
language. Sections that contain no normative content
(§1 Introduction, §1.1–§1.3, §1.6 Design goals, §2.1–§2.2
narrative, §3.1/§3.2 narrative, §3.6 multi-interface
narrative, §3.7 narrative, §4.2 administrative narrative,
§5 Acknowledgments, §6 References, §7 Security
boilerplate, §8 Author's Address) are omitted.

PyTCP's DHCPv4 implementation has shipped through Phases
0-8.x into a full RFC 2131 §4.4 client. The class
`Dhcp4Client` at
`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py` subclasses
`Subsystem` and runs as a long-lived background thread
under `stack.start()` / `stack.stop()`. The FSM models
INIT / SELECTING / REQUESTING / BOUND / RENEWING /
REBINDING / INIT-REBOOT / REBOOTING explicitly via a
`Dhcp4State`-dispatched `_subsystem_loop`. The client
carries:

- RFC 4361 §6.1 DUID/IAID Client Identifier (Phase 3).
- RFC 1542 §3.2 `secs` advance (Phase 1).
- RFC 2131 §4.1 randomised exponential backoff (Phase 1).
- RFC 2131 §3.1 step 5 DHCPDECLINE on ARP conflict
  (Phase 2.2) via the injected `Ip4Acd` engine running the
  RFC 5227 §2.1.1 Probe loop (`acd.probe`).
- RFC 2131 §4.4.1 [1, 10]-second startup desync delay
  (Phase 2.1).
- RFC 2131 §4.4.1 multi-OFFER collection window
  (Phase 8.x).
- RFC 2131 §4.4.5 T1 / T2 / lease-expiry deadlines
  (Phase 4 commit C), with RFC 2132 §9.7/§9.8 server-
  supplied option 58 (T1) / option 59 (T2) overrides
  honoured (Phase 8.x).
- RFC 2131 §3.2 / §4.4.2 INIT-REBOOT cached-lease
  fast-path (Phase 5).
- RFC 4436 §4 DNAv4 link-change probe / fast-path
  (Phase 6).
- RFC 2131 §4.4.6 DHCPRELEASE on graceful shutdown
  (Phase 4 commit D).
- RFC 2132 §9.10 Maximum DHCP Message Size option 57
  (Phase 8.1), option 51 lease-time hint in DISCOVER
  (Phase 8.2), option 52 Option Overload parser-side
  merge (Phase 8.4).

A two-step `sync` API (`fetch()` / `release(lease)` /
`renew(lease)` / `rebind(lease)`) exposes the same
primitives for tests and operator CLI tools.

A separate kernel/userspace boundary surface at
`packages/pytcp/pytcp/stack/address.py` (`AddressApi`) mediates
every address mutation; the lifecycle never writes
`_ip4_ifaddr` directly. The Phase 4.5 FSM → API mutation
table is wired end-to-end (see the table in the Overall
assessment section).

The wire-format library at `packages/net_proto/net_proto/protocols/dhcp4/`
is comprehensive — full BOOTP-shape header, 15+ option
codecs (including the Phase-8 polish set: max_msg_size,
lease_time_hint, option_overload, renewal_time,
rebinding_time), integrity-validated parser — and every
paragraph about message format is met.

Remaining items against the per-RFC adherence catalogue:

- **§3.4 / §4.4.3 DHCPINFORM** — niche, no PyTCP
  consumer for DNS/NTP/etc. configuration today.
  Tracked in `docs/refactor/ip4_audit_punchlist.md` as
  the DHCPv4 Phase 9 backlog item.

RFC 3396 long-option concatenation and the RFC 3442
Classless Static Route consumer both shipped: the
`_concatenated_classless_static_route_data` helper at
`packages/net_proto/net_proto/protocols/dhcp4/options/dhcp4__options.py:330-401`
gathers the RFC 3396 concatenation of every Classless
Static Route fragment before decoding, and the client's
`_install_lease_routes`
(`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:435`)
installs the resulting routes through the shipped Route
API (`RouteApi` at `packages/pytcp/pytcp/stack/route.py:96`,
via `add_route` / `replace_default`). The former
Phase-7 multi-default-gateway / route-table integration
is therefore no longer blocked.

---

## §1.4 Requirements

> "DHCP must coexist with statically configured,
>  non-participating hosts and with existing network
>  protocol implementations."

**Adherence:** met. The DHCP client is opt-in: it is
constructed from `stack.init` only when the L2 packet
handler's `ip4_dhcp` flag is true and no static address
is configured. `_create_stack_ip4_addressing` at
`packages/pytcp/pytcp/runtime/packet_handler/__init__.py:1830-1880`
handles statically configured candidates; the DHCPv4 path
is owned by `stack.dhcp4_client` (a `Subsystem` that
`stack.start()` brings up after the packet handler and
joins on `start_and_wait_for_bind`). Static IPv4 hosts
pass through DHCP entirely.

> "A DHCP client must be prepared to receive multiple
>  responses to a request for configuration parameters."

**Adherence:** met (Phase 8.x — Linux-alike). After the
first valid OFFER, `_discover_request_once` invokes
`_collect_additional_offers` which polls for additional
OFFERs for `dhcp.offer_collection_ms` (default 3000 ms,
matching dhcpcd's `OFFER_TIMEOUT` ballpark). The
selection policy is "first received within the window" —
the same lease that a 0-ms window would pick, but with
every competing OFFER logged for operator visibility.
Setting `dhcp.offer_collection_ms = 0` reverts to the
strict-RFC "e.g. the first DHCPOFFER message" path.

---

## §2 Protocol Summary — message format

> "Figure 1 gives the format of a DHCP message ...
>  fields op, htype, hlen, hops, xid, secs, flags,
>  ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file,
>  options."

**Adherence:** met. The header dataclass at
`packages/net_proto/net_proto/protocols/dhcp4/dhcp4__header.py:136-168`
defines every field at the wire offsets in Figure 1.
Wire layout is `! BBBB L HH L L L L 16s 64s 128s 4s`
(`dhcp4__header.py:129`), totalling 240 bytes
(`DHCP4__HEADER__LEN = 240`).

> "The first four octets of the 'options' field of the
>  DHCP message contain the (decimal) values 99, 130, 83
>  and 99, respectively (this is the same magic cookie
>  as is defined in RFC 1497)."

**Adherence:** met. The constant at
`dhcp4__header.py:130` is
`DHCP4__HEADER__MAGIC_COOKIE = b"\x63\x82\x53\x63"`
(99, 130, 83, 99) and is packed as the final field of
the header struct
(`dhcp4__header.py:254`). The parser
asserts the cookie on every inbound frame
(`dhcp4__header.py:292-294`).

> "One particular option — the 'DHCP message type'
>  option — must be included in every DHCP message."

**Adherence:** met by the client. Both DISCOVER and
REQUEST emit `Dhcp4OptionMessageType(...)` as the first
option (`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:140`, `:194`). RX
validation does not enforce its presence — a malformed
inbound without Message Type would parse and surface
`message_type = None`; the client checks for the
expected type at
`dhcp4_client.py:167-172` and `:222-227`.

> "The 'client identifier' chosen by a DHCP client MUST
>  be unique to that client within the subnet to which
>  the client is attached. If the client uses a 'client
>  identifier' in one message, it MUST use that same
>  identifier in all subsequent messages."

**Adherence:** met (Phase 0 + Phase 3). The client
emits `Dhcp4OptionClientId(self._expected_client_id)`
in DISCOVER, REQUEST, and DECLINE. As of Phase 3 the
CID wire form is the RFC 4361 §6.1 layout —
type=0xff + 4-byte IAID + DUID — built via
'packages/pytcp/pytcp/protocols/dhcp4/dhcp4__uid.build_client_id'. The MAC-derived
DUID-LL is the default; operator override via the
'dhcp.duid' sysctl takes precedence on every
emission. See `rfc4361__node_specific_client_id` for
the full RFC 4361 adherence record. The CID is also
the value validated against the server's echo per
RFC 6842 §3 (see `rfc6842__client_id_echo`).

> "The 'options' field is now variable length. A DHCP
>  client must be prepared to receive DHCP messages with
>  an 'options' field of at least length 312 octets.
>  This requirement implies that a DHCP client must be
>  prepared to receive a message of up to 576 octets."

**Adherence:** met. The integrity check at
`dhcp4__parser.py:69-72` accepts any
frame ≥ 240 bytes (header). The options-parsing loop at
`packages/net_proto/net_proto/protocols/dhcp4/options/dhcp4__options.py`
walks until END or end-of-frame. The 576-byte minimum is
satisfied trivially.

> "DHCP clients may negotiate the use of larger DHCP
>  messages through the 'maximum DHCP message size'
>  option."

**Adherence:** met (Phase 8.1). PyTCP emits a Maximum
DHCP Message Size option (57) in every outbound DHCP
message — DISCOVER, SELECTING REQUEST, RENEW REQUEST,
REBIND REQUEST, and the INIT-REBOOT REQUEST. The value
is sourced from the `dhcp.max_msg_size` sysctl
(default 1500 = standard Ethernet MTU; floor 576 per
RFC 2132 §9.10). The wire codec is at
`packages/net_proto/net_proto/protocols/dhcp4/options/dhcp4__option__max_msg_size.py`.

> "The leftmost bit is defined as the BROADCAST (B)
>  flag. ... The remaining bits of the flags field are
>  reserved for future use. They MUST be set to zero by
>  clients and ignored by servers and relay agents."

**Adherence:** met. The header packs `flag_b << 15` into
the flags word (`dhcp4__header.py:246`),
leaving every other bit cleared. On RX, only the top bit
is decoded back into a bool
(`dhcp4__header.py:301`).

---

## §3 Client-Server Protocol — packet shape

> "DHCP uses the BOOTP message format defined in RFC
>  951 ... The 'op' field of each DHCP message sent from
>  a client to a server contains BOOTREQUEST. BOOTREPLY
>  is used in the 'op' field of each DHCP message sent
>  from a server to a client."

**Adherence:** met. The enum at
`packages/net_proto/net_proto/protocols/dhcp4/dhcp4__enums.py` defines
`Dhcp4Operation.REQUEST = 0x01` and
`Dhcp4Operation.REPLY = 0x02`. Every outbound TX —
`_send_discover` (`dhcp4_client.py:1004`),
`_send_request` (`:1031`), `_send_decline` (`:1067`),
`_send_request_renew` (`:570`), and `_send_release`
(`:609`) — builds the message with
`dhcp4__operation=Dhcp4Operation.REQUEST`.

The parser does not validate that inbound frames carry
REPLY specifically (the FSM-level `message_type` filter
inside `_recv_within_window` catches that downstream), but
as of the RFC-alignment pass it does reject any
`operation` value outside `{REQUEST=1, REPLY=2}` at parser
sanity — `Dhcp4SanityError` covers unknown opcodes via the
`Dhcp4Operation.is_unknown` check
(`packages/net_proto/net_proto/protocols/dhcp4/dhcp4__parser.py::_validate_sanity`).
The header's `from_buffer` was switched from the strict
`Dhcp4Operation(value)` constructor to the tolerant
`Dhcp4Operation.from_int(value)` form so that unknown wire
opcodes materialise as `UNKNOWN_n` and are caught at the
sanity layer rather than leaking a raw `ValueError`.

---

## §3.1 Client-server interaction — allocating a network address

> "1. The client broadcasts a DHCPDISCOVER message on
>  its local physical subnet. The DHCPDISCOVER message
>  MAY include options that suggest values for the
>  network address and lease duration."

**Adherence:** met for the broadcast; lease-time hint
included. `_send_discover` at
`dhcp4_client.py:1752-1788` builds the DISCOVER with a
Param Request List (option 55) requesting
CLASSLESS_STATIC_ROUTE, SUBNET_MASK, and ROUTER, plus a
Host Name option and — as a MAY — an 'IP address lease
time' (option 51) hint sourced from the
`dhcp.requested_lease_time` sysctl (default 86400 s =
1 day; set 0 to omit). It does NOT include 'requested IP
address' (option 50), which is also a MAY clause, so this
is compliant. The DISCOVER is sent via the BSD-socket-style
`connect(("255.255.255.255", 67))` inside
`_do_init_to_bound`.

> "3. The client receives one or more DHCPOFFER messages
>  ... The client chooses one server from which to
>  request configuration parameters ... The client
>  broadcasts a DHCPREQUEST message that MUST include
>  the 'server identifier' option to indicate which
>  server it has selected, and that MAY include other
>  options specifying desired configuration values. The
>  'requested IP address' option MUST be set to the
>  value of 'yiaddr' in the DHCPOFFER message from the
>  server."

**Adherence:** met (the MUSTs). `_send_request` at
`dhcp4_client.py:1031-1065` includes
`Dhcp4OptionServerId(srv_id)` (option 54) sourced from
the DHCPOFFER's `srv_id` property and
`Dhcp4OptionReqIpAddr(yiaddr)` (option 50) sourced from
the DHCPOFFER's `yiaddr` header field. The client
validates that the OFFER contained a Server ID before
proceeding (`dhcp4_client.py:805-811`).

The "broadcasts" requirement is met by the socket
configuration: the client binds to `0.0.0.0:68` and
sends to `255.255.255.255:67`
(`dhcp4_client.py:751-752`).

> "... the DHCPREQUEST message MUST use the same value
>  in the DHCP message header's 'secs' field and be sent
>  to the same IP broadcast address as the original
>  DHCPDISCOVER message."

**Adherence:** met. As of Phase 1, every outbound TX
populates `secs` via `_elapsed_secs()` (`dhcp4_client.py:1118-1129`),
which returns the seconds elapsed since
`self._fetch_started_at_monotonic` (anchored at the top
of `_do_init_to_bound`). DISCOVER and the initial REQUEST
emitted in the same acquisition cycle share the same
anchor, so within-second resolution they carry equal
`secs`. After retransmissions the value advances per
RFC 1542 §3.2, which the RFC permits (§4.4.1 records
local time "for later use in computing lease
expiration", not as an invariant frozen across all
messages of one acquisition). The destination address
is identical (broadcast) because the same
`connect(("255.255.255.255", 67))` socket is reused for
both sends.

> "The client times out and retransmits the
>  DHCPDISCOVER message if the client receives no
>  DHCPOFFER messages."

**Adherence:** met (Phase 1). The DISCOVER recv wait
runs under `_recv_with_backoff` (`dhcp4_client.py:876-925`)
with the caller-supplied `resend` closure re-emitting the
DISCOVER on each window timeout. Defaults follow RFC 2131
§4.1 exactly — initial 4 s, doubled to 64 s, 5 attempts,
±1 s jitter (see §4.1 below for the full breakdown).

> "5. The client receives the DHCPACK message ... The
>  client SHOULD perform a final check on the
>  parameters (e.g., ARP for allocated network address)
>  ... If the client detects that the address is already
>  in use (e.g., through the use of ARP), the client
>  MUST send a DHCPDECLINE message to the server and
>  restarts the configuration process."

**Adherence:** met (Phase 2.2). `Dhcp4Client.__init__`
accepts an injected `acd: Ip4Acd | None` engine (the
userspace RFC 5227 ACD conflict-detector over the
AF_PACKET socket). After a valid ACK the acquisition path
runs `acd.probe(address=ip4_host.address)` against the
offered 'yiaddr' (`dhcp4_client.py:1485`). On a conflict
(`AcdResult.success` False), the client emits a DHCPDECLINE
carrying Server Identifier (option 54) + Requested IP
Address (option 50) + Client Identifier echo (RFC 6842) +
ciaddr=0, waits `dhcp.decline_backoff_ms` (default 10000 ms
per the SHOULD floor) on an interruptible stop-event, and
returns the `_NAK_RESTART` sentinel — the outer NAK-restart
loop already provides the bounded retry budget. On success
the lease is returned; the daemon-mode BOUND transition
then begins ongoing RFC 5227 §2.3/§2.4 defense of the
committed address via `acd.start_defense`.

> "The client SHOULD wait a minimum of ten seconds
>  before restarting the configuration process to avoid
>  excessive network traffic in case of looping."

**Adherence:** met (Phase 2.2). After emitting a
DHCPDECLINE the client sleeps
`dhcp.decline_backoff_ms / 1000.0` seconds before
returning the `_NAK_RESTART` sentinel; the default
10 000 ms matches the SHOULD floor exactly. Setting the
sysctl to 0 disables the wait for deterministic tests.

> "If the client receives a DHCPNAK message, the client
>  restarts the configuration process."

**Adherence:** met (bounded). `_recv_within_window`
detects `Dhcp4MessageType.NAK` (with `allow_nak=True`
passed by the ACK leg) and returns the internal
`_NAK_RESTART` sentinel; `_do_init_to_bound` re-enters
`_discover_request_once` up to `DHCP4__NAK_MAX_RESTARTS`
times (default 3, total 4 attempts) before returning
None. The NAK itself is gated on the same xid + CID-echo
validation as ACK
(`dhcp4_client.py:972-980`) so a stray NAK for an
unrelated transaction cannot stampede the client into a
restart loop.

> "The client times out and retransmits the DHCPREQUEST
>  message if the client receives neither a DHCPACK or a
>  DHCPNAK message. ... a client retransmitting as
>  described in section 4.1 might retransmit the
>  DHCPREQUEST message four times, for a total delay of
>  60 seconds, before restarting the initialization
>  procedure."

**Adherence:** met (Phase 1). The REQUEST recv wait at
`dhcp4_client.py:815-821` runs under the same
`_recv_with_backoff` machinery as DISCOVER, with the
`resend` closure re-emitting `_send_request(...)` on each
window timeout. The same RFC 2131 §4.1 backoff defaults
apply.

> "6. The client may choose to relinquish its lease on a
>  network address by sending a DHCPRELEASE message to
>  the server."

**Adherence:** met (Phase 4 commit D). The
'Dhcp4Client._stop()' Subsystem post-stop hook emits a
unicast DHCPRELEASE for the held lease before joining
the thread, then removes the address via
'address_api.remove_ifaddr(..., abort_bound_sessions=...)'.
'stack.stop()' calls 'dhcp4_client.stop()' first in the
teardown order so the RELEASE flies on still-live
sockets before the TX ring shuts down. The new public
sync 'release(lease)' method provides the same primitive
for operator CLI tools (Linux 'dhclient -r' / 'dhcpcd -k'
equivalent).

---

## §3.2 Client-server interaction — reusing a previously allocated network address

> "If a client remembers and wishes to reuse a
>  previously allocated network address, a client may
>  choose to omit some of the steps described in the
>  previous section."

**Adherence:** met (Phase 5). When the
`dhcp.lease_cache_path` sysctl is set to a non-empty
filesystem path, `Dhcp4Client._on_bound` serialises
the active lease to JSON (atomic write via
`tempfile.mkstemp` + `os.replace`) at
`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__lease_cache.py:88-122`.
The constructor at
`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:160-243` reads
the cache; if a still-valid lease is present (wall-
clock age < lease_time), the FSM starts in INIT-REBOOT
instead of INIT — skipping DISCOVER/OFFER and going
straight to a server-confirming REQUEST. The cache is
purged on every NAK / lease-expiry path so a
subsequently-invalidated lease does not feed a
broken-boot loop. Default `dhcp.lease_cache_path = ""`
means out-of-the-box PyTCP does not touch disk; the
operator opts in.

---

## §3.3 Interpretation and representation of time values

> "Throughout the protocol, times are to be represented
>  in units of seconds. The time value of 0xffffffff is
>  reserved to represent 'infinity'."

**Adherence:** met by wire format. The Lease Time
option at
`packages/net_proto/net_proto/protocols/dhcp4/options/dhcp4__option__lease_time.py`
stores `lease_time: int` as `uint32`. The PyTCP client
surfaces the value through `Dhcp4Lease.lease_time__sec`
(`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py` `_discover_request_once`)
alongside `acquired_at_monotonic = time.monotonic()` so
the Phase-4 lifecycle thread can schedule T1/T2 against
absolute monotonic deadlines. The Phase-0 client now
strictly rejects an ACK that omits Lease Time (MUST per
RFC 2131 Table 3), but does not yet interpret the
0xFFFFFFFF infinity sentinel — that becomes meaningful
in Phase 4 once renewal timers exist.

---

## §3.4 Obtaining parameters with externally configured network address

> "If a client has obtained a network address through
>  some other means (e.g., manual configuration), it
>  may use a DHCPINFORM request message to obtain other
>  local configuration parameters."

**Adherence:** not implemented. `Dhcp4MessageType.INFORM
= 0x08` is declared in `dhcp4__enums.py` but the client
never emits an INFORM. Statically-configured PyTCP hosts
get no DHCP-supplied parameters.

---

## §3.5 Client parameters in DHCP

> "If the client includes a list of parameters in a
>  DHCPDISCOVER message, it MUST include that list in
>  any subsequent DHCPREQUEST messages."

**Adherence:** met. DISCOVER (`dhcp4_client.py:1763-1768`),
the SELECTING REQUEST (`_send_request:1811-1816`), and the
RENEW/REBIND REQUEST (`_send_request_renew:1201-1206`) all
include the same
`Dhcp4OptionParamReqList([CLASSLESS_STATIC_ROUTE, SUBNET_MASK, ROUTER])`.

> "The client SHOULD include the 'maximum DHCP message
>  size' option to let the server know how large the
>  server may make its DHCP messages."

**Adherence:** met (Phase 8.1). See §2 above for the
Maximum DHCP Message Size emission entry — included in
every outbound DHCP message. Codec:
`packages/net_proto/net_proto/protocols/dhcp4/options/dhcp4__option__max_msg_size.py`.

> "The 'requested IP address' option is to be filled in
>  only in a DHCPREQUEST message when the client is
>  verifying network parameters obtained previously."

**Adherence:** partial deviation. The client fills the
'requested IP address' option in the SELECTING-state
REQUEST (`dhcp4_client.py:1059`), which is also where
Table 4 of §4.3.6 says "MUST". The "verifying previously"
wording in §3.5 conflates SELECTING with INIT-REBOOT;
§4.3.6 is the authoritative table. PyTCP matches the
§4.3.6 SELECTING row. The RENEW/REBIND REQUEST in
`_send_request_renew` does NOT include the option, which
also matches Table 4's "MUST NOT" for those rows.

> "The client fills in the 'ciaddr' field only when
>  correctly configured with an IP address in BOUND,
>  RENEWING or REBINDING state."

**Adherence:** met. `ciaddr` is set to 0 in DISCOVER
(`dhcp4_client.py:1004-1029`), the SELECTING-state
REQUEST (`:1031-1065`), and DECLINE (`:1067-1099`) by
omission — the assembler default of `Ip4Address()` =
0.0.0.0 applies. It is explicitly set to the current IP
in the RENEW/REBIND REQUEST
(`_send_request_renew`, `:591` — `dhcp4__ciaddr=ciaddr`)
and in RELEASE (`_send_release`, `:627` —
`dhcp4__ciaddr=lease.ip4_host.address`). The RFC's "only
when correctly configured ... in BOUND, RENEWING or
REBINDING state" rule is honoured: SELECTING /
REQUESTING / DECLINE emit ciaddr=0, BOUND-derived
RENEW / REBIND / RELEASE emit ciaddr=leased IP.

---

## §4.1 Constructing and sending DHCP messages — wire format

> "The options area includes first a four-octet 'magic
>  cookie' (which was described in section 3), followed
>  by the options. The last option must always be the
>  'end' option."

**Adherence:** met. Every TX path ends its option list
with `Dhcp4OptionEnd()` —
`_send_discover:1025`, `_send_request:1061`,
`_send_decline:1095`, `_send_request_renew:603`,
`_send_release:633`. The header packs the magic cookie
as the final fixed field
(`packages/net_proto/net_proto/protocols/dhcp4/dhcp4__header.py`).

> "DHCP uses UDP as its transport protocol. DHCP
>  messages from a client to a server are sent to the
>  'DHCP server' port (67), and DHCP messages from a
>  server to a client are sent to the 'DHCP client'
>  port (68)."

**Adherence:** met. Every TX socket binds to local port
68 and connects to remote port 67 — INIT
(`dhcp4_client.py:751-752`), RENEW/REBIND
(`:433-435`), RELEASE (`:655-656`).

> "DHCP clients MUST use the IP address provided in the
>  'server identifier' option for any unicast requests
>  to the DHCP server."

**Adherence:** met (Phase 4 commit C). The
RENEWING-state path opens a fresh socket and connects to
`(str(lease.server_id), 67)` (`dhcp4_client.py:434`),
where `lease.server_id` comes from the ACK's
`srv_id` option captured at lease-acquisition time. The
RELEASE path likewise unicasts to `lease.server_id`
(`:656`). REBINDING continues to broadcast per Table 4.

> "DHCP messages broadcast by a client prior to that
>  client obtaining its IP address must have the source
>  address field in the IP header set to 0."

**Adherence:** met. Every DHCPv4 client socket binds to
`("0.0.0.0", 68)`; the UDP layer's `_get_ip_addresses`
(`packages/pytcp/pytcp/runtime/socket/udp__socket.py:148-195`) deliberately
skips `pick_local_ip_address` for the DHCP-client
(sport=68/dport=67) connect path so the local address
stays unspecified for the whole FSM lifecycle. Outbound
broadcast DISCOVER / REQUEST / DECLINE / REBIND all
therefore carry IP source 0.0.0.0; RENEW unicast and
RELEASE unicast also keep source 0.0.0.0 (the RFC's
"prior to obtaining" clause is about broadcast; once
unicast is in use the source can be the leased IP per
RFC 2131 §4.4.5, but PyTCP's current implementation
keeps it 0.0.0.0 — the leasing server identifies the
client by `chaddr` and ciaddr, which suffices).

> "DHCP clients are responsible for all message
>  retransmission. The client MUST adopt a
>  retransmission strategy that incorporates a
>  randomized exponential backoff algorithm to determine
>  the delay between retransmissions. ... in a 10Mb/sec
>  Ethernet internetwork, the delay before the first
>  retransmission SHOULD be 4 seconds randomized by the
>  value of a uniform random number chosen from the
>  range -1 to +1. ... The retransmission delay SHOULD
>  be doubled with subsequent retransmissions up to a
>  maximum of 64 seconds."

**Adherence:** met (Phase 1). `_recv_with_backoff` in
`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py` runs the canonical RFC 2131
§4.1 backoff: initial delay 4 s, doubled on each timeout
(8 / 16 / 32 / 64 s), capped at 64 s, jittered uniform
±1 s, up to 5 total recv attempts (~124 s worst-case
budget). On each window timeout the caller-supplied
`resend` closure retransmits the prior TX (DISCOVER or
REQUEST) and the delay advances. Bogus inbound packets
(malformed, mismatched xid / CID echo, wrong type) are
silently dropped without burning the current attempt's
window — `_recv_within_window` keeps listening until
the monotonic deadline expires.

Every retransmit also carries an advancing `secs` field
populated by `_elapsed_secs` per RFC 1542 §3.2; see
§4.4.1 below.

The four delay parameters are operator-tunable via the
'dhcp.retrans_initial_ms' / `_max_ms` /
`_max_attempts` / `_jitter_ms` sysctls registered in
`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__constants.py`. Setting
`retrans_jitter_ms` to 0 disables jitter — useful for
deterministic test pinning. A finalize-validator
rejects `initial_ms > max_ms` so a misconfigured pair
cannot silently degrade to a no-doubling backoff.

> "The 'xid' field is used by the client to match
>  incoming DHCP messages with pending requests. A DHCP
>  client MUST choose 'xid's in such a way as to
>  minimize the chance of using an 'xid' identical to
>  one used by another client."

**Adherence:** met. The client generates `xid` once per
`_discover_request_once()` via
`random.randint(0, 0xFFFFFFFF)`. The full 32-bit range
is used; each NAK-driven restart draws a fresh xid so a
stale OFFER from a previous attempt cannot match the
restarted DISCOVER. xid uniqueness across PyTCP
processes is sourced from CPython's default `random`
seed.

The client validates inbound xid against the outbound:
the shared `_recv_within_window` (`dhcp4_client.py:1582`)
drops any frame whose xid does not match the value the
client emitted (`:1660`), on both the OFFER and the ACK
leg. A stray DHCP reply for an unrelated transaction is
silently discarded (continue) rather than being honoured.

> "A client that cannot receive unicast IP datagrams
>  until its protocol software has been configured with
>  an IP address SHOULD set the BROADCAST bit in the
>  'flags' field to 1 in any DHCPDISCOVER or DHCPREQUEST
>  messages that client sends."

**Adherence:** met. DISCOVER (`dhcp4_client.py:1013`),
SELECTING REQUEST (`:1047`), DECLINE (`:1088`), and the
REBINDING REQUEST (`:590`, `broadcast=True`) all set
`dhcp4__flag_b=True`. The RENEWING REQUEST
(`:590`, `broadcast=False`) and RELEASE (`:626`,
`dhcp4__flag_b=False`) clear it — the leasing server is
expected to unicast back to the client's known IP at
those points. PyTCP's UDP path can in fact receive
unicast before the address is bound (the socket is bound
to `("0.0.0.0", 68)` which matches any destination), so
the SHOULD-clear branch would also be valid for the
pre-lease phase; PyTCP takes the conservative SHOULD-set
path there.

---

## §4.3 DHCP server behavior

**Adherence:** out of scope. PyTCP is a host stack with
a DHCP client only; the server-behaviour normative
text in §4.3 has no audit surface.

---

## §4.3.6 Client messages — Table 4 cross-reference

| State       | Mode      | server-id | requested-ip | ciaddr     | PyTCP                                |
|-------------|-----------|-----------|--------------|------------|--------------------------------------|
| INIT-REBOOT | broadcast | MUST NOT  | MUST         | zero       | met (Phase 5 — `:608-768`)           |
| SELECTING   | broadcast | MUST      | MUST         | zero       | met (`dhcp4_client.py:1031-1065`)    |
| RENEWING    | unicast   | MUST NOT  | MUST NOT     | IP address | met (Phase 4 commit C — `:570-607`)  |
| REBINDING   | broadcast | MUST NOT  | MUST NOT     | IP address | met (Phase 4 commit C — `:570-607`)  |

`_send_request_renew` carries `ciaddr=current IP`, omits
Server Identifier (option 54), omits Requested IP Address
(option 50), and toggles `flag_b` per the
RENEWING / REBINDING distinction. The four shapes line
up with Table 4 exactly modulo the missing INIT-REBOOT
row (Phase 5).

---

## §4.4 DHCP client behavior — state machine

> "Figure 5 gives a state-transition diagram for a DHCP
>  client. A client can receive the following messages
>  from a server: DHCPOFFER, DHCPACK, DHCPNAK."

**Adherence:** met (Phase 4 commit C + Phase 5
INIT-REBOOT). The `Dhcp4State` enum at
`dhcp4_client.py:86-101` declares all eight Figure-5
states. The `_subsystem_loop` dispatch at `:231-267`
maps them to handlers:

| Figure-5 state | PyTCP handler                                              |
|----------------|------------------------------------------------------------|
| INIT           | `_do_init_to_bound`                                        |
| SELECTING      | implicit inside `_discover_request_once`                   |
| REQUESTING     | implicit inside `_discover_request_once`                   |
| BOUND          | `_do_bound`                                                |
| RENEWING       | `_do_renewing`                                             |
| REBINDING      | `_do_rebinding`                                            |
| INIT-REBOOT    | `_do_init_reboot` (Phase 5)                                |
| REBOOTING      | implicit inside `_do_init_reboot` (synchronous wire leg)   |

SELECTING / REQUESTING / REBOOTING are not first-class
FSM states in PyTCP because each corresponds to a single
synchronous wire exchange inside its parent handler
(`_discover_request_once` for SELECTING/REQUESTING;
`_do_init_reboot` for REBOOTING). NAK is handled by an
explicit restart loop in `_do_init_to_bound` (see §3.1
step 4 above), bounded by `DHCP4__NAK_MAX_RESTARTS`.

---

## §4.4.1 Initialization and allocation of network address

> "The client begins in INIT state and forms a
>  DHCPDISCOVER message. The client SHOULD wait a random
>  time between one and ten seconds to desynchronize the
>  use of DHCP at startup."

**Adherence:** met (Phase 2.1). 'fetch()' calls
'_initial_delay()' before opening the socket; the helper
draws a delay from
`random.uniform(min_ms / 1000.0, max_ms / 1000.0)` and
sleeps for it, with `min_ms` / `max_ms` sourced live
from the 'dhcp.init_delay_min_ms' (default 1000) and
'dhcp.init_delay_max_ms' (default 10000) sysctls in
`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__constants.py`. Defaults
match the RFC's [1, 10]-second SHOULD range exactly.
Setting both bounds to 0 disables the delay — the
canonical configuration for unit tests, short-lived
container hosts, and other scenarios where startup
desynchronisation is unnecessary. A cross-knob finalize
validator rejects `min_ms > max_ms`.

> "The client generates and records a random transaction
>  identifier and inserts that identifier into the 'xid'
>  field."

**Adherence:** met. A fresh xid is drawn at the top of
each `_discover_request_once()` round-trip.

> "The client records its own local time for later use
>  in computing the lease expiration."

**Adherence:** met (Phase 0 + Phase 1). 'fetch()' stores
`self._fetch_started_at_monotonic = time.monotonic()`
at the top of every acquisition cycle for the `secs`
field computation (RFC 1542 §3.2; see §4.1 backoff
above and the `_elapsed_secs` helper), and the returned
`Dhcp4Lease` carries an `acquired_at_monotonic` field
the Phase-4 lifecycle thread will use to schedule
T1/T2/lease-expiry deadlines.

> "The client then broadcasts the DHCPDISCOVER on the
>  local hardware broadcast address to the 0xffffffff
>  IP broadcast address and 'DHCP server' UDP port."

**Adherence:** met (`dhcp4_client.py:751-752`,
`_send_discover:1004-1029`).

> "If the 'xid' of an arriving DHCPOFFER message does
>  not match the 'xid' of the most recent DHCPDISCOVER
>  message, the DHCPOFFER message must be silently
>  discarded."

**Adherence:** met. `_recv_within_window` validates
`packet.xid == xid` against the locally generated xid and
drops the frame (silent discard) on mismatch. The same
guard covers both the OFFER and the REQUEST → ACK leg
(the two legs pass different `expected_type` values into
the one receive helper).

> "The client collects DHCPOFFER messages over a period
>  of time, selects one DHCPOFFER message from the
>  (possibly many) incoming DHCPOFFER messages."

**Adherence:** met (Phase 8.x — Linux-alike). After the
first valid OFFER, `_discover_request_once` calls
`_collect_additional_offers`, which polls for additional
OFFERs for `dhcp.offer_collection_ms` milliseconds
(default 3000 = dhcpcd-alike). The selection policy is
"first received within the window," matching the RFC's
"e.g. the first DHCPOFFER message" example; the window
exists to provide operator-visible logging of competing
offers and as a hook for future preference-based
selection. Setting the sysctl to 0 disables the window
(strictly RFC-compliant accept-first behaviour, useful
for tight-boot and test scenarios).

> "The client SHOULD perform a check on the suggested
>  address to ensure that the address is not already in
>  use. ... If the network address appears to be in use,
>  the client MUST send a DHCPDECLINE message to the
>  server."

**Adherence:** met (Phase 2.2). See §3.1 step 5 above —
'Dhcp4Client' runs `acd.probe(address=...)` on the
injected `Ip4Acd` engine against the offered 'yiaddr'
after a valid ACK. The engine's RFC 5227 §2.1.1 Probe
loop runs over the AF_PACKET socket; on conflict the
client emits DHCPDECLINE, waits `dhcp.decline_backoff_ms`,
and restarts from DISCOVER via the bounded `_NAK_RESTART`
outer loop. The "drop the address, disable IPv4" failure
mode that pre-dated Phase 2.2 is gone.

> "The client SHOULD broadcast an ARP reply to announce
>  the client's new IP address."

**Adherence:** met. After `_do_init_to_bound` returns a
valid lease, the `_on_bound` transition
(`dhcp4_client.py:400-432`) calls
`acd.start_defense(address=lease.ip4_host.address)`
(`:429-430`), which emits the RFC 5227 §2.3 ANNOUNCE_NUM
gratuitous-ARP burst and holds the defense socket. The
trigger is technically RFC 5227, not the DHCP path
directly, but the user-visible behaviour matches the SHOULD.

---

## §4.4.2 Initialization with known network address

> "The client begins in INIT-REBOOT state and sends a
>  DHCPREQUEST message. The client MUST insert its known
>  network address as a 'requested IP address' option in
>  the DHCPREQUEST message. ... The client MUST NOT
>  include a 'server identifier' in the DHCPREQUEST
>  message."

**Adherence:** met (Phase 5). `_send_request_init_reboot`
builds the REQUEST with `ciaddr=0` (assembler default),
`dhcp4__flag_b=True` (BROADCAST set so the server can
reply before the client has bound the cached IP),
`Dhcp4OptionReqIpAddr(cached IP)` (option 50; the MUST),
NO `Dhcp4OptionServerId(...)` (the MUST NOT), and the
Param Request List + Client Identifier + End shared
with every other TX. The FSM driver is `_do_init_reboot`
in `dhcp4__client.py:608-768`.

Phase 6 adds a DNAv4 (RFC 4436) early-exit on top:
before the REQUEST flies, `_dnav4_probe` sends a
unicast ARP Request to the cached `(gateway_ip,
gateway_mac)` pair and waits up to
`dhcp.dnav4_timeout_ms` (default 1000 ms) for the
Reply. A successful probe adopts the cached lease and
transitions to BOUND without any DHCP traffic; on miss
the REQUEST proceeds as described above. See
[`rfc4436__dnav4`](../rfc4436__dnav4/adherence.md) for
the full DNAv4 adherence record.

> "If the client receives a DHCPACK message ... the
>  client SHOULD perform a final check on the parameters
>  ... If the parameters are acceptable, the client
>  transitions to BOUND state ..."

**Adherence:** met (Phase 5). On ACK, `_do_init_reboot`
constructs a refreshed `Dhcp4Lease` from the ACK's
`yiaddr` / `subnet_mask` / `router` / `srv_id` /
`lease_time` and calls `_on_bound(refreshed)` which
installs the address via the address API, writes the
cache, and signals `_event__bound`.

> "If the client receives a DHCPNAK message, it cannot
>  reuse its remembered network address. It must
>  instead request a new address by restarting the
>  configuration process ..."

**Adherence:** met (Phase 5). On NAK,
`_do_init_reboot` calls
`_reset_to_init(remove_lease_host=True)` which (a)
removes the cached address via the address API (where
the lifecycle owns one), (b) deletes the on-disk cache
file via `delete_cached_lease(...)` so the next boot
will not retry INIT-REBOOT on the invalidated address,
and (c) sets `_state = Dhcp4State.INIT`. The next
`_subsystem_loop` iteration runs `_do_init_to_bound`.

> "If the client receives neither a DHCPACK nor a
>  DHCPNAK message after employing the retransmission
>  algorithm, the client MAY choose to use the
>  previously allocated network address and
>  configuration parameters for the remainder of the
>  unexpired lease."

**Adherence:** met (Phase 5 — MAY taken). On a silent
server, `_do_init_reboot` calls `_on_bound(cached)` —
adopting the cached lease as-is. The cache reader
anchors `acquired_at_monotonic` against the wall-clock
age, so T1 / T2 / lease-expiry deadlines line up with
the original acquisition time. Operators who deliberately
set `dhcp.lease_cache_path` have opted into fast-boot
semantics; the silent-server case is the path where the
cache pays off.

---

## §4.4.3 Initialization with an externally assigned network address (DHCPINFORM)

**Adherence:** not implemented. See §3.4 above.

---

## §4.4.4 Use of broadcast and unicast

> "The DHCP client broadcasts DHCPDISCOVER, DHCPREQUEST
>  and DHCPINFORM messages, unless the client knows the
>  address of a DHCP server."

**Adherence:** met for DISCOVER and REQUEST; INFORM
not implemented. PyTCP always broadcasts; it does not
implement the unicast-to-known-server optimization.

> "The client unicasts DHCPRELEASE messages to the
>  server."

**Adherence:** met (Phase 4 commit D). The RELEASE path
in `Dhcp4Client.release` (`dhcp4_client.py:643-663`)
opens a fresh UDP socket, binds `("0.0.0.0", 68)`, and
calls `connect((str(lease.server_id), 67))` — unicast to
the leasing server. `_send_release` (`:609-637`) carries
message-type 7 + Server Identifier + Client Identifier +
ciaddr=current IP, with `flag_b=False`.

> "Because the client is declining the use of the IP
>  address supplied by the server, the client broadcasts
>  DHCPDECLINE messages."

**Adherence:** met (Phase 2.2). `_send_decline` builds
the DECLINE via `Dhcp4Assembler` with `flag_b=True`
(broadcast); the socket layer's
`connect(("255.255.255.255", 67))` routes the UDP
datagram to the broadcast IP at port 67.

---

## §4.4.5 Reacquisition and expiration

> "The client maintains two times, T1 and T2, that
>  specify the times at which the client tries to extend
>  its lease on its network address."

**Adherence:** met (Phase 4 commit C). 'Dhcp4Client'
runs as a 'Subsystem' (Phase 4 commit B); the
'_subsystem_loop' BOUND handler checks the
'_t1_deadline' (= acquired_at + lease_time ×
'dhcp.t1_factor', default 0.5) on each iteration and
transitions to RENEWING when elapsed. The RENEWING
handler then checks the '_t2_deadline' (factor
'dhcp.t2_factor', default 0.875) and escalates to
REBINDING; the REBINDING handler checks the lease-
expiry deadline. Both factors are operator-tunable
via the 'dhcp.t1_factor' / 'dhcp.t2_factor' sysctls
in 'packages/pytcp/pytcp/protocols/dhcp4/dhcp4__constants.py', with
a cross-knob finalize validator enforcing 't1 ≤ t2'.

Server-supplied option 58 (T1) / option 59 (T2)
overrides are honoured as of the Phase 8.x server-T1/T2
commit. Typed codecs at
'packages/net_proto/net_proto/protocols/dhcp4/options/dhcp4__option__renewal_time.py'
and `..__rebinding_time.py' parse the wire-format
values; '_extract_t1_t2_overrides' validates them
against the RFC 2131 §4.4.5 'T1 < T2 < lease_time'
invariant and stamps the surviving values onto the
'Dhcp4Lease'. The deadline computation prefers them
over the factor-based defaults. Cache format v3
persists both across reboots.

> "T1 MUST be earlier than T2, which, in turn, MUST be
>  earlier than the time at which the client's lease
>  will expire."

**Adherence:** met (Phase 4 commit C). The
'_finalize__t1_le_t2' cross-knob validator rejects any
operator override that puts 'dhcp.t1_factor' above
'dhcp.t2_factor'. The lease-expiry deadline is
'acquired_at + lease_time' (= factor 1.0), which is
strictly later than 'acquired_at + lease_time × 0.875'
for any positive lease, so 'T2 < expiry' holds by
construction.

> "If the lease expires before the client receives a
>  DHCPACK, the client moves to INIT state, MUST
>  immediately stop any other network processing and
>  requests network initialization parameters as if the
>  client were uninitialized."

**Adherence:** met (Phase 4 commit C). The
'_do_rebinding' handler checks
'now ≥ _lease_expiry_deadline' on each iteration; on
match, it calls
'_halt_ipv4_and_reset_to_init()' → which removes the
expired Ip4IfAddr via
'address_api.remove_ifaddr(ip4_address=..., abort_bound_sessions=True)'
(actively aborting any TCP sessions bound to the
expired address — RFC 5227 §2.4-final SHOULD; cleaner
than Linux's silent-rot kernel behaviour) and resets
the FSM to INIT. The next '_subsystem_loop' iteration
runs '_do_init_to_bound' to acquire a fresh lease.

> [implementation correctness note] RENEW unicast / REBIND
> broadcast wire-level reception.

**Adherence:** met (post-Phase-4 fix). Earlier in the
Phase-4 work the UDP layer's
`UdpSocket._get_ip_addresses` was latching the owned IP
into the DHCP-client socket once a lease was in place,
and `UdpMetadata.socket_ids` only returned a single
`(0.0.0.0, 68, 255.255.255.255, 67)` ID — so RENEW
unicast replies (server → leased IP) and REBIND
broadcast replies (server → 255.255.255.255 to a host
that owns a different unicast IP) had no listening
socket to match and were silently dropped at UDP RX. The
fix at `packages/pytcp/pytcp/runtime/socket/udp__socket.py:148-195` skips
`pick_local_ip_address` for DHCPv4/v6 client sockets and
keeps their local at 0.0.0.0 / :: across the whole FSM
lifecycle; the fix at
`packages/pytcp/pytcp/runtime/socket/udp__metadata.py:67-93` enumerates both
(sender-unicast) and (limited-broadcast) shapes so RENEW
and REBIND replies both find the listener. Locked in by
`packages/pytcp/pytcp/tests/integration/protocols/dhcp4/test__dhcp4__rx_socket_lookup.py`
(three tests covering INIT/RENEW/REBIND reception via a
real `UdpSocket` driven through
`PacketHandlerL2._phrx_ethernet`).

---

## §4.4.6 DHCPRELEASE

**Adherence:** met (Phase 4 commit D). See §3.1 step 6
above for the shutdown integration. The wire-form
builder '_send_release' carries the canonical RELEASE
shape per the RFC: message-type 7, 'ciaddr' = current
IPv4 address, Server Identifier (option 54) echoing
'lease.server_id', and the Client Identifier — no reply
is expected from the server.

---

## Test coverage audit

### §2 Message format

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__header__asserts.py` (785 lines)
  Pin field-level invariants on every header field
  (under_min / over_max for integer fields; type checks
  for enums and addresses).
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__parser__integrity_checks.py`
  Pin integrity error paths (frame too short; bad magic
  cookie, bad hardware type, bad hardware length — the
  last three raised from `Dhcp4Header.from_buffer` and
  surfaced as `Dhcp4IntegrityError` via the
  `_parse` try/except wrap per `net_proto.md` §7).
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__parser__sanity_checks.py`
  Pin sanity error paths covering every `_validate_sanity`
  branch: unknown `operation` (RFC 951 §8 / RFC 2131 §2);
  `ciaddr` / `yiaddr` / `siaddr` / `giaddr` =
  loopback / multicast / limited-broadcast (RFC 1122
  §3.2.1.3); `chaddr` = multicast / broadcast (RFC 2131
  §2 implicit unicast + IEEE 802.3). Includes a happy-path
  pin that a valid REPLY frame parses cleanly.
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__parser__operation.py` (690 lines)
  Pin parser happy path: full round-trip of a DISCOVER
  / OFFER / REQUEST / ACK frame through Dhcp4Parser
  exposing every header field and option.
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__assembler__operation.py` (441 lines)
  Pin assembler happy path: every field round-trips
  byte-for-byte.

**Status:** locked in (wire-format compliance).

### §3.1 DISCOVER → REQUEST flow

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__client.py`
  Exercises `fetch()` end-to-end with a mocked socket:
  the client emits a DISCOVER with the right options,
  receives a stubbed OFFER, emits a REQUEST with the
  right `server-id`, `requested-ip`, and `client-id`,
  receives a stubbed ACK, and returns a `Dhcp4Lease`.

**Status:** locked in (happy-path lease).

### §2 / §4.4.1 / §3.1 step 4 — Phase 0 Client Identifier + xid + NAK

- **Unit:** `packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__client.py`
  - `TestDhcp4ClientFetchClientIdInRequest` —
    round-trips the emitted REQUEST through the real
    Dhcp4Parser and asserts `request.client_id` equals
    `b"\x01" + bytes(mac)`. Pins the §2 CID-in-REQUEST
    MUST.
  - `TestDhcp4ClientFetchXidMismatch` — OFFER and ACK
    each carry an xid different from the locally
    generated value; the client must drop both
    (§4.4.1 silent-discard MUST).
  - `TestDhcp4ClientFetchNakRestart` — a NAK in
    response to REQUEST triggers a fresh DISCOVER on
    the next iteration of the bounded restart loop
    (§3.1 step 4); four NAK rounds exhaust the
    budget and `fetch()` returns None.
  - `TestDhcp4ClientFetchLeaseReturn` and
    `TestDhcp4ClientFetchAckMissingLeaseTime` — pin
    that Lease Time is surfaced via
    `Dhcp4Lease.lease_time__sec` and that an ACK
    without Lease Time is rejected.

**Status:** locked in (Phase 0).

### §3.1 step 5 — DHCPDECLINE on ARP conflict (Phase 2.2)

- **Unit:** `packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__client.py::TestDhcp4ClientFetchArpDad`
  - `test__dhcp4_client__fetch_probes_leased_address_via_acd`
    — the `Ip4Acd` engine's `probe` is called exactly once
    with the offered 'yiaddr' after a valid ACK.
  - `test__dhcp4_client__fetch_without_acd_returns_lease_unverified`
    — backward compatibility: no `acd` engine ⇒ no DAD
    inside the client.
  - `test__dhcp4_client__fetch_probe_conflict_emits_decline_message`
    — DECLINE TX carries message-type 4, Server Identifier,
    Requested IP Address, Client Identifier echo, and
    ciaddr=0.
  - `test__dhcp4_client__fetch_probe_false_then_true_restarts_and_returns_lease`
    — DECLINE-then-restart succeeds on the retry; 5 TXs
    total (D, R, DECL, D, R).
  - `test__dhcp4_client__fetch_probe_always_false_exhausts_restart_budget`
    — bounded by 'dhcp.nak_max_restarts'; 4 rounds × 3 TXs
    = 12 emissions, fetch returns None.
  - `test__dhcp4_client__fetch_decline_path_honours_decline_backoff_sleep`
    — post-DECLINE wait uses decline_backoff_ms/1000.0.
- **Unit:** `packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__constants.py`
  — 'dhcp.decline_backoff_ms' default 10000 ms, accepts
  0, rejects negatives.
- **Integration:** existing `test__arp__dad.py` suite
  re-validates the underlying RFC 5227 §2.1.1 probe loop
  via the `Ip4Acd` engine.

**Status:** locked in (Phase 2.2).

### §4.4.1 — Initial 1-10 s random delay (Phase 2.1)

- **Unit:** `packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__client.py::TestDhcp4ClientFetchInitialDelay`
  - `initial_delay_uses_default_bounds` — `random.uniform(1.0, 10.0)`
    is the canonical draw at the default sysctl values; the
    drawn value flows to `time.sleep(...)`.
  - `initial_delay_honours_custom_sysctl_bounds` — operator
    overrides on `dhcp.init_delay_{min,max}_ms` propagate
    through to the `random.uniform` bounds (expressed in
    seconds).
  - `initial_delay_disabled_when_max_ms_zero` — the
    fixture-default 0/0 configuration bypasses the sleep
    entirely.
- **Unit:** `packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__constants.py`
  — `dhcp.init_delay_{min,max}_ms` defaults, validators (accept 0,
  reject negatives), live-module read-through, and the
  cross-knob `min ≤ max` finalize validator.

**Status:** locked in (Phase 2.1).

### §4.1 — Retransmission backoff (Phase 1)

- **Unit:** `packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__client.py`
  - `TestDhcp4ClientFetchBackoffSilence` —
    `silent_server_runs_5_attempts` pins 5 recv +
    5 send (1 initial + 4 retransmits) under server
    silence; `silent_server_doubles_timeouts` pins
    the [4, 8, 16, 32, 64]-second doubling sequence
    with jitter disabled.
  - `TestDhcp4ClientFetchBackoffEarlyExit::offer_on_third_attempt_returns_lease`
    — OFFER arriving mid-backoff terminates the loop
    early.
  - `TestDhcp4ClientFetchBackoffBogusPacket::bogus_xid_in_window_does_not_burn_attempt`
    — bogus inbound frame is silently dropped without
    retransmitting; valid OFFER in the same window is
    accepted.
  - `TestDhcp4ClientFetchSecsField` —
    `first_discover_carries_secs_zero` and
    `retransmitted_discover_carries_advancing_secs`
    pin the RFC 1542 §3.2 `secs` field behaviour.
  - `TestDhcp4ClientFetchBackoffJitter::fetch_jitter_draws_from_pm_jitter_ms`
    — pins the ±jitter_ms call shape on
    `random.uniform`.
- **Unit:** `packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__constants.py`
  — defaults, validator rejection cases, and the
  cross-knob `initial_ms ≤ max_ms` finalize validator
  for every retransmission sysctl.

**Status:** locked in (Phase 1).

### §4.4 / §4.4.5 — Client FSM (Phase 4 commit C)

- **Unit:** `packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__client.py::TestDhcp4ClientLeaseLifecycle`
  - `do_bound_transitions_to_renewing_when_t1_elapsed`
    — BOUND → RENEWING fires at T1 (= 0.5 × lease).
  - `do_bound_stays_bound_when_t1_not_elapsed`
    — handler blocks on stop event with the
    remaining-until-T1 timeout.
  - `do_renewing_returns_to_bound_on_ack`
    — unicast REQUEST + ACK → refreshed lease, BOUND.
  - `do_renewing_falls_back_to_init_on_nak`
    — DHCPNAK clears the lease, resets to INIT,
    removes the address via the address API.
  - `do_renewing_escalates_to_rebinding_when_t2_elapsed`
    — RENEWING → REBINDING at T2 (= 0.875 × lease).
  - `do_rebinding_returns_to_bound_on_ack`
    — broadcast REQUEST + ACK → BOUND.
  - `do_rebinding_halts_ipv4_on_lease_expiry`
    — lease-expiry → INIT + 'remove_ifaddr'.
  - `renewing_emits_unicast_request_with_ciaddr`
    — RENEW REQUEST wire shape: ciaddr=current IP, no
    server-id, no requested-ip.
- **Unit:** `packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__constants.py`
  — 'dhcp.t1_factor' / 'dhcp.t2_factor' defaults +
  cross-knob 't1 ≤ t2' finalize validator.

**Status:** locked in (Phase 4 commit C).

### §4.4.5 — RENEW/REBIND wire-level RX (post-Phase-4 fix)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/dhcp4/test__dhcp4__rx_socket_lookup.py::TestDhcp4ClientSocketRxDelivery`
  - `test__dhcp4__rx__init_broadcast_reply_delivered`
    — pre-lease broadcast reply lands at the listening
    socket via the special-case lookup.
  - `test__dhcp4__rx__renew_unicast_reply_delivered`
    — post-lease unicast reply from the leasing server
    finds the RENEWING socket (regression guard for the
    socket-id lookup bug fixed post-Phase-4).
  - `test__dhcp4__rx__rebind_broadcast_reply_delivered`
    — post-lease broadcast reply finds the REBINDING
    socket (regression guard for the
    `pick_local_ip4_address` latching bug fixed
    post-Phase-4).
- **Unit:**
  `packages/pytcp/pytcp/tests/unit/runtime/socket/test__runtime__socket__udp__metadata.py::TestUdpMetadataSocketIdsDhcp::test__udp_metadata__socket_ids_dhcp4`
  — pins the two-entry shape returned by
  `UdpMetadata.socket_ids` for the DHCPv4 client.

**Status:** locked in (post-Phase-4 RX-path fix).

### §3.2 / §4.4.2 — INIT-REBOOT + cached lease (Phase 5)

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__lease_cache.py`
  - `TestDhcp4LeaseCacheRoundTrip` — write-then-read
    round-trips the address / mask / gateway / server-
    id / lease-time fields; gateway=None survives the
    JSON null serialisation.
  - `TestDhcp4LeaseCacheReadFailures` — defensive read
    returns None on missing file, empty path, malformed
    JSON, unknown version, expired lease, missing fields,
    non-object root.
  - `TestDhcp4LeaseCacheWriteSemantics` — empty path is
    a no-op; second write replaces prior content.
  - `TestDhcp4LeaseCacheDelete` — delete removes existing
    file; missing-file and empty-path are silent no-ops.
- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__client.py::TestDhcp4ClientInitReboot`
  - `init_starts_in_init_when_no_cache` — empty cache
    path → INIT, no preloaded lease.
  - `init_starts_in_init_reboot_when_cache_present`
    — valid cached lease → INIT-REBOOT, lease preloaded.
  - `do_init_reboot_emits_request_with_cached_ip` — TX
    wire shape: REQUEST, ciaddr=0, req_ip=cached,
    no server-id, BROADCAST set.
  - `do_init_reboot_transitions_to_bound_on_ack` — ACK
    refreshes lease, FSM → BOUND.
  - `do_init_reboot_falls_back_to_init_on_nak` — NAK
    invalidates cache (delete called), FSM → INIT.
  - `do_init_reboot_adopts_cached_on_timeout` — silent
    server → BOUND with the cached lease (RFC 2131
    §4.4.2 last-paragraph MAY).
  - `on_bound_writes_cache_when_path_set` — every BOUND
    transition writes the cache.
  - `reset_to_init_with_remove_lease_host_deletes_cache`
    — NAK / expiry paths invalidate the cache.

**Status:** locked in (Phase 5).

### §4.4.5 / RFC 2132 §9.7 / §9.8 — Server T1/T2 overrides (Phase 8.x)

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__renewal_time.py`
  (13 tests) — Renewal Time (option 58) codec
  round-trip + integrity checks.
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__rebinding_time.py`
  (13 tests) — Rebinding Time (option 59) codec
  round-trip + integrity checks.
- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__client.py::TestDhcp4ClientServerT1T2Overrides`
  (6 tests) — ACK options populate
  `Dhcp4Lease.t1_override` / `t2_override`; deadlines
  honour the lease overrides; missing options fall back
  to factor defaults; invalid T1 ≥ lease_time is
  dropped; invalid T1 ≥ T2 drops both.
- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__lease_cache.py::TestDhcp4LeaseCacheT1T2Overrides`
  (2 tests) — cache v3 round-trips both overrides;
  null values round-trip cleanly.

**Status:** locked in (Phase 8.x — server T1/T2 overrides).

### §1.4 / §4.4.1 — Multi-OFFER collection window (Phase 8.x)

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__client.py::TestDhcp4ClientMultiOfferCollection`
  - `collection_window_disabled_picks_first_offer` —
    `dhcp.offer_collection_ms = 0` → DISCOVER + REQUEST
    only (strict-RFC behaviour preserved).
  - `collection_window_logs_additional_offers` — a
    second OFFER queued during the window is consumed;
    the first OFFER's `server_id` remains the selection.
  - `collection_window_silence_terminates_loop` — the
    loop exits promptly via the `TimeoutError` path
    when no additional OFFERs arrive.

**Status:** locked in (Phase 8.x — Linux-alike).

### §2 / §3.5 / §9.10 — Polish options (Phase 8)

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__max_msg_size.py`
  (16 tests) — Max DHCP Message Size codec round-trip,
  under-min / over-max integrity checks, wrong-type
  buffer rejection.
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__overload.py`
  (20 tests) — Option Overload codec round-trip for all
  three legal values (1/2/3), `includes_file` /
  `includes_sname` decoders, integrity checks (bad
  length, bad value, wrong type).
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__parser__option_overload.py`
  (4 tests) — parser-side merge of options from BOOTP
  'sname' / 'file' fields for overload=1/2/3, plus the
  negative case that those fields stay inert without
  option 52.
- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__client.py::TestDhcp4ClientPhase8Polish`
  (5 tests) — DISCOVER + SELECTING REQUEST carry
  Max-Msg-Size = 1500; DISCOVER carries Lease-Time
  hint = 86400 by default; sysctl override propagates;
  setting Lease-Time hint to 0 omits the option.

**Status:** locked in (Phase 8.1 / 8.2 / 8.4).

### Test coverage summary

| Aspect                                              | Coverage                                                           |
|-----------------------------------------------------|--------------------------------------------------------------------|
| Wire-format (header, options, magic cookie, sizes)  | locked in (~3 700 lines of unit tests)                             |
| Linear DISCOVER → REQUEST happy path                | locked in (`test__dhcp4__client.py`)                           |
| Client Identifier in REQUEST                        | locked in (Phase 0 — `TestDhcp4ClientFetchClientIdInRequest`)      |
| DHCPNAK handling (bounded restart)                  | locked in (Phase 0 — `TestDhcp4ClientFetchNakRestart`)             |
| ARP conflict → DHCPDECLINE                          | locked in (Phase 2.2 — `TestDhcp4ClientFetchArpDad`)               |
| Post-DECLINE backoff sysctl                         | locked in (Phase 2.2 — `test__dhcp4__constants.py`)                |
| Retransmission backoff (4/8/16/32/64 s + jitter)    | locked in (Phase 1 — `TestDhcp4ClientFetchBackoff*`)               |
| 'secs' field advances per RFC 1542 §3.2             | locked in (Phase 1 — `TestDhcp4ClientFetchSecsField`)              |
| DHCPv4 retransmission sysctls (defaults, validators)| locked in (Phase 1 — `test__dhcp4__constants.py`)                  |
| Initial random delay (RFC 2131 §4.4.1, 1-10 s)      | locked in (Phase 2.1 — `TestDhcp4ClientFetchInitialDelay`)         |
| Initial-delay sysctls (defaults, validators)        | locked in (Phase 2.1 — `test__dhcp4__constants.py`)                |
| FSM states (RENEWING/REBINDING/BOUND)               | locked in (Phase 4 — `TestDhcp4ClientLeaseLifecycle`)              |
| FSM state INIT-REBOOT (cached-lease fast-path)      | locked in (Phase 5 — `TestDhcp4ClientInitReboot`)                  |
| Lease cache (round-trip + defensive reads)          | locked in (Phase 5 — `test__dhcp4__lease_cache.py`, 14 tests)      |
| Max DHCP Message Size option (57)                   | locked in (Phase 8.1 — `test__dhcp4__option__max_msg_size.py`)     |
| Multi-OFFER collection window (Linux-alike)         | locked in (Phase 8.x — `TestDhcp4ClientMultiOfferCollection`)      |
| Server T1/T2 overrides (options 58 / 59)            | locked in (Phase 8.x — codec + FSM + cache v3 tests)               |
| Option Overload (52) parser-side merge              | locked in (Phase 8.4 — `test__dhcp4__parser__option_overload.py`)  |
| Lease-time hint in DISCOVER (option 51)             | locked in (Phase 8.2 — `TestDhcp4ClientPhase8Polish`)              |
| Lease expiry / T1 / T2                              | locked in (Phase 4 — `TestDhcp4ClientLeaseLifecycle`)              |
| DHCPRELEASE on shutdown                             | locked in (Phase 4 commit D — `TestDhcp4ClientReleaseAndShutdown`) |
| Sync release / renew / rebind public surface        | locked in (Phase 4 commit D — `TestDhcp4ClientReleaseAndShutdown`) |
| Cross-IP RENEW/REBIND → replace_ifaddr                | locked in (Phase 4 commit D — `TestDhcp4ClientReleaseAndShutdown`) |
| RENEW/REBIND wire-level RX socket lookup            | locked in (post-Phase-4 fix — `test__dhcp4__rx_socket_lookup.py`)  |
| DHCPINFORM                                          | not tested — gap                                                   |
| xid validation on inbound                           | locked in (Phase 0 — `TestDhcp4ClientFetchXidMismatch`)            |
| Lease Time surfaced on Dhcp4Lease                   | locked in (Phase 0 — `TestDhcp4ClientFetchLeaseReturn`)            |

---

## Overall assessment

| Aspect                                                  | Status                                           |
|---------------------------------------------------------|--------------------------------------------------|
| Wire format (header fields, magic cookie, flags)        | met                                              |
| BROADCAST flag emission                                 | met (set for DISCOVER/SELECT/DECLINE/REBIND)     |
| DHCP message-type option present                        | met (every TX)                                   |
| Client Identifier emission (RFC 4361 DUID/IAID form)    | met (Phase 3 — every TX)                         |
| Server Identifier echo in REQUEST                       | met                                              |
| Requested IP Address in SELECTING-state REQUEST         | met                                              |
| Param Request List forwarded DISCOVER → REQUEST         | met                                              |
| Magic cookie + `end` option                             | met                                              |
| Single DISCOVER → OFFER → REQUEST → ACK linear path     | met                                              |
| Multiple-OFFER collection + selection                   | met (Phase 8.x — Linux-alike; default 3000 ms)   |
| ARP probe on ACK + DHCPDECLINE on conflict              | met (Phase 2.2)                                  |
| Post-DECLINE backoff (≥ 10 s before restart)            | met (Phase 2.2)                                  |
| Retransmission with exponential backoff                 | met (Phase 1)                                    |
| RFC 1542 §3.2 secs field advances across retransmissions| met (Phase 1)                                    |
| Initial random delay (1–10 s)                           | met (Phase 2.1)                                  |
| FSM (BOUND / RENEWING / REBINDING)                      | met (Phase 4 commit C)                           |
| FSM (INIT-REBOOT / REBOOTING) + cached-lease fast-path  | met (Phase 5)                                    |
| T1 / T2 / lease-expiry handling                         | met (Phase 4 commit C)                           |
| Server option 58 (T1) / option 59 (T2) overrides        | met (Phase 8.x — typed codecs + lease + cache v3) |
| RENEW unicast wire path                                 | met (Phase 4 commit C + post-fix RX lookup)      |
| REBIND broadcast wire path                              | met (Phase 4 commit C + post-fix RX lookup)      |
| DHCPRELEASE on shutdown                                 | met (Phase 4 commit D)                           |
| Cross-IP RENEW/REBIND atomic 'replace_ifaddr' swap        | met (Phase 4 commit D)                           |
| Active TCP-abort on lease change (deliberate dev.)      | met (Phase 4 commit D — sysctl-gated; default 1) |
| DHCPNAK handling (bounded restart from DISCOVER)        | met (Phase 0)                                    |
| DHCPINFORM                                              | not implemented                                  |
| xid match validation on inbound messages                | met (Phase 0)                                    |
| Lease Time surfaced + ACK-without-Lease-Time rejected   | met (Phase 0)                                    |
| INIT-REBOOT (cached prior lease)                        | met (Phase 5)                                    |
| Unicast-to-known-server optimisation                    | partial (RENEW unicasts; INFORM/REQUEST do not)  |
| 'Maximum DHCP message size' option (57)                 | met (Phase 8.1; default 1500)                    |
| 'Option overload' option (52)                           | met (Phase 8.4 parser-side merge)                |
| Lease-time hint in DISCOVER (option 51)                 | met (Phase 8.2; default 86400 s)                 |

**Principal compliance status.** With Phase 4 complete
(commits 0/A/B/C/D), PyTCP's DHCPv4 client is
host-parity-complete for RFC 2131. Boot acquisition,
RFC 2131 §4.1 retransmission backoff, RFC 2131 §3.1
step 4 DHCPNAK restart, RFC 2131 §3.1 step 5 DHCPDECLINE
on ARP conflict, RFC 4361 DUID client identifier,
RFC 6842 §3 echo validation, RFC 1542 §3.2 secs field
advance, RFC 2131 §4.4.5 T1/T2 timer-driven RENEWING
and REBINDING, lease-expiry IPv4 halt, and RFC 2131
§4.4.6 DHCPRELEASE on graceful shutdown are all in
place.

The 'Dhcp4Client' runs as a long-running 'Subsystem'
under 'stack.start()' / 'stack.stop()', consuming the
Phase-3-clean 'AddressApi' boundary surface
(`stack.address.add` / `.replace` / `.remove`) for all
address mutations. The Phase 4.5 FSM → API mutation table
is wired end-to-end:

| Transition                                  | Address-API call                                       |
|---------------------------------------------|--------------------------------------------------------|
| `INIT → BOUND` (first lease)                | `add(ifaddr=...)`                                      |
| `BOUND → RENEWING → BOUND` (same IP)        | none — internal lease bookkeeping only                 |
| `BOUND → RENEWING → BOUND` (different IP)   | `replace(old_address=, new_ifaddr=, abort_bound_sessions=)`|
| `RENEW / REBIND NAK → INIT`                 | `remove(address=, abort_bound_sessions=)`              |
| lease expiry without ACK                    | `remove(address=, abort_bound_sessions=)`              |
| `stack.stop()` (graceful)                   | `send_release()` + `remove(address=, ...)`             |

**Deliberate deviation from Linux.** The
'dhcp.abort_sessions_on_lease_change' sysctl (default 1)
gates active TCP-session abort on every address change.
The default is a deliberate deviation from Linux's
silent-rot kernel behaviour — PyTCP follows RFC 5227
§2.4-final's SHOULD ("hosts SHOULD actively attempt to
reset any existing connections using that address").
Operators can opt into Linux-parity behaviour by
setting the sysctl to 0.

**Post-Phase-4 RX-path fix.** A coupled pair of bugs in
the UDP socket layer was silently dropping every RENEW
unicast and REBIND broadcast reply once a lease was in
place; the fixes at
`packages/pytcp/pytcp/runtime/socket/udp__socket.py:148-195` and
`packages/pytcp/pytcp/runtime/socket/udp__metadata.py:67-93` are pinned by the
new integration test
`packages/pytcp/pytcp/tests/integration/protocols/dhcp4/test__dhcp4__rx_socket_lookup.py`.
Verified end-to-end against a live DHCP server — eight
consecutive RENEWs at the 1800 s T1 boundary all
received an ACK and logged `Lease renewed: same IP
retained`.

**Phase 5 — cached-lease INIT-REBOOT fast-path (shipped).**
`Dhcp4Client.__init__` consults
`dhcp.lease_cache_path`; if a valid lease is on disk
(wall-clock age < lease_time) the FSM starts in
INIT-REBOOT. `_do_init_reboot` broadcasts a single
REQUEST asking the server to re-confirm the cached IP
(ciaddr=0, requested-ip=cached, no server-id), then
transitions to BOUND on ACK / falls back to INIT on
NAK / adopts the cached lease on silent-server timeout
per the §4.4.2 last-paragraph MAY. The cache is written
on every BOUND transition (atomic JSON via
`tempfile.mkstemp` + `os.replace`) and invalidated on
every NAK / lease-expiry path. Default
`dhcp.lease_cache_path = ""` means out-of-the-box PyTCP
does not touch disk; operators opt in.

Remaining items in the per-RFC adherence catalogue:

- **§3.4 DHCPINFORM** — niche, deferred.
- **RFC 3396 long-option concatenation** — parser-side
  feature with no current consumer. Existing PyTCP
  codecs produce payloads short enough that splitting
  never happens on the wire. Land alongside Phase 7
  (RFC 3442 Classless Static Routes) which is the
  first real consumer.
