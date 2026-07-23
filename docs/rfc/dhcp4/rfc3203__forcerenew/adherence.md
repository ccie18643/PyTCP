# RFC 3203 — DHCP Reconfigure Extension (FORCERENEW)

| Field       | Value                                                |
|-------------|------------------------------------------------------|
| RFC number  | 3203                                                 |
| Title       | DHCP reconfigure extension                           |
| Category    | Standards Track                                      |
| Date        | December 2001                                        |
| Updates     | RFC 2131                                             |
| Source text | [`rfc3203.txt`](rfc3203.txt)                         |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 3203. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `packages/pytcp/pytcp/` and `packages/net_proto/net_proto/` directly.

RFC 3203 introduces the DHCPFORCERENEW message — a
server-to-client signal that tells a BOUND client to
move to RENEWING state immediately (or, after a
DHCPNAK to its RENEW request, fall back to INIT and
re-discover). **PyTCP does not implement FORCERENEW**
at any level:

- The `Dhcp4MessageType` enum at
  `packages/net_proto/net_proto/protocols/dhcp4/dhcp4__enums.py:58-95`
  declares DISCOVER through INFORM (codes 1–8) but
  not FORCERENEW (code 9).
- The PyTCP client runs a full BOUND/RENEWING/REBINDING
  FSM (`_do_bound` :599, `_do_renewing` :629,
  `_do_rebinding` :652 in
  `packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py`),
  but its state transitions are timer-driven (T1/T2);
  there is no receive path for a server-initiated
  FORCERENEW.
- The client receives DHCP messages only synchronously,
  as replies to its own DISCOVER/REQUEST (via
  `_recv_within_window`); it runs no passive listener
  for unsolicited server-initiated messages, so an
  inbound FORCERENEW arrives at no consumer.

Sections without normative content (§1 Introduction,
§2.1 Motivation, §2.3 Example usage, §2.4 Rationale,
§5 IANA Considerations, §6 Security Considerations
[but see note below], §7 Acknowledgments, §8 References,
§9 Authors' Addresses) are omitted.

---

## §2.2 Procedure

> "Upon reception of a FORCERENEW message by the client
>  in BOUND state, it should move into the renew state.
>  It will broadcast a DHCP REQUEST in order to extend
>  the existing lease."

**Adherence:** not met. The BOUND and RENEWING states
exist and a REQUEST is broadcast on T1, but that
transition is timer-driven — there is no FORCERENEW
handler to trigger the move on server command.

> "If the DHCP server does not want to extend the lease
>  or has not yet noticed the original lease, but wants
>  to assign a new IP address to the client, it will
>  reply to the DHCP REQUEST with a DHCP NAK. The
>  client will then go back to the init state and
>  broadcast a DHCP DISCOVER message."

**Adherence:** not met (for the FORCERENEW trigger). The
client does handle DHCPNAK generally — a NAK returns the
`_NAK_RESTART` sentinel (:189) and the FSM falls back to
INIT to re-discover (`_recv_within_window` :1644) — but
there is no FORCERENEW message path to drive the
renew-then-NAK sequence this paragraph describes.

> "Receipt of a multicast FORCERENEW message by the
>  client should be silently discarded."

**Adherence:** vacuously met. PyTCP runs no passive
listener for unsolicited server-initiated DHCP messages
— it only receives replies to its own DISCOVER/REQUEST
— so a multicast FORCERENEW arrives at no consumer.

> "It can be that a client has obtained a network
>  address through some other means (e.g., manual
>  configuration) and has used a DHCP INFORM request
>  to obtain other local configuration parameters.
>  Such clients should respond to the receipt of a
>  unicast FORCERENEW message with a new DHCP INFORM
>  request."

**Adherence:** not met. No DHCPINFORM path (see
RFC 2131 §3.4 audit).

---

## §3 Extended DHCP state diagram

**Adherence:** not met. PyTCP implements the RFC 2131
base state diagram (INIT / SELECTING / REQUESTING /
BOUND / RENEWING / REBINDING), but not the RFC 3203
extension edge — the server-commanded BOUND → RENEW
transition on FORCERENEW.

---

## §4 Message layout

> "The FORCERENEW message makes use of the normal DHCP
>  message layout with the introduction of a new DHCP
>  message type. DHCP option 53 (DHCP message type) is
>  extended with a new value: DHCPFORCERENEW (9)"

**Adherence:** not met. The `Dhcp4MessageType` enum at
`packages/net_proto/net_proto/protocols/dhcp4/dhcp4__enums.py:58-95`
declares codes 1 (DISCOVER) through 8 (INFORM).
Code 9 (FORCERENEW) is absent. An inbound DHCP message
with message-type 9 would parse the option (via
`Dhcp4OptionMessageType` and the `ProtoEnumByte`
unknown-value extension at
`packages/net_proto/net_proto/lib/proto_enum.py`) into an "unknown"
enum member, but the client filter at
`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:167-172`, `:222-227`
treats unknown message types as errors and returns
None.

---

## §6 Security Considerations

> "As in some network environments FORCERENEW can be
>  used to snoop and spoof traffic, the FORCERENEW
>  message MUST be authenticated using the procedures
>  as described in [DHCP-AUTH]. FORCERENEW messages
>  failing the authentication should be silently
>  discarded by the client."

**Adherence:** N/A. PyTCP does not implement RFC 3118
DHCP Authentication either. If FORCERENEW were ever
added, the authentication MUST would block it from
landing without RFC 3118 first.

---

## Test coverage audit

### DHCPFORCERENEW message-type handling

**No test surface — gap not yet closed.** Implementing
FORCERENEW requires a multi-step plan:

1. Extend `Dhcp4MessageType` with `FORCERENEW = 9`.
2. Implement a long-lived DHCP listener
   (Phase 2 — PyTCP's client is one-shot today).
3. Add the BOUND-and-RENEW state machine
   (RFC 2131 §4.4 prerequisite).
4. Implement RFC 3118 authentication option (51 / 90
   per RFC 3118) — without it, FORCERENEW is a known
   spoof vector.

Each of (1)–(4) is its own commit-sized project.

### Test coverage summary

| Aspect                                | Coverage                          |
|---------------------------------------|-----------------------------------|
| FORCERENEW message-type codec         | not implemented; no test          |
| BOUND state FORCERENEW handler        | not implemented; no test          |
| INFORM-state FORCERENEW handler       | not implemented; no test          |
| Multicast FORCERENEW silent discard   | not implemented; no test          |
| Authentication of FORCERENEW          | not implemented; no test          |

---

## Overall assessment

| Aspect                                                  | Status            |
|---------------------------------------------------------|-------------------|
| §2.2 BOUND-state FORCERENEW handler                     | not implemented   |
| §2.2 INFORM-state FORCERENEW handler                    | not implemented   |
| §2.2 Multicast FORCERENEW silent discard                | vacuously met     |
| §3 Extended state diagram (BOUND → RENEW via FORCERENEW)| not implemented   |
| §4 DHCPFORCERENEW (code 9) message-type codec           | not implemented   |
| §6 RFC 3118 authentication of FORCERENEW                | not implemented   |

**Principal compliance note.** FORCERENEW is rarely
deployed in real networks because of the RFC 3118
authentication MUST — most DHCP servers don't bother
emitting it. PyTCP's omission has zero practical
interop impact. It is documented here for catalogue
completeness rather than as a real gap.

Implementing FORCERENEW would only become valuable if
PyTCP gained:
- RFC 2131 §4.4 BOUND/RENEWING/REBINDING FSM (real
  prerequisite); AND
- RFC 3118 DHCP authentication (security MUST).

Without both, server-side FORCERENEW emission is
either unauthenticated (and rightly ignored) or
authenticated (and the authentication infrastructure
costs more than the feature is worth in a host stack).
