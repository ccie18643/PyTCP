# RFC 6842 — Client Identifier Option in DHCP Server Replies

| Field       | Value                                                |
|-------------|------------------------------------------------------|
| RFC number  | 6842                                                 |
| Title       | Client Identifier Option in DHCP Server Replies      |
| Category    | Standards Track                                      |
| Date        | January 2013                                         |
| Updates     | RFC 2131                                             |
| Source text | [`rfc6842.txt`](rfc6842.txt)                         |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 6842. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `packages/pytcp/pytcp/` and `packages/net_proto/net_proto/` directly.

RFC 6842 overrides the RFC 2131 §4.3.1 prohibition on
servers echoing the Client Identifier option back in
DHCPOFFER/DHCPACK/DHCPNAK. Under RFC 6842, **servers
MUST echo the option** and **clients MUST validate the
echoed value matches what they sent** (silently
discarding any mismatching reply).

PyTCP's compliance status:

- **Server-side requirement (MUST echo):** N/A — PyTCP
  is a DHCP client only.
- **Client-side requirement (MUST validate echo):**
  met (Phase 0). `packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py`'s
  `_cid_echo_ok(...)` compares the inbound
  `client_id` against the client's locally cached
  `self._expected_client_id` and returns False on
  mismatch; the `_recv_within_window(...)` receive
  loop gates on the result and silently discards
  mismatching replies. Absent CID echo is
  acceptable per RFC 6842's "if the client identifier
  option is present" framing.

Sections without normative content (§1 Introduction,
§2 Conventions, §4 Security Considerations, §5
Acknowledgments, §6 Normative References, Authors'
Addresses) are omitted.

---

## §3 Modification to RFC 2131

> "If the 'client identifier' option is present in a
>  message received from a client, the server MUST
>  return the 'client identifier' option, unaltered,
>  in its response message."

**Adherence:** N/A. PyTCP has no DHCP server.

> "Option   DHCPOFFER  DHCPACK    DHCPNAK
>  Client identifier (if sent by client)  MUST MUST MUST
>  Client identifier (if not sent by client)  MUST NOT MUST NOT MUST NOT"

**Adherence:** N/A (server-side).

> "When a client receives a DHCP message containing a
>  'client identifier' option, the client MUST compare
>  that client identifier to the one it is configured
>  to send. If the two client identifiers do not match,
>  the client MUST silently discard the message."

**Adherence:** met. The `_recv_within_window(...)`
receive loop in
`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py` invokes
`self._cid_echo_ok(packet)` (lines 1645 and 1667)
after the message-type + xid checks. The helper
extracts `packet.client_id`
(surfaced by the new `Dhcp4Options.client_id`
accessor) and returns False on mismatch with the
client's emitted CID; the loop then logs a
`<WARN>` line and drops the packet. A misdirected reply
echoing someone else's Client Identifier is silently
discarded per the MUST. The same gate also fires on the
NAK path, so a stray NAK for an unrelated transaction
cannot kick the client into a restart loop.

The `Dhcp4OptionClientId` codec at
`packages/net_proto/net_proto/protocols/dhcp4/options/dhcp4__option__client_id.py`
parses the inbound option; the
`Dhcp4Options.client_id` accessor (added in this Phase 0
commit) surfaces it on the parsed message.

---

## Test coverage audit

### §3 — Client-side echo validation

- **Unit:** `packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__client.py`
  - `TestDhcp4ClientFetchCidEcho::test__dhcp4_client__fetch_returns_none_on_offer_cid_mismatch`
    — OFFER echoes a CID built from a different MAC;
    `fetch()` returns None.
  - `TestDhcp4ClientFetchCidEcho::test__dhcp4_client__fetch_returns_none_on_ack_cid_mismatch`
    — same shape on the ACK leg.
  - `TestDhcp4ClientFetchCidEcho::test__dhcp4_client__fetch_accepts_matching_cid_echo`
    — happy-path regression guard: matching echo →
    lease returned.

**Status:** locked in (Phase 0).

### Test coverage summary

| Aspect                                  | Coverage                          |
|-----------------------------------------|-----------------------------------|
| Server-side echo (MUST)                 | n/a (PyTCP is client only)        |
| Client-side echo validation (MUST)      | locked in (Phase 0)               |
| Mismatching-echo silent discard         | locked in (Phase 0)               |
| Matching-echo happy-path regression     | locked in (Phase 0)               |

---

## Overall assessment

| Aspect                                                   | Status                              |
|----------------------------------------------------------|-------------------------------------|
| §3 Server MUST echo Client Identifier                    | n/a (PyTCP is client only)          |
| §3 Client MUST compare echoed CID to configured CID      | met (Phase 0)                       |
| §3 Client MUST silently discard mismatching messages     | met (Phase 0)                       |
| `Dhcp4OptionClientId` codec on RX                        | available (in `Dhcp4Options`)       |
| `Dhcp4Options.client_id` accessor                        | met (added Phase 0)                 |

**Principal compliance note.** This MUST is wired
end-to-end. Phase 3 upgraded the underlying CID form
from the RFC 2131 type-0x01 + MAC layout to the
RFC 4361 §6.1 type-0xff + IAID + DUID layout (see
`rfc4361__node_specific_client_id`); the
echo-validator was unaffected — it compares whatever
`self._expected_client_id` resolves to against whatever
the server echoed. A `TestDhcp4ClientFetchRfc4361Cid`
regression test pins that a server echoing the legacy
form (type 0x01 + MAC) against a Phase-3 client emitting
the RFC 4361 form is silently discarded.
