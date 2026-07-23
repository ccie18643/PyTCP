# RFC 4361 — Node-specific Client Identifiers for DHCPv4

| Field       | Value                                                  |
|-------------|--------------------------------------------------------|
| RFC number  | 4361                                                   |
| Title       | Node-specific Client Identifiers for DHCPv4 using DUID |
| Category    | Standards Track                                        |
| Date        | February 2006                                          |
| Updates     | RFC 2131, RFC 2132                                     |
| Source text | [`rfc4361.txt`](rfc4361.txt)                           |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 4361. The audit was performed by reading
the RFC text fresh and inspecting the codebase under
`packages/pytcp/pytcp/` and `packages/net_proto/net_proto/` directly.

RFC 4361 modernises the DHCPv4 Client Identifier (option
61) by mandating a DUID + IAID construction (matching
DHCPv6 / RFC 3315) instead of the RFC 2131 legacy
hardware-address form. **PyTCP emits the RFC 4361
type-0xff + IAID + DUID form** via
`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__uid.build_client_id`,
called from `Dhcp4Client._expected_client_id` — the
legacy `b"\x01" + bytes(mac_address)` form is gone and
RFC 4361's MUST clauses are implemented (Phase 3).

Sections without normative content (§1 Introduction, §2
Terminology, §3 Applicability, §4 Problem Statement, §5
Requirements rationale, §7 Multi-stage Network Booting
discussion, §8 Security Considerations boilerplate,
§9 IANA Considerations, §10 Acknowledgments, §11
References, §12 Author's Addresses) are omitted.

---

## §6.1 DHCPv4 Client Behavior

> "DHCPv4 clients conforming to this specification MUST
>  use stable DHCPv4 node identifiers in the
>  dhcp-client-identifier option. DHCPv4 clients MUST
>  NOT use client identifiers based solely on layer two
>  addresses that are hard-wired to the layer two device
>  (e.g., the ethernet MAC address) as suggested in
>  RFC 2131, except as allowed in section 9.2 of
>  RFC 3315."

**Adherence:** met (Phase 3). PyTCP emits the RFC 4361
type-0xff Client Identifier (type byte 0xff + 4-byte
IAID + DUID-LL) via 'packages/pytcp/pytcp/protocols/dhcp4/dhcp4__uid.build_client_id',
called from 'Dhcp4Client._expected_client_id'
(now a property that re-resolves on every emission so
operator overrides of 'dhcp.duid' take effect
immediately). The legacy `b"\x01" + bytes(mac)` form is
gone.

> "DHCPv4 clients MUST send a 'client identifier' option
>  containing an Identity Association Unique Identifier,
>  as defined in section 10 of RFC 3315, and a DHCP
>  Unique Identifier, as defined in section 9 of
>  RFC 3315."

**Adherence:** met (Phase 3). 'packages/pytcp/pytcp/protocols/dhcp4/dhcp4__uid.py'
provides 'build_duid_ll' (RFC 3315 §9.4 — 2-byte
type=3 + 2-byte hardware-type=1 + 6-byte MAC =
10 bytes for Ethernet), 'get_iaid' (RFC 3315 §10 —
4-byte big-endian IAID), and 'build_client_id'
(RFC 4361 §6.1 — type=0xff + IAID + DUID). The
resulting 15-byte Client Identifier is emitted in
every DHCPv4 message ('Code 61 | Len 15 | 0xff +
IAID + DUID-LL').

> "To send an RFC 3315-style binding identifier in a
>  DHCPv4 'client identifier' option, the type of the
>  'client identifier' option is set to 255."

**Adherence:** met (Phase 3). 'build_client_id'
prepends the canonical type byte 0xff before the IAID
and DUID portions of the wire form.

> "Any DHCPv4 client that conforms to this specification
>  SHOULD provide a means by which an operator can learn
>  what DUID the client has chosen. Such clients SHOULD
>  also provide a means by which the operator can
>  configure the DUID."

**Adherence:** met (Phase 3). The 'dhcp.duid' sysctl
exposes the active DUID to operators (compact-hex or
colon-separated form), readable via
`pytcp.stack.sysctl["dhcp.duid"]` and configurable at
boot via `stack.init(sysctls={"dhcp.duid": "00:03:..."})`.
The empty default signals "auto-derive DUID-LL from MAC";
a non-empty override takes precedence on every emission.

> "DHCPv4 clients that support more than one network
>  interface SHOULD use the same DUID on every
>  interface."

**Adherence:** N/A. PyTCP is currently single-interface
(Phase 2 multi-interface is on the north-star roadmap).

> "A DHCPv4 client that generates a DUID and that has
>  stable storage MUST retain this DUID for use in
>  subsequent DHCPv4 messages, even after an operating
>  system reboot."

**Adherence:** partial (Phase 3). The DUID is stable
across the process's lifetime — auto-derived from the
host MAC (which is itself stable), or operator-fixed
via the 'dhcp.duid' sysctl. Cross-process-restart
persistence is not yet implemented; the sysctl
registry is in-memory only, so a reboot re-runs the
auto-derive path. Stable-storage backing is tracked
for Phase 5 (cached-lease persistence) and will
naturally absorb DUID persistence.

---

## §6.3 DHCPv4 Server Behavior

**Adherence:** N/A. PyTCP is a DHCP client only.

---

## §6.4 Changes from RFC 2131

> "In section 4.2 of RFC 2131, the text '... If the
>  client does not provide a 'client identifier' option,
>  the server MUST use the contents of the 'chaddr'
>  field to identify the client.' is replaced by the
>  text 'The client MUST explicitly provide a client
>  identifier through the 'client identifier' option.
>  The client MUST use the same 'client identifier'
>  option for all messages.'"

**Adherence:** met (Phase 0 + Phase 3). PyTCP emits the
Client Identifier option in every DHCPv4 message
(DISCOVER, REQUEST, DECLINE — Phase 2.2) via the same
'_expected_client_id' property. Phase 0 added the
option to REQUEST; Phase 3 upgraded the wire form to
the RFC 4361 §6.1 0xff+IAID+DUID layout.

> "In section 4.4.1 of RFC 2131, the text 'The client
>  MAY include a different unique identifier' is
>  replaced with 'The client MUST include a unique
>  identifier'."

**Adherence:** met (in DISCOVER). The client always
includes the option in DISCOVER (it is unconditional).

> "The DHCP client MUST NOT rely on the 'chaddr' field
>  to identify it."

**Adherence:** met. PyTCP sends a Client Identifier
option in DISCOVER, so the server does not need to fall
back to `chaddr`.

---

## §6.5 Changes from RFC 2132

> "The text in section 9.14, beginning with 'The client
>  identifier MAY consist of' through 'that meet this
>  requirement for uniqueness.' is replaced with 'the
>  client identifier consists of a type field whose
>  value is normally 255, followed by a four-byte IA_ID
>  field, followed by the DUID for the client as
>  defined in RFC 3315, section 9.'"

**Adherence:** met (Phase 3). The Client Identifier
wire form is now type byte 0xff + 4-byte IAID +
n-byte DUID per the §6.1 replacement text. The legacy
RFC 2131 §9.14 form is no longer emitted.

---

## Test coverage audit

### §6.1 / §6.4 / §6.5 — DUID-based Client Identifier (Phase 3)

- **Unit:** `packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__uid.py`
  — DUID-LL wire format (10 bytes = 2-byte type-3 +
  2-byte hardware-type-1 + 6-byte MAC), IAID encoding
  (4-byte big-endian), RFC 4361 Client Identifier
  layout (1+4+10 = 15 bytes), MAC-derived fallback,
  sysctl-override precedence (compact + colon-separated
  hex), stability across successive calls.
- **Unit:** `packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__client.py::TestDhcp4ClientFetchRfc4361Cid`
  — every DISCOVER and REQUEST carries the RFC 4361
  form; operator override of 'dhcp.duid' propagates
  through to the emitted CID; two consecutive fetches
  emit byte-identical CIDs; a server echoing the legacy
  type-0x01 form fails RFC 6842 echo validation.
- **Unit:** `packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__constants.py`
  — 'dhcp.duid' default empty, accepts compact +
  colon-separated hex, rejects non-hex / odd-length /
  non-string.

**Status:** locked in (Phase 3).

### Test coverage summary

| Aspect                                       | Coverage                                                       |
|----------------------------------------------|----------------------------------------------------------------|
| RFC 4361 DUID-based Client Identifier        | locked in (Phase 3 — `TestDhcp4ClientFetchRfc4361Cid`)         |
| DUID-LL wire format + IAID encoding          | locked in (Phase 3 — `test__dhcp4__uid.py`)                    |
| Operator-overridable DUID via sysctl         | locked in (Phase 3 — 'dhcp.duid' tests)                        |
| Client Identifier in REQUEST (RFC 2131 §2)   | locked in (Phase 0 — `TestDhcp4ClientFetchClientIdInRequest`)  |
| DUID persistence across OS reboot            | not implemented; Phase 5 (cached-lease persistence) territory  |
| Same DUID across interfaces                  | n/a (single-interface)                                         |

---

## Overall assessment

| Aspect                                                | Status                                                |
|-------------------------------------------------------|-------------------------------------------------------|
| §6.1 Stable DUID-based Client Identifier on TX        | met (Phase 3)                                         |
| §6.1 IAID + DUID wire format (type 255)               | met (Phase 3)                                         |
| §6.1 Operator inspection / configuration of DUID      | met (Phase 3 — 'dhcp.duid' sysctl)                    |
| §6.1 Same DUID across interfaces                      | n/a (single-interface)                                |
| §6.1 DUID retained across OS reboot (stable storage)  | partial (process-stable; cross-reboot is Phase 5)     |
| §6.4 Client MUST NOT rely on chaddr for identification| met (CID always emitted in DISCOVER)                  |
| §6.4 Client MUST use same CID in all messages         | met (Phase 0 + Phase 3 — CID in every DHCPv4 message) |
| §6.5 RFC 2132 §9.14 wire format change                | met (Phase 3)                                         |
| §6.3 Server behaviour                                 | n/a (client only)                                     |

**Principal compliance note.** The PyTCP DHCP client is
now RFC 4361 compliant for everything except cross-OS-
reboot DUID persistence. The operator can pin the DUID
via the 'dhcp.duid' sysctl at boot time, which provides
the equivalent of `/var/lib/dhcp/duid` if the operator
chooses to persist the value externally. Native
file-backed persistence is folded into Phase 5
(cached-lease persistence).

The fix delivered in Phase 3 was a single-file change in
the client plus the new 'packages/pytcp/pytcp/protocols/dhcp4/dhcp4__uid.py' helper;
the wire-format codec (`Dhcp4OptionClientId` at
`packages/net_proto/net_proto/protocols/dhcp4/options/dhcp4__option__client_id.py`)
already accepted arbitrary bytes, so no codec change was
required.
