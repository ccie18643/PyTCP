# RFC 792 — Internet Control Message Protocol

| Field       | Value                             |
|-------------|-----------------------------------|
| RFC number  | 792                               |
| Title       | Internet Control Message Protocol |
| Category    | Internet Standard (STD 5)         |
| Date        | September 1981                    |
| Source text | [`rfc792.txt`](rfc792.txt)        |

This adherence record is currently a stub for the RFC 792 base
spec. The host-requirements layer that prescribes how PyTCP
generates and processes RFC 792 messages is audited in detail at
[`../rfc1122__host_requirements_icmp/adherence.md`](../rfc1122__host_requirements_icmp/adherence.md).

Implementation status by ICMPv4 type, as of the recent ICMP
host-requirements work:

| Type  | Name                    | Status                                            |
|-------|-------------------------|---------------------------------------------------|
| 0     | Echo Reply              | met (RX + RAW socket delivery)                    |
| 3     | Destination Unreachable | met (parser + emitter; demux to TCP/UDP/PMTUD)    |
| 4     | Source Quench           | deliberate non-implementation (RFC 6633)          |
| 5     | Redirect                | met (codec + host RX-accept + router emission, M3)|
| 8     | Echo Request            | met (Smurf gate at v4 echo handler)               |
| 11    | Time Exceeded           | met (parser + RFC 5927 §6 soft-error plumbing)    |
| 12    | Parameter Problem       | met (parser + RFC 5927 §6 soft-error plumbing)    |
| 13/14 | Timestamp / Reply       | deliberate non-implementation (RFC 1122 §3.2.2.8) |
| 15/16 | Information Req/Reply   | deliberate non-implementation (obsolete)          |
| 17/18 | Address Mask            | deliberate non-implementation (RFC 6918)          |

The audit will be expanded into a per-section walkthrough using the
[`rfc_adherence_audit`](../../../../.claude/skills/rfc_adherence_audit/SKILL.md)
skill when Phase β closes the Time Exceeded / Parameter Problem
gap, since those changes touch RFC 792 normative wording on Type 11
/ Type 12 message format.

---

## Parser validation — RFC 792 / RFC 1122 §3.2.2 sanity surface

`Icmp4Parser._validate_integrity`
(`packages/net_proto/net_proto/protocols/icmp4/icmp4__parser.py`)
enforces RFC 792 structural invariants:

- **`ICMP4__HEADER__LEN (4) <= ip4.payload_len <= len(frame)`** — RFC 792
  §"Message Formats" common 4-byte header (type / code / checksum) plus the
  RFC 791 encapsulating IP boundary.
- **Per-message length floor** — each message subclass'
  `validate_integrity` (Echo Req/Reply, Destination Unreachable, Time
  Exceeded, Parameter Problem) enforces its RFC 792 fixed header length.
- **Checksum** — RFC 792 — the parser computes the ones'-complement sum
  over the IPv4-declared ICMP payload and rejects any frame whose result is
  non-zero.

`Icmp4Parser._validate_sanity` delegates to the per-message
`validate_sanity`:

- **Echo Request / Echo Reply** — RFC 792 defines `code = 0` only. Any
  other value is rejected as `Icmp4SanityError`.
- **Destination Unreachable** — RFC 792 codes 0..5 + RFC 1122 §3.2.2.1
  codes 6..12 + RFC 1812 §5.2.7.1 codes 13..15. Code values 16+ are
  unassigned by IANA and rejected.
- **Time Exceeded** — RFC 792 codes 0..1 (TTL exceeded in transit /
  Fragment reassembly time exceeded). Higher codes rejected.
- **Parameter Problem** — RFC 792 code 0 (pointer) + RFC 1122 §3.2.2.5
  codes 1 (Required Option Missing) and 2 (Bad Length). Higher codes
  rejected.
- **Unknown message type** — RFC 1122 §3.2.2 — "If an ICMP message of
  unknown type is received, it MUST be silently discarded." PyTCP's
  `Icmp4Type` enum declares the five types this host stack handles (0, 3,
  8, 11, 12); any other wire `type` byte (including deprecated Source
  Quench / Address Mask Request per RFC 6633 / 6918) materialises as
  `Icmp4MessageUnknown` and is rejected at parser sanity. The
  RX-side counter for both unknown-type and unknown-code rejections is
  `icmp4__failed_parse__drop`.

This is stricter than Linux's `net/ipv4/icmp.c::icmp_rcv`, which builds
the message and falls into the type-dispatch table where unknown types
silently increment a counter and drop. PyTCP rejects them at parser
sanity per RFC 1122 §3.2.2's explicit "silently discard" requirement.

**Wire-format strict-TX enum-domain enforcement (assembler):**
Each known ICMPv4 message type has a closed `*Code` enum
subclass; the parser's `validate_sanity` rejects RX frames
whose code field carries an `UNKNOWN_n` pseudo-member
synthesised via `<code-enum>.from_int()`. The asymmetric
TX-side concern: a programmer who synthesised
`Icmp4EchoRequestCode.from_int(99)` (or any other
closed-enum's UNKNOWN member) and passed it to the assembler
would otherwise emit a frame with an unknown code that
strict receivers reject. `Icmp4Assembler.__init__` refuses
such constructions.

The dataclass `__post_init__` of each message type stays
parser-tolerant (the parser's `from_buffer` constructs via
`<code-enum>.from_int()` and the `__post_init__` only does
isinstance checks); the strict closed-set rejection lives at
the assembler boundary, mirroring the DHCPv4 UNKNOWN-enum
asymmetry split (commit `68e0bd95`).

`Icmp4MessageUnknown` is exempt from the closed-set check:
it is the parser-side carrier for RFC 1122 §3.2.2
unknown-type frames whose code field is by definition an
`UNKNOWN_n` member of the abstract `Icmp4Code` base.
Wrapping such a message in an assembler is a legitimate
roundtrip case (security testing / raw-socket replay); the
per-code check is gated by `not isinstance(message,
Icmp4MessageUnknown)`.

Pinned by `TestIcmp4AssemblerUnknownCodeReject` at
`packages/net_proto/net_proto/tests/unit/protocols/icmp4/test__icmp4__assembler__misc.py`
(four cases: unknown Echo Request code rejected, unknown
Destination Unreachable code rejected, `Icmp4MessageUnknown`
wrapping accepted, known-code happy path accepted).
