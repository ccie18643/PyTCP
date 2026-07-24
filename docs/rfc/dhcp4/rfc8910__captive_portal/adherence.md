# RFC 8910 — Captive-Portal Identification in DHCP and Router Advertisements

| Field       | Value                                                          |
|-------------|----------------------------------------------------------------|
| RFC number  | 8910                                                           |
| Title       | Captive-Portal Identification in DHCP and Router Advertisements|
| Category    | Standards Track                                                |
| Date        | September 2020                                                 |
| Obsoletes   | RFC 7710                                                       |
| Updates     | RFC 3679                                                       |
| Source text | [`rfc8910.txt`](rfc8910.txt)                                   |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 8910. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `packages/pytcp/pytcp/` and `packages/net_proto/net_proto/` directly.

RFC 8910 defines three Captive-Portal option codepoints:

- DHCPv4 option 114
- DHCPv6 option 103
- IPv6 RA option type 37

Each carries a URI to the captive-portal API endpoint
(RFC 8908). PyTCP implements none of the three:

- DHCPv4 option 114 not in `Dhcp4OptionType`
  (`packages/net_proto/net_proto/protocols/dhcp4/options/dhcp4__option.py:56-76`).
- DHCPv6 option 103 not implemented (PyTCP's DHCPv6
  client does not request or parse option 103).
- RA option 37 not in `Icmp6NdOption*` codecs under
  `packages/net_proto/net_proto/protocols/icmp6/message/nd/options/`.

This audit covers only the DHCPv4 piece (option 114),
which falls in the DHCP4 RFC family. The DHCPv6 piece
would belong to a future `docs/rfc/dhcp6/` family; the
RA piece belongs in `docs/rfc/icmp6/`.

Sections without normative content (§1 Introduction,
§1.1 Requirements Notation, §3 Precedence of API URIs,
§4 Use of the URI, §5 IANA Considerations, §6 Security
Considerations, §7 References, Appendices,
Acknowledgments, Authors' Addresses) are omitted.

---

## §2.1 IPv4 DHCP Option — wire format

> "Code: The Captive-Portal DHCPv4 Option (114) (one
>  octet)."

**Adherence:** not implemented. Option code 114 is
absent from `Dhcp4OptionType`. Inbound option 114
parses into `Dhcp4OptionUnknown`.

> "Len: The length (one octet), in octets, of the URI."

**Adherence:** N/A (codec absent).

> "URI: The URI for the captive portal API endpoint to
>  which the user should connect (encoded following the
>  rules in [RFC3986])."

**Adherence:** N/A.

> "Note that the URI parameter is not null terminated."

**Adherence:** N/A.

---

## §2 Client behaviour

> "Clients that support the Captive Portal DHCP option
>  SHOULD include the option in the Parameter Request
>  List in DHCPREQUEST messages."

**Adherence:** not met. PyTCP's PRL contains
CLASSLESS_STATIC_ROUTE, SUBNET_MASK, and ROUTER — but
not option 114
(`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:1763`
DISCOVER, `:1811` REQUEST).

> "In all variants of this option, the URI MUST be that
>  of the captive portal API endpoint."

**Adherence:** N/A (option not consumed).

> "The URI SHOULD NOT contain an IP address literal."

**Adherence:** N/A (server-side / network operator
SHOULD; not a client concern).

> "Networks with no captive portals may explicitly
>  indicate this condition by using this option with
>  the IANA-assigned URI for this purpose. Clients
>  observing the URI value
>  'urn:ietf:params:capport:unrestricted' may forego
>  time-consuming forms of captive portal detection."

**Adherence:** N/A (no captive-portal detection
machinery at all).

---

## §3 Precedence of API URIs

> "A device may learn about Captive Portal API URIs
>  through more than one of (or indeed all of) the
>  above options."

**Adherence:** N/A.

> "If the URIs learned via more than one option
>  described in Section 2 are not all identical, this
>  condition should be logged for the device owner or
>  administrator."

**Adherence:** N/A.

---

## §4 Use of the URI

> "Once a host obtains a URI from a Captive-Portal
>  Option, it should access the URI to obtain
>  information about the captive portal as described
>  in [RFC8908]."

**Adherence:** N/A. PyTCP is not a captive-portal-aware
host — there is no HTTP user agent, no captive-portal
consumer, no notification surface.

---

## Test coverage audit

### Option 114 codec

**No test surface — gap not yet closed.** When the gap
is fixed, the natural test plan:

1. Add a `Dhcp4OptionCaptivePortal` codec parsing a
   variable-length URI (no NUL terminator).
2. Unit-test the codec with a representative URI.
3. Integration-test the client requesting option 114
   in the PRL (DISCOVER and REQUEST), receiving an
   ACK with option 114, and surfacing the URI to a
   callback / log line.

### Test coverage summary

| Aspect                                  | Coverage                          |
|-----------------------------------------|-----------------------------------|
| Option 114 codec                        | not implemented; no test          |
| Parameter Request List entry (114)      | not implemented; no test          |
| URI extraction / consumer plumbing      | not implemented; no test          |

---

## Overall assessment

| Aspect                                                   | Status                       |
|----------------------------------------------------------|------------------------------|
| §2.1 DHCPv4 option 114 wire format                       | not implemented              |
| §2 PRL entry for option 114 in DISCOVER/REQUEST          | not implemented              |
| §3 Precedence resolution across multiple sources         | n/a (no sources implemented) |
| §4 URI consumer plumbing                                 | n/a                          |
| DHCPv6 option 103 (in `docs/rfc/dhcp6/`)                 | not implemented              |
| IPv6 RA option type 37 (in `docs/rfc/icmp6/`)            | not implemented              |

**Principal compliance note.** Captive-Portal
identification is a "modern host" feature (Apple
captive-portal-detection, Windows NCSI, etc.). PyTCP
has no HTTP user-agent / browser surface that would
consume the URI, so implementing the codec without a
consumer would be purely informational.

For Phase 1 host parity this is genuinely out of scope
— Linux's captive-portal handling lives in user-space
NetworkManager / connman, not in the kernel stack
PyTCP mirrors. The right approach is:

1. Add option 114 to the codec when (and if) a PyTCP
   consumer needs the URI.
2. Optionally request it in the PRL with no consumer
   (so the value is at least parsed into the
   `Dhcp4Options` and a future log channel could
   surface it).

If a future PyTCP feature (e.g. an HTTP client) wants
to detect captive portals via this URI, the codec is
~30 lines and follows the same pattern as
`Dhcp4OptionHostName`.
