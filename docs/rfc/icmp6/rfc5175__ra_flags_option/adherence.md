# RFC 5175 — IPv6 Router Advertisement Flags Option

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 5175                                              |
| Title       | IPv6 Router Advertisement Flags Option            |
| Category    | Standards Track                                   |
| Date        | March 2008                                        |
| Source text | [`rfc5175.txt`](rfc5175.txt)                      |

## Status: partial (MAY per RFC 8504 §5.6; option parsed, no consumer flag reacts)

The base Router Advertisement message carries an 8-bit
flags field; six bits are assigned (M, O, H, plus the 2-bit
Prf preference field defined by RFC 4191), two remain
available for future assignment. RFC 5175 defines a 48-bit
extension via a separate ND option, allowing future RA
flags to be advertised without exhausting the 8-bit field.

PyTCP parses the RA Flags Option today. The wire codec
`Icmp6NdOptionRaFlags` (type 26, `RA_FLAGS_EXTENSION`) lives
at
`packages/net_proto/net_proto/protocols/icmp6/message/nd/option/icmp6__nd__option__ra_flags.py`
and is dispatched from the ND options walker
`.../icmp6/message/nd/option/icmp6__nd__options.py:195-196`.
RFC 8504 §5.6 explicitly notes "no flags have been defined
that make use of the new option" — implementations MAY
parse it for forward-compatibility but no current standard
requires consumption.

The remaining gap is inert: the option is parsed, but no
consumer flag reacts to it — there is nothing to react to
until a real extension flag is defined.

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §5.6
  — parent classification (MAY)
- `docs/rfc/icmp6/rfc4861__ipv6_nd/adherence.md` — parent
  ND record
