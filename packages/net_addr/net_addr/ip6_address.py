################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


"""
This module contains IPv6 address support class.

net_addr/ip6_address.py

ver 3.0.8
"""

import socket
from typing import ClassVar, Self, final, override

from net_addr.buffer import Buffer
from net_addr.errors import Ip6AddressFormatError, Ip6AddressSanityError, NetAddrError
from net_addr.ip4_address import Ip4Address
from net_addr.ip_address import IpAddress
from net_addr.ip_version import IpVersion
from net_addr.mac_address import MAC__IP6_MULTICAST_PREFIX, MacAddress

IP6__ADDRESS_LEN = 16
IP6__MASK = 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF

IP6__GLOBAL_PREFIX = 0x2000_0000_0000_0000_0000_0000_0000_0000  # RFC 4291 2000::/3
IP6__GLOBAL_PREFIX_MASK = 0xE000_0000_0000_0000_0000_0000_0000_0000

IP6__LINK_LOCAL_PREFIX = 0xFE80_0000_0000_0000_0000_0000_0000_0000  # RFC 4291 fe80::/10
IP6__LINK_LOCAL_PREFIX_MASK = 0xFFC0_0000_0000_0000_0000_0000_0000_0000

IP6__LOOPBACK = 0x0000_0000_0000_0000_0000_0000_0000_0001  # RFC 4291 ::1/128

IP6__MULTICAST_PREFIX = 0xFF00_0000_0000_0000_0000_0000_0000_0000  # RFC 4291 ff00::/8
IP6__MULTICAST_PREFIX_MASK = 0xFF00_0000_0000_0000_0000_0000_0000_0000

IP6__MULTICAST_ALL_NODES = 0xFF02_0000_0000_0000_0000_0000_0000_0001  # RFC 4291 ff02::1
IP6__MULTICAST_ALL_ROUTERS = 0xFF02_0000_0000_0000_0000_0000_0000_0002  # RFC 4291 ff02::2

IP6__SOLICITED_NODE_PREFIX = 0xFF02_0000_0000_0000_0000_0001_FF00_0000  # RFC 4291 ff02::1:ff00:0/104
IP6__SOLICITED_NODE_PREFIX_MASK = 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FF00_0000
IP6__SOLICITED_NODE_HOST_MASK = 0x0000_0000_0000_0000_0000_0000_00FF_FFFF

IP6__PRIVATE_PREFIX = 0xFC00_0000_0000_0000_0000_0000_0000_0000  # RFC 4193 fc00::/7
IP6__PRIVATE_PREFIX_MASK = 0xFE00_0000_0000_0000_0000_0000_0000_0000

# RFC 3849 Documentation prefix — 2001:db8::/32
IP6__DOCUMENTATION_PREFIX = 0x2001_0DB8_0000_0000_0000_0000_0000_0000
IP6__DOCUMENTATION_PREFIX_MASK = 0xFFFF_FFFF_0000_0000_0000_0000_0000_0000

# RFC 9637 second Documentation prefix — 3fff::/20
IP6__DOCUMENTATION_RFC9637_PREFIX = 0x3FFF_0000_0000_0000_0000_0000_0000_0000
IP6__DOCUMENTATION_RFC9637_PREFIX_MASK = 0xFFFF_F000_0000_0000_0000_0000_0000_0000

# RFC 6666 Discard-Only Address Block — 100::/64
IP6__DISCARD_PREFIX = 0x0100_0000_0000_0000_0000_0000_0000_0000
IP6__DISCARD_PREFIX_MASK = 0xFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000

# RFC 2928 IETF Protocol Assignments — 2001::/23. The umbrella
# allocation that contains the TEREDO (2001::/32), Benchmarking
# (2001:2::/48, RFC 5180), AMT (2001:3::/32), AS112-v6
# (2001:4:112::/48), ORCHIDv2 (2001:20::/28), DET (2001:30::/28)
# and the PCP / TURN / DNS-SD anycast single-address assignments.
IP6__IETF_PROTOCOL_PREFIX = 0x2001_0000_0000_0000_0000_0000_0000_0000
IP6__IETF_PROTOCOL_PREFIX_MASK = 0xFFFF_FE00_0000_0000_0000_0000_0000_0000

# RFC 4291 §2.5.5.2 IPv4-mapped IPv6 — ::ffff:0:0/96
IP6__IPV4_MAPPED_PREFIX = 0x0000_0000_0000_0000_0000_FFFF_0000_0000
IP6__IPV4_MAPPED_PREFIX_MASK = 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0000_0000

# RFC 3056 §2 6to4 — 2002::/16 (embedded IPv4 in bits 111..80)
IP6__6TO4_PREFIX = 0x2002_0000_0000_0000_0000_0000_0000_0000
IP6__6TO4_PREFIX_MASK = 0xFFFF_0000_0000_0000_0000_0000_0000_0000

# RFC 4380 §4 Teredo — 2001:0000::/32 (server bits 95..64,
# obfuscated client = bitwise-NOT of bits 31..0)
IP6__TEREDO_PREFIX = 0x2001_0000_0000_0000_0000_0000_0000_0000
IP6__TEREDO_PREFIX_MASK = 0xFFFF_FFFF_0000_0000_0000_0000_0000_0000

# Remaining IANA IPv6 Special-Purpose Registry prefixes that
# 'is_reserved' aggregates and that have no dedicated predicate.

# RFC 6052 §2.1 NAT64 well-known prefix — 64:ff9b::/96
IP6__NAT64_WELL_KNOWN_PREFIX = 0x0064_FF9B_0000_0000_0000_0000_0000_0000
IP6__NAT64_WELL_KNOWN_PREFIX_MASK = 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0000_0000

# RFC 8215 NAT64 local-use translation prefix — 64:ff9b:1::/48
IP6__NAT64_LOCAL_PREFIX = 0x0064_FF9B_0001_0000_0000_0000_0000_0000
IP6__NAT64_LOCAL_PREFIX_MASK = 0xFFFF_FFFF_FFFF_0000_0000_0000_0000_0000

# RFC 9780 Dummy IPv6 Prefix — 100:0:0:1::/64
IP6__DUMMY_PREFIX = 0x0100_0000_0000_0001_0000_0000_0000_0000
IP6__DUMMY_PREFIX_MASK = 0xFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000

# RFC 7534 Direct Delegation AS112 Service — 2620:4f:8000::/48
IP6__AS112_PREFIX = 0x2620_004F_8000_0000_0000_0000_0000_0000
IP6__AS112_PREFIX_MASK = 0xFFFF_FFFF_FFFF_0000_0000_0000_0000_0000

# RFC 9602 Segment Routing over IPv6 (SRv6) SIDs — 5f00::/16
IP6__SRV6_PREFIX = 0x5F00_0000_0000_0000_0000_0000_0000_0000
IP6__SRV6_PREFIX_MASK = 0xFFFF_0000_0000_0000_0000_0000_0000_0000


@final
class Ip6Address(IpAddress):
    """
    IPv6 address support class.
    """

    __slots__ = ("_scope_id",)

    _version: IpVersion = IpVersion.IP6

    _address_len: ClassVar[int] = IP6__ADDRESS_LEN

    _sanity_error: ClassVar[type[NetAddrError]] = Ip6AddressSanityError

    _scope_id: str | None

    def __init__(
        self,
        address: Self | str | Buffer | int | None = None,
        /,
    ) -> None:
        """
        Initialize the IPv6 address object.
        """

        self._scope_id = None

        if address is None:
            self._address = 0
            return

        if isinstance(address, Ip6Address):
            self._address = int(address)
            self._scope_id = address._scope_id
            return

        if isinstance(address, int):
            if 0 <= address <= IP6__MASK:
                self._address = address
                return

        if isinstance(address, (memoryview, bytes, bytearray)):
            if len(address) == IP6__ADDRESS_LEN:
                self._address = int.from_bytes(address)
                return

        if isinstance(address, str):
            # RFC 4007 / RFC 6874: an optional '%<zone>' suffix
            # is the scope identifier. It is accepted only when
            # absent, or present with a non-empty zone containing
            # no further '%'. Surrounding whitespace is stripped
            # uniformly across every net_addr string constructor.
            # 'socket.inet_pton' is the strict POSIX parser and
            # the sole address validator (mirrors the IPv4
            # constructor); no pre-filter regex.
            addr_part, sep, zone = address.strip().partition("%")
            zone_ok = not sep or (bool(zone) and "%" not in zone)
            if zone_ok:
                try:
                    self._address = int.from_bytes(socket.inet_pton(socket.AF_INET6, addr_part))
                except OSError:
                    pass
                else:
                    # RFC 4007 §6: a zone index is only meaningful
                    # for non-global scopes. Reject a '%zone' on a
                    # global-scope address.
                    if sep and not self._is_zoneable:
                        raise Ip6AddressFormatError(address)
                    self._scope_id = zone if sep else None
                    return

        raise Ip6AddressFormatError(address)

    @override
    def __str__(self) -> str:
        """
        Get the IPv6 address log string.
        """

        text = socket.inet_ntop(socket.AF_INET6, bytes(self))

        if self._scope_id is not None:
            text = f"{text}%{self._scope_id}"

        return text

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv6 address as a memoryview.
        """

        return memoryview(bytearray(self._address.to_bytes(IP6__ADDRESS_LEN)))

    @override
    def __eq__(self, other: object, /) -> bool:
        """
        Compare the IPv6 address with another object. The RFC
        4007 scope identifier is part of the address identity.
        """

        return other is self or (
            isinstance(other, type(self)) and self._address == other._address and self._scope_id == other._scope_id
        )

    @override
    def __hash__(self) -> int:
        """
        Get the IPv6 address hash value (scope identifier
        included).
        """

        return hash((type(self), self._address, self._scope_id))

    def _order_key(self) -> tuple[int, str]:
        """
        Get the ordering key. The RFC 4007 scope identifier is
        folded in so ordering stays consistent with equality
        (same address, different scope is unequal and ordered).
        """

        return (self._address, self._scope_id or "")

    @override
    def __lt__(self, other: object, /) -> bool:
        """
        Order the IPv6 address by (integer value, scope id).
        """

        if not isinstance(other, type(self)):
            return NotImplemented

        return self._order_key() < other._order_key()

    @override
    def __le__(self, other: object, /) -> bool:
        """
        Order the IPv6 address by (integer value, scope id).
        """

        if not isinstance(other, type(self)):
            return NotImplemented

        return self._order_key() <= other._order_key()

    @override
    def __gt__(self, other: object, /) -> bool:
        """
        Order the IPv6 address by (integer value, scope id).
        """

        if not isinstance(other, type(self)):
            return NotImplemented

        return self._order_key() > other._order_key()

    @override
    def __ge__(self, other: object, /) -> bool:
        """
        Order the IPv6 address by (integer value, scope id).
        """

        if not isinstance(other, type(self)):
            return NotImplemented

        return self._order_key() >= other._order_key()

    @override
    def __add__(self, other: object, /) -> Self:
        """
        Get the IPv6 address advanced by an integer offset, with
        the RFC 4007 zone identifier carried onto the result. An
        out-of-range result raises 'Ip6AddressSanityError'.
        """

        if not isinstance(other, int):
            return NotImplemented

        result = self._with_offset(other)
        # RFC 4007 §6: a zone is meaningful only for a non-global
        # scope. Carry the zone onto the result only when the
        # offset address is still zoneable; otherwise drop it so
        # a scoped Ip6Address always satisfies the constructor's
        # invariant (and stays consistent under __eq__ / __hash__).
        # The scoped result is produced through the string
        # constructor rather than by mutating a freshly built
        # instance, keeping the value-type "construct fresh, never
        # mutate" contract literal.
        if self._scope_id is None or not result._is_zoneable:
            return result
        return type(self)(f"{result}%{self._scope_id}")

    @override
    def __sub__(self, other: object, /) -> Self:
        """
        Get the IPv6 address retreated by an integer offset, with
        the RFC 4007 zone identifier carried onto the result. An
        out-of-range result raises 'Ip6AddressSanityError'.
        """

        if not isinstance(other, int):
            return NotImplemented

        result = self._with_offset(-other)
        # RFC 4007 §6: a zone is meaningful only for a non-global
        # scope. Carry the zone onto the result only when the
        # offset address is still zoneable; otherwise drop it so
        # a scoped Ip6Address always satisfies the constructor's
        # invariant (and stays consistent under __eq__ / __hash__).
        # The scoped result is produced through the string
        # constructor rather than by mutating a freshly built
        # instance, keeping the value-type "construct fresh, never
        # mutate" contract literal.
        if self._scope_id is None or not result._is_zoneable:
            return result
        return type(self)(f"{result}%{self._scope_id}")

    @property
    def _is_zoneable(self) -> bool:
        """
        Check whether the address has a non-global scope and so
        may carry an RFC 4007 zone identifier: link-local
        unicast, loopback (link-local scope per RFC 4007 §6), or
        multicast with a non-global scope value (0 < scop < 0xE).
        """

        if self.is_link_local or self.is_loopback:
            return True

        if self.is_multicast:
            return 0x0 < (self._address >> 112) & 0x0F < 0xE

        return False

    @property
    def scope_id(self) -> str | None:
        """
        Get the RFC 4007 zone identifier (the text after '%'),
        or None if the address is unscoped.
        """

        # Phase 2: multi-interface link-local scoping consumes
        # this (ND / routing / source selection thread the
        # sin6_scope_id equivalent through the data path).
        return self._scope_id

    @property
    @override
    def multicast_mac(self) -> MacAddress:
        """
        Get the IPv6 multicast MAC address.
        """

        if not self.is_multicast:
            raise Ip6AddressSanityError(
                f"The IPv6 address must be a multicast address to get a multicast MAC address. Got: {self}"
            )

        return MacAddress(MAC__IP6_MULTICAST_PREFIX | self._address & 0x0000_FFFF_FFFF)

    @property
    @override
    def reverse_pointer(self) -> str:
        """
        Get the IPv6 reverse-DNS PTR name (all 32 reversed
        nibbles in the ip6.arpa zone).
        """

        return ".".join(reversed(f"{self._address:032x}")) + ".ip6.arpa"

    @override
    def _format_alt(self, format_spec: str, /) -> str | None:
        """
        Render the 'ex' (expanded) text code — eight groups of
        four lowercase hex digits, no zero compression (RFC 4291
        §2.2 form 1). Any other code is not recognised.
        """

        if format_spec == "ex":
            nibbles = f"{self._address:032x}"
            return ":".join(nibbles[index : index + 4] for index in range(0, 32, 4))

        return None

    @property
    def ipv4_mapped(self) -> Ip4Address | None:
        """
        Get the embedded IPv4 address of an IPv4-mapped IPv6
        address (::ffff:0:0/96), or None.
        """

        if self._address & IP6__IPV4_MAPPED_PREFIX_MASK == IP6__IPV4_MAPPED_PREFIX:
            return Ip4Address(self._address & 0xFFFF_FFFF)

        return None

    @property
    def is_ipv4_mapped(self) -> bool:
        """
        Return True when this address is in the ::ffff:0:0/96
        IPv4-mapped IPv6 prefix — the predicate dual-stack
        socket code keys off to detect "this peer is actually
        IPv4 wearing an IPv6 mask" before unwrapping via
        'ipv4_mapped'. Parallel to 'is_loopback' / 'is_global'
        and to Linux's 'IN6_IS_ADDR_V4MAPPED' macro.
        """

        return self._address & IP6__IPV4_MAPPED_PREFIX_MASK == IP6__IPV4_MAPPED_PREFIX

    @classmethod
    def from_ipv4_mapped(cls, ip4_address: Ip4Address, /) -> Self:
        """
        Build the canonical ::ffff:0:0/96 IPv4-mapped IPv6
        address embedding 'ip4_address' as the low 32 bits.
        The explicit IPv4 → IPv6 conversion the dual-stack
        listener-fork uses on 'accept()' so an inbound IPv4
        peer surfaces as an IPv4-mapped IPv6 address to an
        AF_INET6 application — matching Linux's behaviour on
        a V6ONLY=0 listener.
        """

        return cls(IP6__IPV4_MAPPED_PREFIX | int(ip4_address))

    @property
    def sixtofour(self) -> Ip4Address | None:
        """
        Get the embedded IPv4 address of a 6to4 IPv6 address
        (2002::/16), or None.
        """

        if self._address & IP6__6TO4_PREFIX_MASK == IP6__6TO4_PREFIX:
            return Ip4Address((self._address >> 80) & 0xFFFF_FFFF)

        return None

    @property
    def teredo(self) -> tuple[Ip4Address, Ip4Address] | None:
        """
        Get the (server, client) IPv4 pair of a Teredo IPv6
        address (2001:0000::/32), or None. The client address
        is the bitwise-NOT-obfuscated low 32 bits.
        """

        if self._address & IP6__TEREDO_PREFIX_MASK == IP6__TEREDO_PREFIX:
            return (
                Ip4Address((self._address >> 64) & 0xFFFF_FFFF),
                Ip4Address(~self._address & 0xFFFF_FFFF),
            )

        return None

    @property
    def solicited_node_multicast(self) -> Self:
        """
        Create IPv6 solicited node multicast address.
        """

        if not (self.is_unicast or self.is_unspecified):
            raise Ip6AddressSanityError(
                "The IPv6 address must be a unicast or unspecified address "
                f"to get a solicited node multicast address. Got: {self}"
            )

        return type(self)(self._address & IP6__SOLICITED_NODE_HOST_MASK | IP6__SOLICITED_NODE_PREFIX)

    # Known deliberate divergence: this is "global unicast" in
    # the addressing-architecture sense (RFC 4291 2000::/3), NOT
    # RFC 6890 "Globally Reachable". It does not exclude the
    # not-reachable sub-blocks 2001::/23 (RFC 6890 IETF Protocol
    # Assignments — TEREDO, benchmarking, ORCHIDv2, AMT) or
    # 2001:db8::/32 (RFC 3849 Documentation), so it returns True
    # for them. Tightening to RFC-6890 reachability was verified
    # correct but is intentionally NOT applied: is_global has no
    # PyTCP consumer, so the strict form buys no functional
    # correctness while destabilising unrelated stack tests —
    # same disposition as is_site_local.
    @property
    @override
    def is_global(self) -> bool:
        """
        Check if IPv6 address is global.
        """

        return self._address & IP6__GLOBAL_PREFIX_MASK == IP6__GLOBAL_PREFIX

    @property
    @override
    def is_link_local(self) -> bool:
        """
        Check if IPv6 address is link local.
        """

        return self._address & IP6__LINK_LOCAL_PREFIX_MASK == IP6__LINK_LOCAL_PREFIX

    # Non-goal: site-local addressing (fec0::/10, the stdlib
    # `ipaddress` `is_site_local`) is deliberately not
    # implemented. RFC 3879 formally deprecated the site-local
    # prefix; its successor, Unique Local Addresses (ULA,
    # fc00::/7, RFC 4193), is already classified by
    # `is_private`. Adding an `is_site_local` predicate would
    # resurface a deprecated mechanism with no PyTCP consumer.

    @property
    @override
    def is_loopback(self) -> bool:
        """
        Check if the IPv6 address is a loopback address.
        """

        return self._address == IP6__LOOPBACK

    @property
    @override
    def is_multicast(self) -> bool:
        """
        Check if IPv6 address is multicast.
        """

        return self._address & IP6__MULTICAST_PREFIX_MASK == IP6__MULTICAST_PREFIX

    @property
    def is_multicast__all_nodes(self) -> bool:
        """
        Check if address is IPv6 all nodes multicast address.
        """

        return self._address == IP6__MULTICAST_ALL_NODES

    @property
    def is_multicast__all_routers(self) -> bool:
        """
        Check if address is IPv6 all routers multicast address.
        """

        return self._address == IP6__MULTICAST_ALL_ROUTERS

    @property
    def is_multicast__solicited_node(self) -> bool:
        """
        Check if address is IPv6 solicited node multicast address.
        """

        return self._address & IP6__SOLICITED_NODE_PREFIX_MASK == IP6__SOLICITED_NODE_PREFIX

    @property
    @override
    def is_private(self) -> bool:
        """
        Check if IPv6 address is private.
        """

        return self._address & IP6__PRIVATE_PREFIX_MASK == IP6__PRIVATE_PREFIX

    @property
    def is_documentation(self) -> bool:
        """
        Check if IPv6 address is in a documentation prefix:
        2001:db8::/32 (RFC 3849) or 3fff::/20 (RFC 9637).
        """

        return (
            self._address & IP6__DOCUMENTATION_PREFIX_MASK == IP6__DOCUMENTATION_PREFIX
            or self._address & IP6__DOCUMENTATION_RFC9637_PREFIX_MASK == IP6__DOCUMENTATION_RFC9637_PREFIX
        )

    @property
    def is_reserved(self) -> bool:
        """
        Check if IPv6 address belongs to a special-purpose
        prefix from the IANA IPv6 Special-Purpose Address
        Registry (RFC 8190 / RFC 6890) that is NOT already
        covered by another predicate (is_loopback,
        is_link_local, is_multicast, is_private,
        is_unspecified). Mirrors the full registry:

        - ::ffff:0:0/96     (RFC 4291 §2.5.5.2 IPv4-mapped)
        - 64:ff9b::/96      (RFC 6052 NAT64 well-known)
        - 64:ff9b:1::/48    (RFC 8215 NAT64 local-use)
        - 100::/64          (RFC 6666 Discard-Only)
        - 100:0:0:1::/64    (RFC 9780 Dummy Prefix)
        - 2001::/23         (RFC 2928 IETF Protocol Assignments,
                             subsuming TEREDO / Benchmarking /
                             AMT / AS112-v6 / ORCHIDv2 / DET and
                             the PCP / TURN / DNS-SD anycast
                             single-address assignments)
        - 2001:db8::/32     (RFC 3849 Documentation)
        - 2002::/16         (RFC 3056 6to4)
        - 2620:4f:8000::/48 (RFC 7534 Direct Delegation AS112)
        - 3fff::/20         (RFC 9637 Documentation)
        - 5f00::/16         (RFC 9602 SRv6 SIDs)

        See
        `docs/rfc/ip6/rfc8190__ipv6_special_purpose/adherence.md`
        for the per-prefix walk-through.
        """

        return (
            self.is_documentation
            or self._address & IP6__NAT64_WELL_KNOWN_PREFIX_MASK == IP6__NAT64_WELL_KNOWN_PREFIX
            or self._address & IP6__NAT64_LOCAL_PREFIX_MASK == IP6__NAT64_LOCAL_PREFIX
            or self._address & IP6__DISCARD_PREFIX_MASK == IP6__DISCARD_PREFIX
            or self._address & IP6__DUMMY_PREFIX_MASK == IP6__DUMMY_PREFIX
            or self._address & IP6__IETF_PROTOCOL_PREFIX_MASK == IP6__IETF_PROTOCOL_PREFIX
            or self._address & IP6__6TO4_PREFIX_MASK == IP6__6TO4_PREFIX
            or self._address & IP6__AS112_PREFIX_MASK == IP6__AS112_PREFIX
            or self._address & IP6__SRV6_PREFIX_MASK == IP6__SRV6_PREFIX
            or self._address & IP6__IPV4_MAPPED_PREFIX_MASK == IP6__IPV4_MAPPED_PREFIX
        )
