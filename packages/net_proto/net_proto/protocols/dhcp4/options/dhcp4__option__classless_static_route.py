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
This module contains the DHCPv4 Classless Static Route option
support code (option 121, RFC 3442).

net_proto/protocols/dhcp4/options/dhcp4__option__classless_static_route.py

ver 3.0.8
"""

from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer, Ip4Address, Ip4Mask, Ip4Network
from net_proto.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError
from net_proto.protocols.dhcp4.options.dhcp4__option import (
    DHCP4__OPTION__LEN,
    Dhcp4Option,
    Dhcp4OptionType,
)

# The DHCPv4 Classless Static Route option [RFC 3442].
#
#  Code Len Destination 1    Router 1
# +-----+---+----+-----+----+----+----+----+----+
# | 121 | n | d1 | ... | dN | r1 | r2 | r3 | r4 |
# +-----+---+----+-----+----+----+----+----+----+
#
#  Destination 2       Router 2
# +----+-----+----+----+----+----+----+
# | d1 | ... | dN | r1 | r2 | r3 | r4 |
# +----+-----+----+----+----+----+----+
#
# Each destination descriptor is a compact encoding: one octet
# giving the subnet-mask width (0-32), followed by the significant
# octets of the subnet number (width / 8, rounded up). A 4-byte
# router IP address follows each descriptor.

DHCP4__OPTION__CLASSLESS_STATIC_ROUTE__STRUCT = "! BB"
DHCP4__OPTION__CLASSLESS_STATIC_ROUTE__MIN_LEN = 5
DHCP4__OPTION__CLASSLESS_STATIC_ROUTE__ROUTER_LEN = 4
DHCP4__OPTION__CLASSLESS_STATIC_ROUTE__MAX_DATA_LEN = 255


def _significant_octet_count(prefixlen: int, /) -> int:
    """
    Get the number of significant subnet-number octets for a given
    mask width per the RFC 3442 'width / 8, rounded up' rule.
    """

    return (prefixlen + 7) // 8


def _is_well_formed_route(route: object, /) -> bool:
    """
    Get whether a 'routes' element is a well-formed
    (Ip4Network, Ip4Address) 2-tuple.
    """

    # Typed 'object' (not the field's 'tuple[Ip4Network, Ip4Address]')
    # so these are genuine runtime checks, not statically-redundant
    # ones: a caller may pass a mistyped tuple despite the field
    # annotation, and it must be rejected here rather than later on
    # 'network.prefixlen'.
    return (
        isinstance(route, tuple)
        and len(route) == 2
        and isinstance(route[0], Ip4Network)
        and isinstance(route[1], Ip4Address)
    )


@dataclass(frozen=True, kw_only=False, slots=True)
class Dhcp4OptionClasslessStaticRoute(Dhcp4Option):
    """
    The DHCPv4 Classless Static Route option support class.
    """

    type: Dhcp4OptionType = field(
        repr=False,
        init=False,
        default=Dhcp4OptionType.CLASSLESS_STATIC_ROUTE,
    )
    len: int = field(
        repr=False,
        init=False,
    )

    routes: list[tuple[Ip4Network, Ip4Address]]

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the DHCPv4 Classless Static Route option fields.
        """

        assert isinstance(self.routes, list), f"The 'routes' field must be a list. Got: {type(self.routes)!r}"

        # Defensive programmer-error guard: the field is typed
        # 'list[tuple[Ip4Network, Ip4Address]]', so mypy proves each
        # 'isinstance' operand statically true, but the runtime check
        # is load-bearing — a caller passing a wrong-shaped tuple (the
        # field annotation is advisory, not enforced) must be rejected
        # here rather than blowing up later on 'network.prefixlen'.
        assert all(_is_well_formed_route(route) for route in self.routes), (
            f"The 'routes' field must be a list of (Ip4Network, Ip4Address) tuples. "
            f"Got: {[type(route) for route in self.routes]!r}"
        )

        # RFC 3442 — "its minimum length is 5 bytes" — the option
        # must carry at least one route (a width-0 default route is
        # 1 descriptor octet + 4 router octets = 5).
        assert len(self.routes) >= 1, (
            f"The 'routes' field must carry at least 1 route (RFC 3442 minimum "
            f"length 5 octets). Got: {len(self.routes)}"
        )

        data_len = sum(
            1 + _significant_octet_count(network.prefixlen) + DHCP4__OPTION__CLASSLESS_STATIC_ROUTE__ROUTER_LEN
            for network, _ in self.routes
        )

        # The object models the logical route set, which RFC 3396
        # allows to exceed a single 255-octet option: on receive the
        # options parser concatenates the data of all option-121
        # instances (RFC 3442 mandates RFC 3396 option concatenation)
        # before decoding, so a parsed object's data may be > 255. The
        # single-octet length byte therefore constrains assembly only,
        # and that bound is enforced in '__buffer__'.

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(self, "len", DHCP4__OPTION__LEN + data_len)

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv4 Classless Static Route option log string.
        """

        return "classless_static_route " + str([f"{network} via {router}" for network, router in self.routes])

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv4 Classless Static Route option as a memoryview.
        """

        # Assembly emits a single TLV, so the data must fit the
        # single-octet length byte. PyTCP is a DHCP client and never
        # transmits option 121 (it only requests + receives it), so a
        # route set large enough to require RFC 3396 TX-side splitting
        # is a Phase-2 DHCP-server concern, not a host-stack path.
        assert (data_len := self.len - DHCP4__OPTION__LEN) <= DHCP4__OPTION__CLASSLESS_STATIC_ROUTE__MAX_DATA_LEN, (
            f"Assembling the Classless Static Route option into a single TLV requires "
            f"data <= {DHCP4__OPTION__CLASSLESS_STATIC_ROUTE__MAX_DATA_LEN} octets. Got: {data_len}"
        )

        buffer = bytearray(self.len - DHCP4__OPTION__LEN)
        offset = 0
        for network, router in self.routes:
            prefixlen = network.prefixlen
            n_sig = _significant_octet_count(prefixlen)
            buffer[offset] = prefixlen
            buffer[offset + 1 : offset + 1 + n_sig] = bytes(network.address)[:n_sig]
            buffer[offset + 1 + n_sig : offset + 1 + n_sig + DHCP4__OPTION__CLASSLESS_STATIC_ROUTE__ROUTER_LEN] = bytes(
                router
            )
            offset += 1 + n_sig + DHCP4__OPTION__CLASSLESS_STATIC_ROUTE__ROUTER_LEN

        return memoryview(bytes((int(self.type), self.len - DHCP4__OPTION__LEN)) + bytes(buffer))

    @staticmethod
    def decode_routes(data: Buffer, /) -> list[tuple[Ip4Network, Ip4Address]]:
        """
        Decode the compact RFC 3442 route list from option data.

        Operates on the data portion only (the concatenated
        descriptors + routers, with the type / length header
        stripped) so the options parser can feed it the RFC 3396
        concatenation of several option-121 instances directly.
        Raises 'Dhcp4IntegrityError' on a malformed descriptor.
        """

        routes: list[tuple[Ip4Network, Ip4Address]] = []
        offset = 0
        while offset < len(data):
            prefixlen = data[offset]
            offset += 1

            if prefixlen > 32:
                raise Dhcp4IntegrityError(
                    f"The Classless Static Route subnet-mask width must be 0-32 (RFC 3442). Got: {prefixlen}"
                )

            n_sig = _significant_octet_count(prefixlen)
            if (offset + n_sig + DHCP4__OPTION__CLASSLESS_STATIC_ROUTE__ROUTER_LEN) > len(data):
                raise Dhcp4IntegrityError(
                    "The Classless Static Route descriptor truncates the option data. "
                    f"Got: {prefixlen=}, {n_sig=}, remaining={len(data) - offset}"
                )

            # Pad the significant octets back to a full 4-byte address;
            # the Ip4Network constructor then ANDs the host bits per
            # RFC 3442 ("the subnet number ... is the logical AND of
            # the subnet number and subnet mask").
            address_bytes = bytes(data[offset : offset + n_sig]) + bytes(4 - n_sig)
            offset += n_sig
            router = Ip4Address(bytes(data[offset : offset + DHCP4__OPTION__CLASSLESS_STATIC_ROUTE__ROUTER_LEN]))
            offset += DHCP4__OPTION__CLASSLESS_STATIC_ROUTE__ROUTER_LEN

            network = Ip4Network((Ip4Address(address_bytes), Ip4Mask(f"/{prefixlen}")))
            routes.append((network, router))

        return routes

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the DHCPv4 Classless Static Route option before parsing it.
        """

        if (value := DHCP4__OPTION__LEN + buffer[1]) > len(buffer):
            raise Dhcp4IntegrityError(
                "The DHCPv4 Classless Static Route option length value must be less than or equal "
                f"to the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

        # RFC 3442 — "its minimum length is 5 bytes". The length byte
        # carries the data portion only, so the spec minimum data
        # length is 5. Reject below-minimum wire frames with a typed
        # integrity error before the constructor's dataclass assert.
        if (value := buffer[1]) < DHCP4__OPTION__CLASSLESS_STATIC_ROUTE__MIN_LEN:
            raise Dhcp4IntegrityError(
                f"The DHCPv4 Classless Static Route option minimum length is "
                f"{DHCP4__OPTION__CLASSLESS_STATIC_ROUTE__MIN_LEN} octets (RFC 3442). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv4 Classless Static Route option from buffer.
        """

        assert (value := len(buffer)) >= DHCP4__OPTION__LEN, (
            f"The minimum length of the DHCPv4 Classless Static Route option must be "
            f"{DHCP4__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Dhcp4OptionType.CLASSLESS_STATIC_ROUTE), (
            f"The DHCPv4 Classless Static Route option type must be "
            f"{Dhcp4OptionType.CLASSLESS_STATIC_ROUTE!r}. Got: {Dhcp4OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(cls.decode_routes(buffer[DHCP4__OPTION__LEN : DHCP4__OPTION__LEN + buffer[1]]))
