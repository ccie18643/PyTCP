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
This module contains the IPv6 Routing Header.

net_proto/protocols/ip6_routing/ip6_routing__header.py

ver 3.0.8
"""

import struct
from abc import ABC
from dataclasses import dataclass
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.enums import IpProto
from net_proto.lib.int_checks import is_uint8
from net_proto.lib.proto_struct import ProtoStruct
from net_proto.protocols.ip6_routing.ip6_routing__enums import Ip6RoutingType

# The IPv6 Routing Extension header [RFC 8200 §4.4].
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Next Header  |  Hdr Ext Len  |  Routing Type | Segments Left |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# .                                                               .
# .                       type-specific data                      .
# .                                                               .
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# Total header length on the wire = (Hdr Ext Len + 1) * 8 bytes.

IP6_ROUTING__HEADER__LEN = 4
IP6_ROUTING__HEADER__STRUCT = "! BBBB"


@dataclass(frozen=True, kw_only=True, slots=True)
class Ip6RoutingHeader(ProtoStruct):
    """
    The IPv6 Routing header.
    """

    next: IpProto
    hdr_ext_len: int
    routing_type: Ip6RoutingType
    segments_left: int

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the IPv6 Routing header fields.
        """

        assert isinstance(self.next, IpProto), f"The 'next' field must be an IpProto. Got: {type(self.next)!r}"

        assert is_uint8(
            self.hdr_ext_len
        ), f"The 'hdr_ext_len' field must be an 8-bit unsigned integer. Got: {self.hdr_ext_len!r}"

        assert isinstance(
            self.routing_type, Ip6RoutingType
        ), f"The 'routing_type' field must be an Ip6RoutingType. Got: {type(self.routing_type)!r}"

        assert is_uint8(
            self.segments_left
        ), f"The 'segments_left' field must be an 8-bit unsigned integer. Got: {self.segments_left!r}"

    @override
    def __len__(self) -> int:
        """
        Get the IPv6 Routing header fixed-prefix length.
        """

        return IP6_ROUTING__HEADER__LEN

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv6 Routing header as a memoryview.
        """

        struct.pack_into(
            IP6_ROUTING__HEADER__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.next),
            self.hdr_ext_len,
            int(self.routing_type),
            self.segments_left,
        )

        return memoryview(buffer)

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the IPv6 Routing header from buffer.
        """

        next, hdr_ext_len, routing_type, segments_left = struct.unpack(
            IP6_ROUTING__HEADER__STRUCT, buffer[:IP6_ROUTING__HEADER__LEN]
        )

        return cls(
            next=IpProto.from_int(next),
            hdr_ext_len=hdr_ext_len,
            routing_type=Ip6RoutingType.from_int(routing_type),
            segments_left=segments_left,
        )


class Ip6RoutingHeaderProperties(ABC):
    """
    Properties used to access the IPv6 Routing header fields.
    """

    _header: Ip6RoutingHeader

    @property
    def next(self) -> IpProto:
        """
        Get the IPv6 Routing header 'next' field.
        """

        return self._header.next

    @property
    def hdr_ext_len(self) -> int:
        """
        Get the IPv6 Routing header 'hdr_ext_len' field.
        """

        return self._header.hdr_ext_len

    @property
    def routing_type(self) -> Ip6RoutingType:
        """
        Get the IPv6 Routing header 'routing_type' field.
        """

        return self._header.routing_type

    @property
    def segments_left(self) -> int:
        """
        Get the IPv6 Routing header 'segments_left' field.
        """

        return self._header.segments_left
