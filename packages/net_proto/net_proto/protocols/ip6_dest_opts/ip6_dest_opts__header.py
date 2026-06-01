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
This module contains the IPv6 Destination Options header.

net_proto/protocols/ip6_dest_opts/ip6_dest_opts__header.py

ver 3.0.8
"""

import struct
from abc import ABC
from dataclasses import dataclass
from typing import Self, override

from net_proto.lib.buffer import Buffer
from net_proto.lib.enums import IpProto
from net_proto.lib.int_checks import is_uint8
from net_proto.lib.proto_struct import ProtoStruct

# The IPv6 Destination Options Extension header [RFC 8200 §4.6].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Next Header  |  Hdr Ext Len  |                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
# |                                                               |
# .                                                               .
# .                            Options                            .
# .                                                               .
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# Hdr Ext Len is the header length in 8-octet units NOT including
# the first 8 octets, so total DestOpts header on the wire is
# (Hdr Ext Len + 1) * 8 bytes.

IP6_DEST_OPTS__HEADER__LEN = 2
IP6_DEST_OPTS__HEADER__STRUCT = "! BB"


@dataclass(frozen=True, kw_only=True, slots=True)
class Ip6DestOptsHeader(ProtoStruct):
    """
    The IPv6 Destination Options header.
    """

    next: IpProto
    hdr_ext_len: int

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the IPv6 Dest Opts header fields.
        """

        assert isinstance(self.next, IpProto), f"The 'next' field must be an IpProto. Got: {type(self.next)!r}"

        assert is_uint8(
            self.hdr_ext_len
        ), f"The 'hdr_ext_len' field must be an 8-bit unsigned integer. Got: {self.hdr_ext_len!r}"

    @override
    def __len__(self) -> int:
        """
        Get the IPv6 Dest Opts header length (the fixed 2-byte prefix).
        """

        return IP6_DEST_OPTS__HEADER__LEN

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv6 Dest Opts header as a memoryview.
        """

        struct.pack_into(
            IP6_DEST_OPTS__HEADER__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.next),
            self.hdr_ext_len,
        )

        return memoryview(buffer)

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the IPv6 Dest Opts header from buffer.
        """

        next, hdr_ext_len = struct.unpack(IP6_DEST_OPTS__HEADER__STRUCT, buffer[:IP6_DEST_OPTS__HEADER__LEN])

        return cls(
            next=IpProto.from_int(next),
            hdr_ext_len=hdr_ext_len,
        )


class Ip6DestOptsHeaderProperties(ABC):
    """
    Properties used to access the IPv6 Dest Opts header fields.
    """

    _header: Ip6DestOptsHeader

    @property
    def next(self) -> IpProto:
        """
        Get the IPv6 Dest Opts header 'next' field.
        """

        return self._header.next

    @property
    def hdr_ext_len(self) -> int:
        """
        Get the IPv6 Dest Opts header 'hdr_ext_len' field.
        """

        return self._header.hdr_ext_len
