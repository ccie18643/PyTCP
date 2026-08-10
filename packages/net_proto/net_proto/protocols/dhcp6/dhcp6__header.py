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
This module contains the DHCPv6 header class.

net_proto/protocols/dhcp6/dhcp6__header.py

ver 3.0.10
"""

import struct
from abc import ABC
from dataclasses import dataclass
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import is_uint24
from net_proto.lib.proto_struct import ProtoStruct
from net_proto.protocols.dhcp6.dhcp6__enums import Dhcp6MessageType

# The DHCPv6 client/server message header [RFC 8415 §8].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    msg-type   |                 transaction-id                |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# .                            options                            .
# .                           (variable)                          .
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


DHCP6__HEADER__LEN = 4
DHCP6__HEADER__STRUCT = "! B 3s"


@dataclass(frozen=True, kw_only=True, slots=True)
class Dhcp6Header(ProtoStruct):
    """
    The DHCPv6 header.
    """

    msg_type: Dhcp6MessageType
    xid: int

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the DHCPv6 header fields.
        """

        assert isinstance(
            self.msg_type, Dhcp6MessageType
        ), f"The 'msg_type' field must be a Dhcp6MessageType. Got: {type(self.msg_type)!r}"

        assert is_uint24(self.xid), f"The 'xid' field must be a 24-bit unsigned integer. Got: {self.xid!r}"

    @override
    def __len__(self) -> int:
        """
        Get the DHCPv6 header length.
        """

        return DHCP6__HEADER__LEN

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv6 header as a memoryview.
        """

        struct.pack_into(
            DHCP6__HEADER__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.msg_type),
            self.xid.to_bytes(3),
        )

        return memoryview(buffer)

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv6 header from buffer.
        """

        msg_type, xid = struct.unpack(DHCP6__HEADER__STRUCT, buffer[:DHCP6__HEADER__LEN])

        return cls(
            # Use the tolerant 'from_int' so an unknown wire 'msg-type'
            # value is materialised as UNKNOWN_n rather than raising
            # ValueError out of '_parse'; the parser's '_validate_sanity'
            # rejects unknowns under RFC 8415 §7.3.
            msg_type=Dhcp6MessageType.from_int(msg_type),
            xid=int.from_bytes(xid),
        )


class Dhcp6HeaderProperties(ABC):
    """
    Properties used to access the DHCPv6 header fields.
    """

    _header: Dhcp6Header

    @property
    def msg_type(self) -> Dhcp6MessageType:
        """
        Get the DHCPv6 header 'msg_type' field.
        """

        return self._header.msg_type

    @property
    def xid(self) -> int:
        """
        Get the DHCPv6 header 'xid' field.
        """

        return self._header.xid
