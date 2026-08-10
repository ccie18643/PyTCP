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
This module contains the ICMPv4 message base class.

net_proto/protocols/icmp4/message/icmp4__message.py

ver 3.0.10
"""

from abc import abstractmethod
from dataclasses import dataclass

from net_addr import Buffer
from net_proto.lib.proto_enum import ProtoEnumByte
from net_proto.lib.proto_struct import ProtoStruct

# The ICMPv4 message header [RFC 792].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP4__HEADER__LEN = 4
ICMP4__HEADER__STRUCT = "! BBH"


class Icmp4Type(ProtoEnumByte):
    """
    The ICMPv4 message 'type' field values.
    """

    ECHO_REPLY = 0  # RFC 792 §"Echo or Echo Reply Message".
    DESTINATION_UNREACHABLE = 3  # RFC 792 §"Destination Unreachable Message".
    REDIRECT = 5  # RFC 792 §"Redirect Message".
    ECHO_REQUEST = 8  # RFC 792 §"Echo or Echo Reply Message".
    TIME_EXCEEDED = 11  # RFC 792 §"Time Exceeded Message".
    PARAMETER_PROBLEM = 12  # RFC 792 §"Parameter Problem Message".


class Icmp4Code(ProtoEnumByte):
    """
    Base class for ICMPv4 'code' field enums. Concrete code values
    are defined by each message type's subclass.
    """


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp4Message(ProtoStruct):
    """
    The ICMPv4 message base.
    """

    type: Icmp4Type
    code: Icmp4Code
    cksum: int

    @abstractmethod
    def _pack_header(self, buffer_len: int, /) -> bytearray:
        """
        Get the ICMPv4 message header as bytes.
        """

        raise NotImplementedError

    @abstractmethod
    def validate_sanity(self) -> None:
        """
        Ensure sanity of the ICMPv4 message.
        """

        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def validate_integrity(*, frame: Buffer, ip4__payload_len: int) -> None:
        """
        Ensure integrity of the ICMPv4 message.
        """

        raise NotImplementedError

    @abstractmethod
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the ICMPv4 message.
        """

        raise NotImplementedError
