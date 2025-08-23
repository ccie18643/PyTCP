#!/usr/bin/env python3

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

pytcp/protocols/icmp4/message/icmp4_message.py

ver 3.0.3
"""


from abc import abstractmethod
from dataclasses import dataclass

from pytcp.lib.proto_enum import ProtoEnumByte
from pytcp.lib.proto_struct import ProtoStruct

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

    ECHO_REPLY = 0
    DESTINATION_UNREACHABLE = 3
    ECHO_REQUEST = 8


class Icmp4Code(ProtoEnumByte):
    """
    The ICMPv4 message 'code' field values.
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
    def validate_sanity(self) -> None:
        """
        Validate the ICMPv4 message sanity.
        """

        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def validate_integrity(*, frame: bytes, ip4__payload_len: int) -> None:
        """
        Validate the ICMPv4 message integrity.
        """

        raise NotImplementedError
