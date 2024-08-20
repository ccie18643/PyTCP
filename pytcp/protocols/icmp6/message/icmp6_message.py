#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


"""
This module contains the ICMPv6 message base class.

pytcp/protocols/icmp6/message/icmp6_message.py

ver 3.0.0
"""


from __future__ import annotations

from abc import abstractmethod
from dataclasses import dataclass

from pytcp.lib.proto_enum import ProtoEnumByte
from pytcp.lib.proto_struct import ProtoStruct

# ICMPv6 message header [RFC 4443].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP6__HEADER__LEN = 4
ICMP6__HEADER__STRUCT = "! BBH"


class Icmp6Type(ProtoEnumByte):
    """
    The ICMPv6 message 'type' field values.
    """

    DESTINATION_UNREACHABLE = 1
    ECHO_REQUEST = 128
    ECHO_REPLY = 129
    ND__ROUTER_SOLICITATION = 133
    ND__ROUTER_ADVERTISEMENT = 134
    ND__NEIGHBOR_SOLICITATION = 135
    ND__NEIGHBOR_ADVERTISEMENT = 136
    MLD2__REPORT = 143


class Icmp6Code(ProtoEnumByte):
    """
    The ICMPv6 message 'code' field values.
    """


@dataclass(frozen=True, kw_only=True)
class Icmp6Message(ProtoStruct):
    """
    The ICMPv6 message base.
    """

    type: Icmp6Type
    code: Icmp6Code
    cksum: int

    @abstractmethod
    def __str__(self) -> str:
        """
        Get the ICMPv6 message log string.
        """

        raise NotImplementedError
