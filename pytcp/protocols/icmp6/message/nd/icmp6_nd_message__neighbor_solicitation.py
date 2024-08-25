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
This module contains the ICMPv6 ND Neighbor Solicitation message support class.

pytcp/protocols/icmp6/message/nd/icmp6_nd_message__neighbor_solicitation.py

ver 3.0.0
"""


from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import override

from pytcp.lib.int_checks import is_uint16
from pytcp.lib.ip6_address import Ip6Address
from pytcp.protocols.icmp6.message.icmp6_message import Icmp6Code, Icmp6Type
from pytcp.protocols.icmp6.message.nd.icmp6_nd_message import Icmp6NdMessage
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_options import (
    Icmp6NdOptions,
)

# The ICMPv6 ND Neighbor Solicitation message (135/0) [RFC4861].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Reserved                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +                                                               +
# >                                                               >
# +                       Target Address                          +
# >                                                               >
# +                                                               +
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                                                               ~
# ~                          Options                              ~
# ~                                                               ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


ICMP6__ND__NEIGHBOR_SOLICITATION__LEN = 24
ICMP6__ND__NEIGHBOR_SOLICITATION__STRUCT = "! BBH L 16s"


class Icmp6NdNeighborSolicitationCode(Icmp6Code):
    """
    The ICMPv6 ND Neighbor Solicitation message 'code' values.
    """

    DEFAULT = 0


@dataclass(frozen=True, kw_only=True)
class Icmp6NdNeighborSolicitationMessage(Icmp6NdMessage):
    """
    The ICMPv6 ND Neighbor Solicitation message.
    """

    type: Icmp6Type = field(
        repr=False,
        init=False,
        default=Icmp6Type.ND__NEIGHBOR_SOLICITATION,
    )
    code: Icmp6NdNeighborSolicitationCode = (
        Icmp6NdNeighborSolicitationCode.DEFAULT
    )
    cksum: int = 0

    target_address: Ip6Address
    options: Icmp6NdOptions

    @override
    def __post_init__(self) -> None:
        """
        Validate the ICMPv6 ND Neighbor Solicitation message fields.
        """

        assert isinstance(
            self.code, Icmp6NdNeighborSolicitationCode
        ), f"The 'code' field must be an Icmp6NdNeighborSolicitationCode. Got: {type(self.code)!r}"

        assert is_uint16(
            self.cksum
        ), f"The 'cksum' field must be a 16-bit unsigned integer. Got: {self.cksum!r}"

        assert isinstance(
            self.target_address, Ip6Address
        ), f"The 'target_address' field must be an Ip6Address. Got: {type(self.target_address)!r}"

        assert isinstance(
            self.options, Icmp6NdOptions
        ), f"The 'options' field must be an Icmp6NdOptions. Got: {type(self.options)!r}"

    @override
    def __len__(self) -> int:
        """
        Get the ICMPv6 ND Neighbor Solicitation message length.
        """

        return ICMP6__ND__NEIGHBOR_SOLICITATION__LEN + len(self.options)

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 ND Neighbor Solicitation message log string.
        """

        return (
            f"ICMP6 ND Neighbor Solicitation, "
            f"target {self.target_address}, opts [{self.options}], "
            f"len {len(self)} ({ICMP6__ND__NEIGHBOR_SOLICITATION__LEN}+"
            f"{len(self.options)})"
        )

    @override
    def __bytes__(self) -> bytes:
        """
        Get the ICMPv6 ND Neighbor Solicitation message as bytes.
        """

        return struct.pack(
            ICMP6__ND__NEIGHBOR_SOLICITATION__STRUCT,
            int(self.type),
            int(self.code),
            0,
            0,
            bytes(self.target_address),
        ) + bytes(self.options)

    @override
    @staticmethod
    def from_bytes(_bytes: bytes) -> Icmp6NdNeighborSolicitationMessage:
        """
        Initialize the ICMPv6 ND Neighbor Solicitation message from bytes.
        """

        type, code, cksum, _, target_address = struct.unpack(
            ICMP6__ND__NEIGHBOR_SOLICITATION__STRUCT,
            _bytes[:ICMP6__ND__NEIGHBOR_SOLICITATION__LEN],
        )

        assert (received_type := Icmp6Type.from_int(type)) == (
            valid_type := Icmp6Type.ND__NEIGHBOR_SOLICITATION
        ), f"The 'type' field must be {valid_type!r}. Got: {received_type!r}"

        return Icmp6NdNeighborSolicitationMessage(
            code=Icmp6NdNeighborSolicitationCode(code),
            cksum=cksum,
            target_address=Ip6Address(target_address),
            options=Icmp6NdOptions.from_bytes(
                _bytes[ICMP6__ND__NEIGHBOR_SOLICITATION__LEN:]
            ),
        )
