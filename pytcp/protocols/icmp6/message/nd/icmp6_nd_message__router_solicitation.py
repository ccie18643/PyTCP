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
Module contains the ICMPv6 ND Router Solicitation message support class.

pytcp/protocols/icmp6/message/nd/icmp6_nd_message__router_solicitation.py

ver 3.0.1
"""


from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import override

from pytcp.lib.int_checks import is_uint16
from pytcp.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from pytcp.protocols.icmp6.message.icmp6_message import Icmp6Code, Icmp6Type
from pytcp.protocols.icmp6.message.nd.icmp6_nd_message import Icmp6NdMessage
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_options import (
    Icmp6NdOptions,
)

# The ICMPv6 ND Router Solicitation message (133/0) [RFC4861].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                            Reserved                           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                                                               ~
# ~                            Options                            ~
# ~                                                               ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


ICMP6__ND__ROUTER_SOLICITATION__LEN = 8
ICMP6__ND__ROUTER_SOLICITATION__STRUCT = "! BBH L"


class Icmp6NdRouterSolicitationCode(Icmp6Code):
    """
    The ICMPv6 ND Router Solicitation message 'code' values.
    """

    DEFAULT = 0


@dataclass(frozen=True, kw_only=True)
class Icmp6NdRouterSolicitationMessage(Icmp6NdMessage):
    """
    The ICMPv6 ND Router Solicitation message.
    """

    type: Icmp6Type = field(
        repr=False,
        init=False,
        default=Icmp6Type.ND__ROUTER_SOLICITATION,
    )
    code: Icmp6NdRouterSolicitationCode = Icmp6NdRouterSolicitationCode.DEFAULT
    cksum: int = 0

    options: Icmp6NdOptions

    @override
    def __post_init__(self) -> None:
        """
        Validate the ICMPv6 ND Router Solicitation message fields.
        """

        assert isinstance(self.code, Icmp6NdRouterSolicitationCode), (
            f"The 'code' field must be an Icmp6NdRouterSolicitationCode. "
            f"Got: {type(self.code)!r}"
        )

        assert is_uint16(self.cksum), (
            f"The 'cksum' field must be a 16-bit unsigned integer. "
            f"Got: {self.cksum!r}"
        )

        assert isinstance(self.options, Icmp6NdOptions), (
            f"The 'options' field must be an Icmp6NdOptions. "
            f"Got: {type(self.options)!r}"
        )

    @override
    def __len__(self) -> int:
        """
        Get the ICMPv6 ND Router Solicitation messeage length.
        """

        return ICMP6__ND__ROUTER_SOLICITATION__LEN + len(self.options)

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 ND Router Solicitation message log string.
        """

        return (
            f"ICMPv6 ND Router Solicitation"
            f"{f', opts [{self.options}]' if self.options else ''}"
            f", len {len(self)} ({ICMP6__ND__ROUTER_SOLICITATION__LEN}+"
            f"{len(self.options)})"
        )

    @override
    def __bytes__(self) -> bytes:
        """
        Get the ICMPv6 ND Router Solicitation message as bytes.
        """

        return struct.pack(
            ICMP6__ND__ROUTER_SOLICITATION__STRUCT,
            int(self.type),
            int(self.code),
            0,
            0,
        ) + bytes(self.options)

    @override
    @staticmethod
    def validate_integrity(*, frame: bytes, ip6__dlen: int) -> None:
        """
        Validate integrity of the ICMPv6 ND Router Solicitation message
        before parsing it.
        """

        if not (ICMP6__ND__ROUTER_SOLICITATION__LEN <= ip6__dlen <= len(frame)):
            raise Icmp6IntegrityError(
                "The condition 'ICMP6__ND__ROUTER_SOLICITATION__LEN <= ip6__dlen "
                f"<= len(frame)' must be met. Got: {ICMP6__ND__ROUTER_SOLICITATION__LEN=}, "
                f"{ip6__dlen=}, {len(frame)=}"
            )

        Icmp6NdOptions.validate_integrity(
            frame=frame,
            offset=ICMP6__ND__ROUTER_SOLICITATION__LEN,
        )

    @override
    @staticmethod
    def from_bytes(_bytes: bytes) -> Icmp6NdRouterSolicitationMessage:
        """
        Initialize the ICMPv6 ND Router Solicitation message from bytes.
        """

        type, code, cksum, _ = struct.unpack(
            ICMP6__ND__ROUTER_SOLICITATION__STRUCT,
            _bytes[:ICMP6__ND__ROUTER_SOLICITATION__LEN],
        )

        assert (received_type := Icmp6Type.from_int(type)) == (
            valid_type := Icmp6Type.ND__ROUTER_SOLICITATION
        ), (
            f"The 'type' field must be {valid_type!r}. "
            f"Got: {received_type!r}"
        )

        return Icmp6NdRouterSolicitationMessage(
            code=Icmp6NdRouterSolicitationCode(code),
            cksum=cksum,
            options=Icmp6NdOptions.from_bytes(
                _bytes[ICMP6__ND__ROUTER_SOLICITATION__LEN:]
            ),
        )
