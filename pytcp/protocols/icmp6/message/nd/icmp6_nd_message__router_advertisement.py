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
This Module contains ICMPv6 ND Router Advertisement message support class.

pytcp/protocols/icmp6/message/nd/icmp6_nd_message__router_advertisement.py

ver 3.0.0 - Refactor needed for the 'from_bytes()' method.
"""


from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import override

from pytcp.lib.int_checks import is_uint8, is_uint16, is_uint32
from pytcp.protocols.icmp6.message.icmp6_message import Icmp6Code, Icmp6Type
from pytcp.protocols.icmp6.message.nd.icmp6_nd_message import Icmp6NdMessage
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_options import (
    Icmp6NdOptions,
)

# The ICMPv6 ND Router Advertisement message (134/0) [RFC4861].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Hop Limit   |M|O|H|PRF|P|0|0|        Router Lifetime        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                          Reachable Time                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Retrans Timer                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                                                               ~
# ~                            Options                            ~
# ~                                                               ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


ICMP6__ND__ROUTER_ADVERTISEMENT__LEN = 16
ICMP6__ND__ROUTER_ADVERTISEMENT__STRUCT = "! BBH BBH L L"


class Icmp6NdRouterAdvertisementCode(Icmp6Code):
    """
    The ICMPv6 ND Router Advertisement message 'code' values.
    """

    DEFAULT = 0


@dataclass(frozen=True, kw_only=True)
class Icmp6NdRouterAdvertisementMessage(Icmp6NdMessage):
    """
    The ICMPv6 ND Router Advertisement message.
    """

    type: Icmp6Type = field(
        repr=False, init=False, default=Icmp6Type.ND__ROUTER_ADVERTISEMENT
    )
    code: Icmp6NdRouterAdvertisementCode = (
        Icmp6NdRouterAdvertisementCode.DEFAULT
    )
    cksum: int = 0

    hop: int
    flag_m: bool = False
    flag_o: bool = False
    router_lifetime: int
    reachable_time: int
    retrans_timer: int
    options: Icmp6NdOptions

    @override
    def __post_init__(self) -> None:
        """
        Validate the ICMPv6 ND Router Advertisement message fields.
        """

        assert isinstance(
            self.code, Icmp6NdRouterAdvertisementCode
        ), f"The 'code' field must be an Icmp6NdRouterAdvertisementCode. Got: {type(self.code)!r}"

        assert is_uint16(
            self.cksum
        ), f"The 'cksum' field must be a 16-bit unsigned integer. Got: {self.cksum!r}"

        assert is_uint8(
            self.hop
        ), f"The 'hop' field must be a 8-bit unsigned integer. Got: {self.hop!r}"

        assert isinstance(
            self.flag_m, bool
        ), f"The 'flag_m' field must be a boolean. Got: {type(self.flag_m)!r}"

        assert isinstance(
            self.flag_o, bool
        ), f"The 'flag_o' field must be a boolean. Got: {type(self.flag_o)!r}"

        assert is_uint16(
            self.router_lifetime
        ), f"The 'router_lifetime' field must be a 16-bit unsigned integer. Got: {self.router_lifetime!r}"

        assert is_uint32(
            self.reachable_time
        ), f"The 'reachable_time' field must be a 32-bit unsigned integer. Got: {self.reachable_time!r}"

        assert is_uint32(
            self.retrans_timer
        ), f"The 'retrans_timer' field must be a 32-bit unsigned integer. Got: {self.retrans_timer!r}"

        assert isinstance(
            self.options, Icmp6NdOptions
        ), f"The 'options' field must be an Icmp6NdOptions. Got: {type(self.options)!r}"

    @override
    def __len__(self) -> int:
        """
        Get the ICMPv6 ND Router Advertisement message length.
        """

        return ICMP6__ND__ROUTER_ADVERTISEMENT__LEN + len(self.options)

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 ND Router Advertisement message log string.
        """

        return (
            f"ICMPv6 ND Router Advertisement, hop {self.hop}, flags "
            f"{'M' if self.flag_m else '-'}{'O' if self.flag_o else '-'}, "
            f"rlft {self.router_lifetime}, reacht {self.reachable_time}, "
            f"retrt {self.retrans_timer}, opts [{self.options}], "
            f"len {len(self)} ({ICMP6__ND__ROUTER_ADVERTISEMENT__LEN}+{len(self.options)})"
        )

    @override
    def __bytes__(self) -> bytes:
        """
        Get the ICMPv6 ND Router Advertisement message as bytes.
        """

        return struct.pack(
            ICMP6__ND__ROUTER_ADVERTISEMENT__STRUCT,
            int(self.type),
            int(self.code),
            0,
            self.hop,
            (self.flag_m << 7) | (self.flag_o << 6),
            self.router_lifetime,
            self.reachable_time,
            self.retrans_timer,
        ) + bytes(self.options)

    @staticmethod
    def from_bytes(_bytes: bytes) -> Icmp6NdRouterAdvertisementMessage:
        """
        Initialize the ICMPv6 ND Router Advertisement message from bytes.
        """

        assert (
            Icmp6Type.from_bytes(_bytes[0:1])
            == Icmp6Type.ND__ROUTER_ADVERTISEMENT
        ), (
            f"The 'type' field must be {Icmp6Type.ND__ROUTER_ADVERTISEMENT!r}. "
            f"Got: {Icmp6Type.from_bytes(_bytes[0:1])!r}"
        )

        # TODO: Refactor this code after unit tests are implemented.

        return Icmp6NdRouterAdvertisementMessage(
            hop=_bytes[4],
            flag_m=bool(_bytes[5] & 0b10000000),
            flag_o=bool(_bytes[5] & 0b01000000),
            router_lifetime=int.from_bytes(_bytes[6:8]),
            reachable_time=int.from_bytes(_bytes[8:12]),
            retrans_timer=int.from_bytes(_bytes[12:16]),
            options=Icmp6NdOptions.from_bytes(
                _bytes[ICMP6__ND__ROUTER_ADVERTISEMENT__LEN:]
            ),
        )
