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

# pylint: disable = too-many-instance-attributes
# pylint: disable = too-many-locals
# pylint: disable = too-many-return-statements
# pylint: disable = too-many-arguments
# pylint: disable = redefined-builtin

"""
Module contains Fast Packet Assembler support class for the ICMPv6 protocol.

pytcp/protocols/icmp6/fpa.py

ver 2.7
"""


from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from pytcp.lib.ip6_address import Ip6Address, Ip6Network
from pytcp.lib.ip_helper import inet_cksum
from pytcp.lib.tracker import Tracker
from pytcp.protocols.icmp6.ps import (
    ICMP6_MESSAGE_LEN__ECHO_REPLY,
    ICMP6_MESSAGE_LEN__ECHO_REQUEST,
    ICMP6_MESSAGE_LEN__UNREACHABLE,
    ICMP6_UNREACHABLE_ORIGINAL_DATAGRAM_LEN,
    Icmp6,
    Icmp6EchoReplyMessage,
    Icmp6EchoRequestMessage,
    Icmp6Message,
    Icmp6Mld2AddressRecord,
    Icmp6Mld2RecordType,
    Icmp6Mld2ReportMessage,
    Icmp6NdNeighborAdvertisementMessage,
    Icmp6NdNeighborSolicitationMessage,
    Icmp6NdOpt,
    Icmp6NdOptPi,
    Icmp6NdOptSlla,
    Icmp6NdOptTlla,
    Icmp6NdRouterAdvertisementMessage,
    Icmp6NdRouterSolicitationMessage,
    Icmp6PortUnreachableMessage,
)
from pytcp.protocols.ip6.ps import IP6_HEADER_LEN, IP6_NEXT_ICMP6

if TYPE_CHECKING:
    from pytcp.lib.mac_address import MacAddress


class Icmp6Assembler(Icmp6):
    """
    ICMPv6 packet assembler support class.
    """

    ip6_next = IP6_NEXT_ICMP6

    def __init__(
        self,
        *,
        message: Icmp6Message,
        echo_tracker: Tracker | None = None,
    ) -> None:
        """
        Create the ICMPv6 packet assembler object.
        """

        self._tracker = Tracker(prefix="TX", echo_tracker=echo_tracker)
        self._message = message

    def __len__(self) -> int:
        """
        Length of the packet.
        """

        return len(self._message)

    def __str__(self) -> str:
        """
        Packet log string.
        """

        return str(self._message)

    @property
    def tracker(self) -> Tracker:
        """
        Get the '_tracker' attribute.
        """

        return self._tracker

    def assemble(self, /, frame: memoryview, pshdr_sum: int = 0) -> None:
        """
        Write packet into the provided frame.
        """

        struct.pack_into(f"{len(self)}s", frame, 0, bytes(self))
        struct.pack_into("! H", frame, 2, inet_cksum(frame, pshdr_sum))


#
#  The ICMPv6 message assembler classes.
#


class Icmp6PortUnreachableMessageAssembler(Icmp6PortUnreachableMessage):
    """
    Assembler class for the ICMPv6 Port Unreachable message.
    """

    def __init__(self, *, data: bytes = b"") -> None:
        """
        Create the ICMPv6 Port Unreachable message assembler object.
        """

        assert (
            len(data)
            <= 0xFFFF - IP6_HEADER_LEN - ICMP6_MESSAGE_LEN__UNREACHABLE
        )

        self._reserved = 0
        self._data = data[:ICMP6_UNREACHABLE_ORIGINAL_DATAGRAM_LEN]


class Icmp6EchoRequestMessageAssembler(Icmp6EchoRequestMessage):
    """
    Assembler class for the ICMPv6 Echo Request message.
    """

    def __init__(self, *, id: int, seq: int, data: bytes) -> None:
        """
        Create the ICMPv6 Echo Request message assembler object.
        """

        assert 0 <= id <= 0xFFFF
        assert 0 <= seq <= 0xFFFF
        assert (
            len(data)
            <= 0xFFFF - IP6_HEADER_LEN - ICMP6_MESSAGE_LEN__ECHO_REQUEST
        )

        self._id = id
        self._seq = seq
        self._data = data


class Icmp6EchoReplyMessageAssembler(Icmp6EchoReplyMessage):
    """
    Assembler class for the ICMPv6 Echo Reply message.
    """

    def __init__(self, *, id: int, seq: int, data: bytes) -> None:
        """
        Create the ICMPv6 Echo Reply message assembler object.
        """

        assert 0 <= id <= 0xFFFF
        assert 0 <= seq <= 0xFFFF
        assert (
            len(data) <= 0xFFFF - IP6_HEADER_LEN - ICMP6_MESSAGE_LEN__ECHO_REPLY
        )

        self._id = id
        self._seq = seq
        self._data = data


class Icmp6NdRouterSolicitationMessageAssembler(
    Icmp6NdRouterSolicitationMessage
):
    """
    Assembler class for the ICMPv6 ND Router Soliciation message.
    """

    def __init__(self, *, nd_options: list[Icmp6NdOpt]) -> None:
        """
        Create the message object.
        """

        self._reserved = 0
        self._nd_options = nd_options


class Icmp6NdRouterAdvertisementMessageAssembler(
    Icmp6NdRouterAdvertisementMessage
):
    """
    Assembler class for the ICMPv6 ND Router Advertisement message.
    """

    def __init__(
        self,
        *,
        hop: int,
        flag_m: bool,
        flag_o: bool,
        router_lifetime: int,
        reachable_time: int,
        retrans_timer: int,
        nd_options: list[Icmp6NdOpt],
    ) -> None:
        """
        Create the message object.
        """

        assert 0 <= hop <= 0xFF
        assert 0 <= router_lifetime <= 0xFFFF
        assert 0 <= reachable_time <= 0xFFFFFFFF
        assert 0 <= retrans_timer <= 0xFFFFFFFF

        self._hop = hop
        self._flag_m = flag_m
        self._flag_o = flag_o
        self._router_lifetime = router_lifetime
        self._reachable_time = reachable_time
        self._retrans_timer = retrans_timer
        self._nd_options = nd_options


class Icmp6NdNeighborSolicitationMessageAssembler(
    Icmp6NdNeighborSolicitationMessage
):
    """
    Assembler class for the ICMPv6 ND Neighbor Soliciation message.
    """

    def __init__(
        self, *, target_address: Ip6Address, nd_options: list[Icmp6NdOpt]
    ) -> None:
        """
        Create the message object.
        """

        self._reserved = 0
        self._target_address = target_address
        self._nd_options = nd_options


class Icmp6NdNeighborAdvertisementMessageAssembler(
    Icmp6NdNeighborAdvertisementMessage
):
    """
    Assembler class for the ICMPv6 ND Neighbor Advertisement message.
    """

    def __init__(
        self,
        *,
        flag_r: bool = False,
        flag_s: bool = False,
        flag_o: bool = False,
        target_address: Ip6Address,
        nd_options: list[Icmp6NdOpt],
    ) -> None:
        """
        Create the message object.
        """

        self._reserved = 0
        self._flag_r = flag_r
        self._flag_s = flag_s
        self._flag_o = flag_o
        self._target_address = target_address
        self._nd_options = nd_options


class Icmp6Mld2ReportMessageAssembler(Icmp6Mld2ReportMessage):
    """
    Assembler class for the ICMPv6 MLD2 Report packet.
    """

    def __init__(self, *, records: list[Icmp6Mld2AddressRecord]) -> None:
        """
        Create the message object.
        """

        self._reserved = 0
        self._nor = len(records)
        self._records = records


#
#   ICMPv6 Neighbor Discovery options
#


class Icmp6NdOptSllaAssembler(Icmp6NdOptSlla):
    """
    ICMPv6 ND option assembler - Source Link Layer Address (1).
    """

    def __init__(self, *, slla: MacAddress) -> None:
        """
        Create the option object.
        """

        self._slla = slla


class Icmp6NdOptTllaAssembler(Icmp6NdOptTlla):
    """
    ICMPv6 ND option - Target Link Layer Address (2).
    """

    def __init__(self, *, tlla: MacAddress) -> None:
        """
        Create the option object.
        """

        self._tlla = tlla


class Icmp6NdOptPiAssembler(Icmp6NdOptPi):
    """
    ICMPv6 ND option assembler - Prefix Information (3).
    """

    def __init__(
        self,
        *,
        flag_l: bool = False,
        flag_a: bool = False,
        flag_r: bool = False,
        valid_lifetime: int,
        prefer_lifetime: int,
        prefix: Ip6Network,
    ) -> None:
        """
        Option constructor.
        """

        assert 0 <= valid_lifetime <= 0xFFFFFFFF
        assert 0 <= prefer_lifetime <= 0xFFFFFFFF

        self._flag_l = flag_l
        self._flag_a = flag_a
        self._flag_r = flag_r
        self._valid_lifetime = valid_lifetime
        self._prefer_lifetime = prefer_lifetime
        self._prefix = prefix


#
#   ICMPv6 MLD2 Multicast support classes
#


class Icmp6Mld2AddressRecordAssembler(Icmp6Mld2AddressRecord):
    """
    Multicast Address Record used by MLDv2 Report message - assembler.
    """

    def __init__(
        self,
        *,
        record_type: Icmp6Mld2RecordType,
        multicast_address: Ip6Address,
        source_addresses: list[Ip6Address] | None = None,
        aux_data: bytes | None = None,
    ) -> None:
        """
        Create the Multicast Address Record object.
        """

        self._record_type = record_type
        self._multicast_address = multicast_address
        self._source_addresses = (
            [] if source_addresses is None else source_addresses
        )
        self._number_of_sources = len(self._source_addresses)
        self._aux_data = b"" if aux_data is None else aux_data
        self._aux_data_len = len(self._aux_data)
