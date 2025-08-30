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
This module contains the ARP packet parser class.

net_proto/protocols/arp/arp__parser.py

ver 3.0.4
"""


from typing import override

from net_proto.lib.enums import EtherType
from net_proto.lib.packet_rx import PacketRx
from net_proto.lib.proto_parser import ProtoParser
from net_proto.protocols.arp.arp__base import Arp
from net_proto.protocols.arp.arp__errors import (
    ArpIntegrityError,
    ArpSanityError,
)
from net_proto.protocols.arp.arp__header import (
    ARP__HARDWARE_LEN__ETHERNET,
    ARP__HEADER__LEN,
    ARP__PROTOCOL_LEN__IP4,
    ArpHardwareType,
    ArpHeader,
    ArpOperation,
)


class ArpParser(Arp, ProtoParser):
    """
    The ARP packet parser.
    """

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Initialize the ARP packet parser.
        """

        self._frame = packet_rx.frame

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

        packet_rx.arp = self
        packet_rx.frame = packet_rx.frame[len(self._header) :]

    @override
    def _validate_integrity(self) -> None:
        """
        Validate integrity of the ARP packet before parsing it.
        """

        if len(self._frame) < ARP__HEADER__LEN:
            raise ArpIntegrityError(
                f"The minimum packet length must be {ARP__HEADER__LEN} "
                f"bytes, got {len(self._frame)} bytes."
            )

        if (
            hrtype := ArpHardwareType.from_bytes(self._frame[0:2])
        ) != ArpHardwareType.ETHERNET:
            raise ArpIntegrityError(
                f"The 'hrtype' field value must be {ArpHardwareType.ETHERNET!r}. "
                f"Got: {hrtype!r}."
            )

        if (prtype := EtherType.from_bytes(self._frame[2:4])) != EtherType.IP4:
            raise ArpIntegrityError(
                f"The 'prtype' field value must be {EtherType.IP4!r}. "
                f"Got: {prtype!r}."
            )

        if (hrlen := self._frame[4]) != ARP__HARDWARE_LEN__ETHERNET:
            raise ArpIntegrityError(
                f"The 'hrlen' field value must be {ARP__HARDWARE_LEN__ETHERNET}, "
                f"got {hrlen!r}."
            )

        if (prlen := self._frame[5]) != ARP__PROTOCOL_LEN__IP4:
            raise ArpIntegrityError(
                f"The 'prlen' field value must be {ARP__PROTOCOL_LEN__IP4}, "
                f"got {prlen!r}."
            )

    @override
    def _parse(self) -> None:
        """
        Parse the ARP packet.
        """

        self._header = ArpHeader.from_bytes(self._frame)

    @override
    def _validate_sanity(self) -> None:
        """
        Validate sanity of the ARP packet after parsing it.
        """

        if self._header.oper.is_unknown:
            raise ArpSanityError(
                "The 'oper' field value must be one of "
                f"{ArpOperation.get_known_values()}, got {int(self._header.oper)}."
            )
