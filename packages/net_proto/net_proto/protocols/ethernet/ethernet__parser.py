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
This module contains the Ethernet II packet parser class.

net_proto/protocols/ethernet/ethernet__parser.py

ver 3.0.8
"""

from typing import override

from net_proto.lib.buffer import Buffer
from net_proto.lib.packet_rx import PacketRx
from net_proto.lib.proto_parser import ProtoParser
from net_proto.protocols.ethernet.ethernet__base import Ethernet
from net_proto.protocols.ethernet.ethernet__errors import (
    EthernetIntegrityError,
    EthernetSanityError,
)
from net_proto.protocols.ethernet.ethernet__header import (
    ETHERNET__HEADER__LEN,
    EthernetHeader,
)


class EthernetParser(Ethernet[Buffer], ProtoParser):
    """
    The Ethernet packet parser.
    """

    _payload: Buffer

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Initialize the Ethernet packet parser.
        """

        self._frame = packet_rx.frame

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

        packet_rx.ethernet = self
        packet_rx.frame = packet_rx.frame[len(self._header) :]

    @override
    def _validate_integrity(self) -> None:
        """
        Ensure integrity of the Ethernet packet before parsing it.
        """

        # RFC 894 / DIX — fixed 14-byte Ethernet II header (6+6+2).
        if len(self._frame) < ETHERNET__HEADER__LEN:
            raise EthernetIntegrityError(
                f"The minimum packet length must be {ETHERNET__HEADER__LEN} bytes. Got: {len(self._frame)} bytes."
            )

    @override
    def _parse(self) -> None:
        """
        Parse the Ethernet packet.
        """

        self._header = EthernetHeader.from_buffer(self._frame)
        self._payload = self._frame[len(self._header) :]

    @override
    def _validate_sanity(self) -> None:
        """
        Ensure sanity of the Ethernet packet after parsing it.
        """

        # IEEE 802.3 / RFC 1042 — the 16-bit field after src disambiguates DIX
        # (EtherType, value >= 0x0600) from 802.3 (Length, value < 0x0600); the
        # 802.3 framing is handled by a separate parser.
        if (value := int(self._header.type)) < 0x0600:
            raise EthernetSanityError(f"The minimum 'type' field value must be 0x0600. Got: 0x{value:04x}.")

        # IEEE 802.3 — source MAC MUST be a unicast address (group bit clear,
        # not all-ones, not all-zeros); a non-unicast 'src' is malformed.
        if self._header.src.is_unspecified:
            raise EthernetSanityError(
                f"The 'src' field value {self._header.src} must not be an unspecified MAC address."
            )

        if self._header.src.is_multicast:
            raise EthernetSanityError(f"The 'src' field value {self._header.src} must not be a multicast MAC address.")

        if self._header.src.is_broadcast:
            raise EthernetSanityError(f"The 'src' field value {self._header.src} must not be a broadcast MAC address.")
