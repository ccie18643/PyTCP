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
This module contains the Ethernet 802.3 packet parser class.

net_proto/protocols/ethernet_802_3/ethernet_802_3__parser.py

ver 3.0.8
"""

from typing import override

from net_addr import Buffer
from net_proto.lib.packet_rx import PacketRx
from net_proto.lib.proto_parser import ProtoParser
from net_proto.protocols.ethernet_802_3.ethernet_802_3__base import Ethernet8023
from net_proto.protocols.ethernet_802_3.ethernet_802_3__errors import (
    Ethernet8023IntegrityError,
    Ethernet8023SanityError,
)
from net_proto.protocols.ethernet_802_3.ethernet_802_3__header import (
    ETHERNET_802_3__HEADER__LEN,
    ETHERNET_802_3__PAYLOAD__MAX_LEN,
    Ethernet8023Header,
)


class Ethernet8023Parser(Ethernet8023[Buffer], ProtoParser):
    """
    The Ethernet 802.3 packet parser.
    """

    _payload: Buffer

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Initialize the Ethernet 802.3 packet parser.
        """

        self._frame = packet_rx.frame

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

        packet_rx.ethernet_802_3 = self
        packet_rx.frame = self._payload

    @override
    def _validate_integrity(self) -> None:
        """
        Ensure integrity of the Ethernet 802.3 packet before parsing it.
        """

        # IEEE 802.3 / RFC 1042 — fixed 14-byte 802.3 header (6+6+2).
        if len(self._frame) < ETHERNET_802_3__HEADER__LEN:
            raise Ethernet8023IntegrityError(
                f"The minimum packet length must be {ETHERNET_802_3__HEADER__LEN} bytes. "
                f"Got: {len(self._frame)} bytes."
            )

        dlen = int.from_bytes(self._frame[12:14])
        payload_len = len(self._frame) - ETHERNET_802_3__HEADER__LEN

        # IEEE 802.3 — the 16-bit Length field MUST equal the actual MAC
        # client data length (excluding the 14-byte MAC header).
        if dlen != payload_len:
            raise Ethernet8023IntegrityError(
                f"The 'dlen' field value must equal the actual payload length. "
                f"Got: dlen={dlen}, payload_len={payload_len}."
            )

        # IEEE 802.3 — maximum MAC client data length is 1500 octets. Values
        # 1501..1535 (0x05DD..0x05FF) are the type/length ambiguous zone and
        # belong to neither 802.3 nor Ethernet II — rejected by both parsers.
        if dlen > ETHERNET_802_3__PAYLOAD__MAX_LEN:
            raise Ethernet8023IntegrityError(
                f"The 'dlen' field value must be less than or equal to {ETHERNET_802_3__PAYLOAD__MAX_LEN}. "
                f"Got: {dlen}."
            )

    @override
    def _parse(self) -> None:
        """
        Parse the Ethernet 802.3 packet.
        """

        self._header = Ethernet8023Header.from_buffer(self._frame)
        self._payload = self._frame[len(self._header) : len(self._header) + self._header.dlen]

    @override
    def _validate_sanity(self) -> None:
        """
        Ensure sanity of the Ethernet 802.3 packet after parsing it.
        """

        # IEEE 802.3 — source MAC MUST be a unicast address (group bit clear,
        # not all-ones, not all-zeros); a non-unicast 'src' is malformed.
        if self._header.src.is_unspecified:
            raise Ethernet8023SanityError(
                f"The 'src' field value {self._header.src} must not be an unspecified MAC address."
            )

        if self._header.src.is_multicast:
            raise Ethernet8023SanityError(
                f"The 'src' field value {self._header.src} must not be a multicast MAC address."
            )

        if self._header.src.is_broadcast:
            raise Ethernet8023SanityError(
                f"The 'src' field value {self._header.src} must not be a broadcast MAC address."
            )
