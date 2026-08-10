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

ver 3.0.10
"""

from typing import override

from net_proto.lib.enums import EtherType
from net_proto.lib.packet_rx import PacketRx
from net_proto.lib.proto_parser import ProtoParser
from net_proto.protocols.arp.arp__base import Arp
from net_proto.protocols.arp.arp__enums import (
    ARP__HARDWARE_LEN__ETHERNET,
    ARP__PROTOCOL_LEN__IP4,
    ArpHardwareType,
    ArpOperation,
)
from net_proto.protocols.arp.arp__errors import (
    ArpIntegrityError,
    ArpSanityError,
)
from net_proto.protocols.arp.arp__header import (
    ARP__HEADER__LEN,
    ArpHeader,
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
        Ensure integrity of the ARP packet before parsing it.
        """

        # RFC 826 "Packet format" — fixed 28-byte Ethernet/IPv4 ARP wire layout.
        if len(self._frame) < ARP__HEADER__LEN:
            raise ArpIntegrityError(
                f"The minimum packet length must be {ARP__HEADER__LEN} bytes. Got: {len(self._frame)} bytes."
            )

        # RFC 826 "Packet Reception" step 1 — "Do I have the hardware type?"
        if (hrtype := ArpHardwareType.from_bytes(self._frame[0:2])) != ArpHardwareType.ETHERNET:
            raise ArpIntegrityError(f"The 'hrtype' field value must be {ArpHardwareType.ETHERNET!r}. Got: {hrtype!r}.")

        # RFC 826 "Packet Reception" step 2 — "Do I speak the protocol?"
        if (prtype := EtherType.from_bytes(self._frame[2:4])) != EtherType.IP4:
            raise ArpIntegrityError(f"The 'prtype' field value must be {EtherType.IP4!r}. Got: {prtype!r}.")

        # RFC 826 "Generalization" pins hrlen=6 for Ethernet; RFC's "optionally check" hardened to MUST.
        if (hrlen := self._frame[4]) != ARP__HARDWARE_LEN__ETHERNET:
            raise ArpIntegrityError(f"The 'hrlen' field value must be {ARP__HARDWARE_LEN__ETHERNET}. Got: {hrlen!r}.")

        # RFC 826 — prlen=4 for IPv4; RFC's "optionally check the protocol length" hardened to MUST.
        if (prlen := self._frame[5]) != ARP__PROTOCOL_LEN__IP4:
            raise ArpIntegrityError(f"The 'prlen' field value must be {ARP__PROTOCOL_LEN__IP4}. Got: {prlen!r}.")

    @override
    def _parse(self) -> None:
        """
        Parse the ARP packet.
        """

        self._header = ArpHeader.from_buffer(self._frame)

    @override
    def _validate_sanity(self) -> None:
        """
        Ensure sanity of the ARP packet after parsing it.
        """

        # RFC 826 defines only REQUEST=1 and REPLY=2; RFC 5494 §3 reserves 0 and 65535.
        if self._header.oper.is_unknown:
            raise ArpSanityError(
                f"The 'oper' field value must be one of {ArpOperation.get_known_values()}. "
                f"Got: {int(self._header.oper)}."
            )

        # --- SHA (sender hardware address) ---
        # RFC 826 — sha is "the 48.bit ethernet address of itself" (RFC 5227 §1.1 reinforces);
        # IEEE 802.3 forbids the all-zeros, group-bit-set, or all-ones MAC as a unicast source.
        if self._header.sha.is_unspecified:
            raise ArpSanityError(f"The 'sha' field value {self._header.sha} must not be an unspecified MAC address.")

        if self._header.sha.is_multicast:
            raise ArpSanityError(f"The 'sha' field value {self._header.sha} must not be a multicast MAC address.")

        if self._header.sha.is_broadcast:
            raise ArpSanityError(f"The 'sha' field value {self._header.sha} must not be a broadcast MAC address.")

        # --- SPA (sender protocol address) ---
        # RFC 5227 §1.1 — only an ARP Probe (Request form) carries spa=0.0.0.0; a Reply with spa=0.0.0.0 is malformed.
        if self._header.oper == ArpOperation.REPLY:
            if self._header.spa.is_unspecified:
                raise ArpSanityError(
                    f"The 'spa' field value {self._header.spa} must not be an "
                    f"unspecified IPv4 address for an ARP Reply."
                )

        # RFC 1122 §3.2.1.3 — a sender's IPv4 source MUST NOT be loopback (127/8),
        # multicast (224/4), or limited broadcast (255.255.255.255).
        if self._header.spa.is_loopback:
            raise ArpSanityError(f"The 'spa' field value {self._header.spa} must not be a loopback IPv4 address.")

        if self._header.spa.is_multicast:
            raise ArpSanityError(f"The 'spa' field value {self._header.spa} must not be a multicast IPv4 address.")

        if self._header.spa.is_limited_broadcast:
            raise ArpSanityError(
                f"The 'spa' field value {self._header.spa} must not be a limited broadcast IPv4 address."
            )

        # --- TPA (target protocol address) ---
        # RFC 1112 §6.4 — IPv4 multicast maps algorithmically to MAC 01:00:5e:xx:xx:xx, bypassing ARP entirely.
        # Limited broadcast resolves to ff:ff:ff:ff:ff:ff directly; neither is ever a legitimate ARP target.
        if self._header.tpa.is_multicast:
            raise ArpSanityError(f"The 'tpa' field value {self._header.tpa} must not be a multicast IPv4 address.")

        if self._header.tpa.is_limited_broadcast:
            raise ArpSanityError(
                f"The 'tpa' field value {self._header.tpa} must not be a limited broadcast IPv4 address."
            )
