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

# pylint: disable=protected-access
# pyright: reportPrivateUsage=false

"""
This module contains packet handler for inbound the IPv6 fragment extension header.

pytcp/runtime/packet_handler/packet_handler__ip6_frag__rx.py

ver 3.0.10
"""

import struct
from typing import TYPE_CHECKING

from net_proto import Ip6FragParser, PacketRx, PacketValidationError
from pytcp.lib.logger import log
from pytcp.protocols.ip.ip_frag import IpFragFlowId
from pytcp.protocols.ip.ip_frag_table import IpFragAddOutcome

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandler


class Ip6FragRxHandler:
    """
    Packet handler for the inbound IPv6 fragment extension header.
    """

    _if: PacketHandler

    def __init__(self, *, interface: PacketHandler) -> None:
        """
        Initialize the IPv6 fragment RX sub-handler.
        """

        self._if = interface

    def _phrx_ip6_frag(self, packet_rx: PacketRx, /) -> None:
        """
        Handle inbound IPv6 fragment extension header.
        """

        self._if._packet_stats_rx.ip6_frag__pre_parse += 1

        try:
            Ip6FragParser(packet_rx)

        except PacketValidationError as error:
            self._if._packet_stats_rx.ip6_frag__failed_parse += 1
            __debug__ and log(
                "ip6",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            return

        __debug__ and log("ip6", f"{packet_rx.tracker} - {packet_rx.ip6_frag}")

        if defragmented_packet_rx := self.__defragment_ip6_packet(packet_rx):
            self._if._packet_stats_rx.ip6_frag__defrag += 1
            if packet_rx.ip6_frag.offset == 0 and not packet_rx.ip6_frag.flag_mf:
                self._if._packet_stats_rx.ip6_frag__atomic__defrag += 1
            self._if._phrx_ip6(
                defragmented_packet_rx,
            )

    def __defragment_ip6_packet(self, packet_rx: PacketRx) -> PacketRx | None:
        """
        Defragment IPv6 packet.
        """

        __debug__ and log(
            "ip6",
            f"{packet_rx.tracker} - IPv6 packet fragment, "
            f"offset {packet_rx.ip6_frag.offset}, "
            f"len {len(packet_rx.ip6_frag.payload)}"
            f"{'' if packet_rx.ip6_frag.flag_mf else ', last'}",
        )

        result = self._if._ip6_frag_table.add_fragment(
            flow_id=IpFragFlowId(
                src=packet_rx.ip6.src,
                dst=packet_rx.ip6.dst,
                id=packet_rx.ip6_frag.id,
            ),
            offset=packet_rx.ip6_frag.offset,
            payload=packet_rx.ip6_frag.payload_bytes,
            flag_mf=packet_rx.ip6_frag.flag_mf,
            header=packet_rx.ip6.header_bytes,
            ecn=packet_rx.ip6.ecn,
        )
        if result.outcome in (IpFragAddOutcome.OVERLAP, IpFragAddOutcome.DISCARDED):
            self._if._packet_stats_rx.ip6_frag__overlap__drop += 1
            return None
        if result.outcome is IpFragAddOutcome.ECN_MIXED__DROP:
            self._if._packet_stats_rx.ip6_frag__ecn_mixed__drop += 1
            __debug__ and log(
                "ip6",
                f"{packet_rx.tracker} - <WARN>Dropping reassembled IPv6 datagram: "
                f"fragments carry inconsistent ECN bits (RFC 3168 §5.3)</>",
            )
            return None
        if result.outcome is not IpFragAddOutcome.COMPLETE:
            return None
        header_bytes = result.header
        payload = result.payload

        # Reassembled IPv6 header rewrite: rewrite Payload Length
        # (bytes 4-5), set Next Header (byte 6) to the upper-layer
        # protocol carried after the Fragment header, and patch
        # the ECN bits inside the Traffic Class field (byte 1 bits
        # 5-4, where the high two bits of TC[3:0] carry ECN) per
        # RFC 3168 §5.3.
        header = bytearray(header_bytes)
        header[1] = (header[1] & 0xCF) | ((result.ecn & 0x03) << 4)
        struct.pack_into("!H", header, 4, len(payload))
        header[6] = int(packet_rx.ip6_frag.next)
        packet_rx = PacketRx(bytes(header) + payload)
        # Mark this PacketRx as having been reassembled so the
        # ICMPv6 RX dispatch can refuse fragmented ND / SEND
        # messages per RFC 6980 §5.
        packet_rx.was_fragmented = True
        __debug__ and log(
            "ip6",
            f"{packet_rx.tracker} - Defragmented IPv6 packet, " f"payload len {len(payload)} bytes",
        )
        return packet_rx
