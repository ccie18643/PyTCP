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
Module contains packet handler for the outbound ARP packets.

pytcp/protocols/arp/arp__packet_handler_tx.py

ver 3.0.2
"""


from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING

from pytcp import config
from pytcp.lib.logger import log
from pytcp.lib.net_addr import Ip4Address, MacAddress
from pytcp.lib.tracker import Tracker
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.arp.arp__assembler import ArpAssembler
from pytcp.protocols.arp.arp__header import ArpOperation


class ArpPacketHandlerTx(ABC):
    """
    Packet handler for the outbound ARP packets.
    """

    if TYPE_CHECKING:
        from pytcp.lib.packet_stats import PacketStatsTx
        from pytcp.protocols.ethernet.ethernet__base import EthernetPayload

        packet_stats_tx: PacketStatsTx
        mac_unicast: MacAddress

        # pylint: disable=unused-argument

        def _phtx_ethernet(
            self,
            *,
            ethernet__src: MacAddress = MacAddress(),
            ethernet__dst: MacAddress = MacAddress(),
            ethernet__payload: EthernetPayload | None = None,
        ) -> TxStatus: ...

        # pylint: disable=missing-function-docstring

        @property
        def ip4_unicast(self) -> list[Ip4Address]: ...

    def _phtx_arp(
        self,
        *,
        ethernet__src: MacAddress,
        ethernet__dst: MacAddress,
        arp__oper: ArpOperation,
        arp__sha: MacAddress,
        arp__spa: Ip4Address,
        arp__tha: MacAddress,
        arp__tpa: Ip4Address,
        echo_tracker: Tracker | None = None,
    ) -> TxStatus:
        """
        Handle outbound ARP packets.
        """

        self.packet_stats_tx.arp__pre_assemble += 1

        # Check if IPv4 protocol support is enabled, if not then silently
        # drop the packet.
        if not config.IP4__SUPPORT_ENABLED:
            self.packet_stats_tx.arp__no_proto_support__drop += 1
            return TxStatus.DROPED__ARP__NO_PROTOCOL_SUPPORT

        match arp__oper:
            case ArpOperation.REQUEST:
                self.packet_stats_tx.arp__op_request__send += 1
            case ArpOperation.REPLY:
                self.packet_stats_tx.arp__op_reply__send += 1
            case _:
                raise ValueError(f"Invalid ARP operation: {arp__oper}")

        arp_packet_tx = ArpAssembler(
            arp__oper=arp__oper,
            arp__sha=arp__sha,
            arp__spa=arp__spa,
            arp__tha=arp__tha,
            arp__tpa=arp__tpa,
            echo_tracker=echo_tracker,
        )

        __debug__ and log("arp", f"{arp_packet_tx.tracker} - {arp_packet_tx}")

        return self._phtx_ethernet(
            ethernet__src=ethernet__src,
            ethernet__dst=ethernet__dst,
            ethernet__payload=arp_packet_tx,
        )

    def _send_arp_announcement(self, *, ip4_unicast: Ip4Address) -> None:
        """
        Send out ARP announcement to claim IP address.
        """

        tx_status = self._phtx_arp(
            ethernet__src=self.mac_unicast,
            ethernet__dst=MacAddress(0xFFFFFFFFFFFF),
            arp__oper=ArpOperation.REQUEST,
            arp__sha=self.mac_unicast,
            arp__spa=ip4_unicast,
            arp__tha=MacAddress(),
            arp__tpa=ip4_unicast,
        )

        if tx_status == TxStatus.PASSED__ETHERNET__TO_TX_RING:
            __debug__ and log(
                "stack",
                f"Sent out ARP Announcement for {ip4_unicast}",
            )
        else:
            __debug__ and log(
                "stack",
                f"Failed to send out ARP Announcement for {ip4_unicast}, "
                f"tx_status: {tx_status}",
            )

    def _send_gratitous_arp(self, *, ip4_unicast: Ip4Address) -> None:
        """
        Send out gratitous arp.
        """

        tx_status = self._phtx_arp(
            ethernet__src=self.mac_unicast,
            ethernet__dst=MacAddress(0xFFFFFFFFFFFF),
            arp__oper=ArpOperation.REPLY,
            arp__sha=self.mac_unicast,
            arp__spa=ip4_unicast,
            arp__tha=MacAddress(),
            arp__tpa=ip4_unicast,
        )

        if tx_status == TxStatus.PASSED__ETHERNET__TO_TX_RING:
            __debug__ and log(
                "stack",
                f"Sent out Gratitous ARP for {ip4_unicast}",
            )
        else:
            __debug__ and log(
                "stack",
                f"Failed to send out Gratitous ARP for {ip4_unicast}, "
                f"tx_status: {tx_status}",
            )

    def _send_arp_probe(self, *, ip4_unicast: Ip4Address) -> None:
        """
        Send out ARP probe to detect possible IP conflict.
        """

        tx_status = self._phtx_arp(
            ethernet__src=self.mac_unicast,
            ethernet__dst=MacAddress(0xFFFFFFFFFFFF),
            arp__oper=ArpOperation.REQUEST,
            arp__sha=self.mac_unicast,
            arp__spa=Ip4Address(),
            arp__tha=MacAddress(),
            arp__tpa=ip4_unicast,
        )

        if tx_status == TxStatus.PASSED__ETHERNET__TO_TX_RING:
            __debug__ and log(
                "stack",
                f"Sent out ARP probe for {ip4_unicast}",
            )
        else:
            __debug__ and log(
                "stack",
                f"Failed to send out ARP probe for {ip4_unicast}, "
                f"tx_status: {tx_status}",
            )

    def send_arp_request(self, *, arp__tpa: Ip4Address) -> None:
        """
        Enqueue ARP request packet with TX ring.
        """

        tx_status = self._phtx_arp(
            ethernet__src=self.mac_unicast,
            ethernet__dst=MacAddress(0xFFFFFFFFFFFF),
            arp__oper=ArpOperation.REQUEST,
            arp__sha=self.mac_unicast,
            arp__spa=(
                self.ip4_unicast[0] if self.ip4_unicast else Ip4Address()
            ),
            arp__tha=MacAddress(),
            arp__tpa=arp__tpa,
        )

        if tx_status == TxStatus.PASSED__ETHERNET__TO_TX_RING:
            __debug__ and log(
                "stack",
                f"Sent out ARP Request for {arp__tpa}",
            )
        else:
            __debug__ and log(
                "stack",
                f"Failed to send out ARP Request for {arp__tpa}, "
                f"tx_status: {tx_status}",
            )
