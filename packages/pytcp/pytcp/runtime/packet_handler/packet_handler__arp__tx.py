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
This module contains packet handler for the outbound ARP packets.

pytcp/runtime/packet_handler/packet_handler__arp__tx.py

ver 3.0.10
"""

from typing import TYPE_CHECKING

from net_addr import Ip4Address, MacAddress
from net_proto import ArpAssembler, ArpOperation, Tracker
from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus
from pytcp.stack import sysctl_iface

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2


class ArpTxHandler:
    """
    The outbound ARP packet handler for one interface.
    """

    _if: PacketHandlerL2

    def __init__(self, *, interface: PacketHandlerL2) -> None:
        """
        Bind the handler to its owning interface.
        """

        self._if = interface

    def _select_arp_spa(self, /, arp__tpa: Ip4Address) -> Ip4Address:
        """
        Pick the Sender Protocol Address for an outbound ARP
        Request to 'arp__tpa', honouring the live 'arp.announce'
        sysctl. Mode 0 (Linux default) returns the first listed
        local IP. Modes 1 and 2 prefer a local IP whose subnet
        contains the target, falling back to the first listed
        IP if none matches. Returns 0.0.0.0 when no local IPv4
        address is configured.
        """

        if not self._if._ip4_unicast:
            return Ip4Address()

        if sysctl_iface.get_for_iface("arp.announce", self._if._interface_name) in (1, 2):
            for host in self._if._ip4_ifaddr:
                if arp__tpa in host.network:
                    return host.address

        return self._if._ip4_unicast[0]

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

        self._if._packet_stats_tx.arp__pre_assemble += 1

        # Check if IPv4 protocol support is enabled, if not then silently
        # drop the packet.
        if not self._if._ip4_support:
            self._if._packet_stats_tx.arp__no_proto_support__drop += 1
            return TxStatus.DROPPED__ARP__NO_PROTOCOL_SUPPORT

        match arp__oper:
            case ArpOperation.REQUEST:
                self._if._packet_stats_tx.arp__op_request__send += 1
            case ArpOperation.REPLY:
                self._if._packet_stats_tx.arp__op_reply__send += 1
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

        return self._if._phtx_ethernet(
            ethernet__src=ethernet__src,
            ethernet__dst=ethernet__dst,
            ethernet__payload=arp_packet_tx,
        )

    def _send_arp_reply(
        self,
        *,
        arp__spa: Ip4Address,
        arp__tha: MacAddress,
        arp__tpa: Ip4Address,
        tracker: Tracker | None = None,
    ) -> None:
        """
        Send out ARP reply to respond to ARP request.
        """

        tx_status = self._if._marshal_tx(
            lambda: self._phtx_arp(
                ethernet__src=self._if._mac_unicast,
                ethernet__dst=arp__tha,
                arp__oper=ArpOperation.REPLY,
                arp__sha=self._if._mac_unicast,
                arp__spa=arp__spa,
                arp__tha=arp__tha,
                arp__tpa=arp__tpa,
                echo_tracker=tracker,
            )
        )

        if tx_status == TxStatus.PASSED__ETHERNET__TO_TX_RING:
            __debug__ and log(
                "stack",
                f"Sent out ARP Reply for {arp__spa} to {arp__tpa}",
            )
        else:
            __debug__ and log(
                "stack",
                f"Failed to send out ARP Reply for {arp__spa} to {arp__tpa}, " f"tx_status: {tx_status}",
            )

    def send_arp_request(self, *, arp__tpa: Ip4Address) -> None:
        """
        Enqueue ARP request packet with TX ring.
        """

        tx_status = self._if._marshal_tx(
            lambda: self._phtx_arp(
                ethernet__src=self._if._mac_unicast,
                ethernet__dst=MacAddress(0xFFFFFFFFFFFF),
                arp__oper=ArpOperation.REQUEST,
                arp__sha=self._if._mac_unicast,
                arp__spa=self._select_arp_spa(arp__tpa),
                arp__tha=MacAddress(),
                arp__tpa=arp__tpa,
            )
        )

        if tx_status == TxStatus.PASSED__ETHERNET__TO_TX_RING:
            __debug__ and log(
                "stack",
                f"Sent out ARP Request for {arp__tpa}",
            )
        else:
            __debug__ and log(
                "stack",
                f"Failed to send out ARP Request for {arp__tpa}, " f"tx_status: {tx_status}",
            )

    def send_arp_unicast_request(
        self,
        *,
        arp__tpa: Ip4Address,
        ethernet__dst: MacAddress,
        arp__spa: Ip4Address | None = None,
    ) -> None:
        """
        Enqueue a unicast ARP cache-refresh probe addressed to
        the cached neighbour MAC. Used by 'ArpCache' to refresh
        an entry approaching expiry without broadcasting a
        Request to the whole segment — only the actual owner
        of the IP wakes up to reply.

        'arp__spa' overrides the default sender-protocol-address
        selection (via '_select_arp_spa'). RFC 4436 §4.3 DNAv4
        callers MUST pass the candidate IPv4 address being
        verified, because at INIT-REBOOT time the candidate is
        not yet assigned to the interface and '_select_arp_spa'
        would otherwise return 0.0.0.0 — which RFC 5227 §1.1
        designates as the ACD-Probe sentinel, NOT a DNAv4 probe.
        Other callers (ArpCache cache-refresh) leave 'arp__spa'
        as None and rely on the interface-address fallback.
        """

        tx_status = self._if._marshal_tx(
            lambda: self._phtx_arp(
                ethernet__src=self._if._mac_unicast,
                ethernet__dst=ethernet__dst,
                arp__oper=ArpOperation.REQUEST,
                arp__sha=self._if._mac_unicast,
                arp__spa=arp__spa if arp__spa is not None else self._select_arp_spa(arp__tpa),
                arp__tha=MacAddress(),
                arp__tpa=arp__tpa,
            )
        )

        if tx_status == TxStatus.PASSED__ETHERNET__TO_TX_RING:
            __debug__ and log(
                "stack",
                f"Sent out unicast ARP Request for {arp__tpa} to {ethernet__dst}",
            )
        else:
            __debug__ and log(
                "stack",
                f"Failed to send out unicast ARP Request for {arp__tpa} to " f"{ethernet__dst}, tx_status: {tx_status}",
            )
