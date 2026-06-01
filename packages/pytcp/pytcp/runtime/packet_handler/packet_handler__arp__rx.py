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
This module contains packet handler for the inbound ARP packets.

pytcp/runtime/packet_handler/packet_handler__arp__rx.py

ver 3.0.8
"""

from typing import TYPE_CHECKING

from net_proto import ArpOperation, ArpParser, PacketRx, PacketValidationError
from pytcp.lib.logger import log
from pytcp.stack import sysctl_iface

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2


class ArpRxHandler:
    """
    The inbound ARP packet handler for one interface.
    """

    _if: PacketHandlerL2

    def __init__(self, *, interface: PacketHandlerL2) -> None:
        """
        Bind the handler to its owning interface.
        """

        self._if = interface

    def _phrx_arp(self, packet_rx: PacketRx, /) -> None:
        """
        Handle inbound ARP packets.
        """

        self._if._packet_stats_rx.arp__pre_parse += 1

        try:
            ArpParser(packet_rx)

        except PacketValidationError as error:
            self._if._packet_stats_rx.arp__failed_parse__drop += 1
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            return

        __debug__ and log("arp", f"{packet_rx.tracker} - {packet_rx.arp}")

        match packet_rx.arp.oper:
            case ArpOperation.REQUEST:
                self.__phrx_arp__request(packet_rx)
            case ArpOperation.REPLY:
                self.__phrx_arp__reply(packet_rx)
            case _:
                self._if._packet_stats_rx.arp__op_unknown__drop += 1
                __debug__ and log(
                    "arp",
                    f"{packet_rx.tracker} - Unsupported operation " f"{packet_rx.arp.oper}, dropping.",
                )

    def __update_arp_cache(
        self,
        *,
        packet_rx: PacketRx,
        operation: ArpOperation,
    ) -> None:
        """
        Update ARP cache with the SPA<->SHA mapping if the packet is intended for us.
        """

        # If SPA matches one of our subnets — or 'arp.accept = 1'
        # admits off-subnet senders (Linux
        # net.ipv4.conf.<iface>.arp_accept) — update ARP cache
        # with the SPA<->SHA mapping. Also ensure we update cache
        # only if the packet is either direct or broadcast to
        # avoid updating cache with packets not intended for us
        # in case the interface is in promiscuous mode. Finally,
        # do not update cache if SPA matches one of our IP
        # addresses to avoid updating cache with our own IP
        # address that could be spoofed by an attacker.
        spa_on_local_subnet = any(packet_rx.arp.spa in host.network for host in self._if._ip4_ifaddr)
        if (
            (spa_on_local_subnet or sysctl_iface.get_for_iface("arp.accept", self._if._interface_name) == 1)
            and (packet_rx.ethernet.dst == self._if._mac_unicast or packet_rx.ethernet.dst.is_broadcast)
            and packet_rx.arp.spa not in self._if._ip4_unicast
        ):
            match operation:
                case ArpOperation.REQUEST:
                    self._if._packet_stats_rx.arp__op_request__update_arp_cache += 1
                case ArpOperation.REPLY:
                    self._if._packet_stats_rx.arp__op_reply__update_arp_cache += 1
                case _:
                    raise ValueError("Invalid ARP operation")

            assert self._if._arp_cache is not None, "L2 handler updating the ARP cache must have one wired."
            self._if._arp_cache.add_entry(
                ip4_address=packet_rx.arp.spa,
                mac_address=packet_rx.arp.sha,
            )

    def __phrx_arp__request(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ARP request packets.
        """

        self._if._packet_stats_rx.arp__op_request += 1

        # Drop any ARP request if it is originated from us and looped for whatever.
        if (
            packet_rx.arp.spa in self._if._ip4_unicast or packet_rx.arp.spa.is_unspecified
        ) and packet_rx.arp.sha == self._if._mac_unicast:
            self._if._packet_stats_rx.arp__op_request__looped__drop += 1
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <WARN>IP Received our own ARP request for "
                f"{packet_rx.arp.tpa} from {packet_rx.arp.spa}, dropping.</>",
            )
            return

        # Note receiving gratuitous ARP request. Ongoing RFC 5227
        # §2.4 conflict detection is no longer done here — it runs in
        # userspace over each managed address's own 'Ip4Acd' socket
        # (the Linux 'sd-ipv4acd' model; the kernel ARP path does no
        # ACD). The RX path just notes the gratuitous ARP and learns
        # the cache below.
        if (
            packet_rx.ethernet.dst.is_broadcast
            and packet_rx.arp.spa.is_unicast
            and packet_rx.arp.spa == packet_rx.arp.tpa
            and packet_rx.arp.tha.is_unspecified
        ):
            self._if._packet_stats_rx.arp__op_request__gratuitous += 1
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <INFO>Received gratuitous ARP request, "
                f"{packet_rx.arp.spa} -> {packet_rx.arp.sha}</>",
            )

        # Note receiving ARP request not for our IP address.
        elif packet_rx.arp.tpa not in self._if._ip4_unicast:
            self._if._packet_stats_rx.arp__op_request__tpa_unknown += 1
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <INFO>Dropping ARP request for unknown TPA "
                f"{packet_rx.arp.tpa} from {packet_rx.arp.spa}</>",
            )

        else:
            # Note receiving ARP probe (RFC 5227).
            if packet_rx.arp.spa.is_unspecified:
                self._if._packet_stats_rx.arp__op_request__probe += 1
                __debug__ and log(
                    "arp",
                    f"{packet_rx.tracker} - <INFO>Replying to the ARP probe for TPA "
                    f"{packet_rx.arp.tpa} from {packet_rx.arp.spa}</>",
                )

            # Note receiving regular ARP request.
            elif packet_rx.arp.spa.is_unicast:
                self._if._packet_stats_rx.arp__op_request__tpa_stack += 1
                __debug__ and log(
                    "arp",
                    f"{packet_rx.tracker} - <INFO>Replying to ARP request for TPA "
                    f"{packet_rx.arp.tpa} from {packet_rx.arp.spa}</>",
                )

            # Decide whether to emit a Reply. Modes 2 and 8 of
            # 'arp.ignore' suppress the Reply; cache learning
            # (the '__update_arp_cache' call below) still runs
            # so the stack can reach the peer once outbound
            # traffic initiates. Linux's per-mode semantics:
            #   8 = kill switch — never reply (useful for
            #       "stealth" interfaces in fail-over /
            #       clustering that own the IP at L3 but should
            #       not advertise it via ARP).
            #   2 = sender-subnet-match — reply only when SPA is
            #       on one of our local subnets (anti-spoof gate
            #       on hosts that should answer only neighbours).
            # Probes (SPA = 0) are exempt from the mode-2 check —
            # a probe is the peer's "is this IP free?" wire
            # signal and has no SPA yet.
            should_reply = True
            arp_ignore = sysctl_iface.get_for_iface("arp.ignore", self._if._interface_name)
            if arp_ignore == 8:
                __debug__ and log(
                    "arp",
                    f"{packet_rx.tracker} - <INFO>arp.ignore=8 dropped Reply: " f"kill switch active",
                )
                should_reply = False
            else:
                sender_on_local_subnet = packet_rx.arp.spa.is_unspecified or any(
                    packet_rx.arp.spa in host.network for host in self._if._ip4_ifaddr
                )
                if arp_ignore == 2 and not sender_on_local_subnet:
                    __debug__ and log(
                        "arp",
                        f"{packet_rx.tracker} - <INFO>arp.ignore=2 dropped Reply: "
                        f"sender {packet_rx.arp.spa} is not on any local subnet",
                    )
                    should_reply = False

            # Send ARP reply packet to requester.
            if should_reply and (
                packet_rx.ethernet.dst.is_broadcast or packet_rx.ethernet.dst == self._if._mac_unicast
            ):
                self._if._packet_stats_rx.arp__op_request__respond += 1
                self._if._send_arp_reply(
                    arp__spa=packet_rx.arp.tpa,
                    arp__tha=packet_rx.arp.sha,
                    arp__tpa=packet_rx.arp.spa,
                    tracker=packet_rx.tracker,
                )

        self.__update_arp_cache(
            packet_rx=packet_rx,
            operation=ArpOperation.REQUEST,
        )

    def __phrx_arp__reply(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ARP reply packets.
        """

        self._if._packet_stats_rx.arp__op_reply += 1

        # Drop any ARP reply if it is originated from us and looped for whatever.
        if packet_rx.arp.spa in self._if._ip4_unicast and packet_rx.arp.sha == self._if._mac_unicast:
            self._if._packet_stats_rx.arp__op_reply__looped__drop += 1
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <WARN>IP Received our own ARP reply for "
                f"{packet_rx.arp.tpa} from {packet_rx.arp.spa}, dropping.</>",
            )
            return

        # Note receiving packet as direct ARP reply.
        if packet_rx.ethernet.dst == self._if._mac_unicast:
            self._if._packet_stats_rx.arp__op_reply__direct += 1
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <INFO>Received direct ARP reply, "
                f"{packet_rx.arp.spa} -> {packet_rx.arp.sha}</>",
            )

        # Note receiving packet as gratuitous ARP reply.
        elif (
            packet_rx.ethernet.dst.is_broadcast
            and packet_rx.arp.spa == packet_rx.arp.tpa
            and packet_rx.arp.tha.is_unspecified
        ):
            self._if._packet_stats_rx.arp__op_reply__gratuitous += 1
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <INFO>Received gratuitous ARP reply, "
                f"{packet_rx.arp.spa} -> {packet_rx.arp.sha}</>",
            )

        self.__update_arp_cache(packet_rx=packet_rx, operation=ArpOperation.REPLY)
