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
Module contains packet handler for the outbound IPv6 packets.

pytcp/subsystems/packet_handler/packet_handler__ip6__tx.py

ver 3.0.2
"""


from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING

from net_addr import Ip6Address, MacAddress
from pytcp import config
from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.icmp6.icmp6__base import Icmp6
from pytcp.protocols.icmp6.message.mld2.icmp6_mld2_message__report import (
    Icmp6Mld2ReportMessage,
)
from pytcp.protocols.icmp6.message.nd.icmp6_nd_message import Icmp6NdMessage
from pytcp.protocols.ip6.ip6__assembler import Ip6Assembler
from pytcp.protocols.raw.raw__assembler import RawAssembler


class PacketHandlerIp6Tx(ABC):
    """
    Class implements packet handler for the outbound IPv6 packets.
    """

    if TYPE_CHECKING:
        from net_addr import Ip6Host
        from pytcp.lib.packet_stats import PacketStatsTx
        from pytcp.lib.tracker import Tracker
        from pytcp.protocols.ethernet.ethernet__base import EthernetPayload
        from pytcp.protocols.ip6.ip6__base import Ip6Payload

        packet_stats_tx: PacketStatsTx
        ip6_host: list[Ip6Host]

        # pylint: disable=unused-argument

        def _phtx_ethernet(
            self,
            *,
            ethernet__src: MacAddress = MacAddress(),
            ethernet__dst: MacAddress = MacAddress(),
            ethernet__payload: EthernetPayload = RawAssembler(),
        ) -> TxStatus: ...

        def _phtx_ip6_frag(
            self, *, ip6_packet_tx: Ip6Assembler
        ) -> TxStatus: ...

        # pylint: disable=missing-function-docstring

        @property
        def ip6_unicast(self) -> list[Ip6Address]: ...

        @property
        def ip6_multicast(self) -> list[Ip6Address]: ...

    def _phtx_ip6(
        self,
        *,
        ip6__dst: Ip6Address,
        ip6__src: Ip6Address,
        ip6__hop: int = config.IP6__DEFAULT_HOP_LIMIT,
        ip6__payload: Ip6Payload = RawAssembler(),
    ) -> TxStatus:
        """
        Handle outbound IP packets.
        """

        self.packet_stats_tx.ip6__pre_assemble += 1

        assert 0 < ip6__hop < 256

        # Check if IPv6 protocol support is enabled, if not then silently
        # drop the packet.
        if not config.IP6__SUPPORT_ENABLED:
            self.packet_stats_tx.ip6__no_proto_support__drop += 1
            return TxStatus.DROPED__IP6__NO_PROTOCOL_SUPPORT

        # Validate source address.
        result = self.__validate_src_ip6_address(
            ip6__src=ip6__src,
            ip6__dst=ip6__dst,
            ip6__payload=ip6__payload,
        )
        if isinstance(result, TxStatus):
            return result
        ip6__src = result

        # Validate destination address.
        result = self.__validate_dst_ip6_address(
            ip6__dst=ip6__dst,
            tracker=ip6__payload.tracker,
        )
        if isinstance(result, TxStatus):
            return result
        ip6__dst = result

        # assemble IPv6 apcket
        ip6_packet_tx = Ip6Assembler(
            ip6__src=ip6__src,
            ip6__dst=ip6__dst,
            ip6__hop=ip6__hop,
            ip6__payload=ip6__payload,
        )

        # Check if IP packet can be sent out without fragmentation,
        # if so send it out.
        if len(ip6_packet_tx) <= config.INTERFACE__TAP__MTU:
            self.packet_stats_tx.ip6__mtu_ok__send += 1
            __debug__ and log(
                "ip6", f"{ip6_packet_tx.tracker} - {ip6_packet_tx}"
            )
            return self._phtx_ethernet(
                ethernet__src=MacAddress(),
                ethernet__dst=MacAddress(),
                ethernet__payload=ip6_packet_tx,
            )

        # Fragment packet and send out.
        self.packet_stats_tx.ip6__mtu_exceed__frag += 1
        __debug__ and log(
            "ip6",
            f"{ip6_packet_tx.tracker} - IPv6 packet len "
            f"{len(ip6_packet_tx)} bytes, fragmentation needed",
        )
        return self._phtx_ip6_frag(ip6_packet_tx=ip6_packet_tx)

    def __validate_src_ip6_address(
        self,
        *,
        ip6__src: Ip6Address,
        ip6__dst: Ip6Address,
        ip6__payload: Ip6Payload,
    ) -> Ip6Address | TxStatus:
        """
        Make sure source ip address is valid, supplement with valid one
        as appropriate.
        """

        tracker = ip6__payload.tracker

        # Check if the the source IP address belongs to this stack
        # or its unspecified.
        if ip6__src not in {
            *self.ip6_unicast,
            *self.ip6_multicast,
            Ip6Address(),
        }:
            self.packet_stats_tx.ip6__src_not_owned__drop += 1
            __debug__ and log(
                "ip6",
                f"{tracker} - <WARN>Unable to sent out IPv6 packet, stack "
                f"doesn't own IPv6 address {ip6__src}, dropping</>",
            )
            return TxStatus.DROPED__IP6__SRC_NOT_OWNED

        # If packet is a response to multicast then replace source address with link
        # local address of the stack.
        if ip6__src in self.ip6_multicast:
            if self.ip6_unicast:
                self.packet_stats_tx.ip6__src_multicast__replace += 1
                ip6__src = self.ip6_unicast[0]
                __debug__ and log(
                    "ip6",
                    f"{tracker} - Packet is response to multicast, replaced "
                    f"source with stack link local IPv6 address {ip6__src}",
                )
                return ip6__src
            self.packet_stats_tx.ip6__src_multicast__drop += 1
            __debug__ and log(
                "ip6",
                f"{tracker} - <WARN>Unable to sent out IPv6 packet, no stack "
                "link local unicast IPv6 address available</>",
            )
            return TxStatus.DROPED__IP6__SRC_MULTICAST

        # If source is unspecified and destination belongs to any of local networks
        # then pick source address from that network.
        if ip6__src.is_unspecified:
            for ip6_host in self.ip6_host:
                if ip6__dst in ip6_host.network:
                    self.packet_stats_tx.ip6__src_network_unspecified__replace_local += (
                        1
                    )
                    ip6__src = ip6_host.address
                    __debug__ and log(
                        "ip6",
                        f"{tracker} - Packet source is unspecified, replaced "
                        f"source with IPv6 address {ip6__src} from the local "
                        "destination subnet",
                    )
                    return ip6__src

        # If source is unspecified and destination is external pick source from
        # first network that has default gateway set.
        if ip6__src.is_unspecified:
            for ip6_host in self.ip6_host:
                if ip6_host.gateway:
                    self.packet_stats_tx.ip6__src_network_unspecified__replace_external += (
                        1
                    )
                    ip6__src = ip6_host.address
                    __debug__ and log(
                        "ip6",
                        f"{tracker} - Packet source is unspecified, replaced "
                        f"source with IPv6 address {ip6__src} that has gateway "
                        "available",
                    )
                    return ip6__src

        # If src is unspecified and stack is sending ICMPv6 ND DAD packet
        if (
            ip6__src.is_unspecified
            and isinstance(ip6__payload, Icmp6)
            and isinstance(ip6__payload.message, Icmp6NdMessage)
            and not ip6__payload.message.options
        ):
            self.packet_stats_tx.ip6__src_unspecified__send += 1
            __debug__ and log(
                "ip6",
                f"{tracker} - Packet source is unspecified, ICMPv6 ND DAD "
                "packet, sending",
            )
            return ip6__src

        # If src is unspecified and stack is sending ICMPv6 MLDv2 report
        if (
            ip6__src.is_unspecified
            and isinstance(ip6__payload, Icmp6)
            and isinstance(ip6__payload.message, Icmp6Mld2ReportMessage)
        ):
            self.packet_stats_tx.ip6__src_unspecified__send += 1
            __debug__ and log(
                "ip6",
                f"{tracker} - Packet source is unspecified, ICMPv6 MLDv2 "
                "report, sending",
            )
            return ip6__src

        # If src is unspecified and stack can't replace it
        if ip6__src.is_unspecified:
            self.packet_stats_tx.ip6__src_unspecified__drop += 1
            __debug__ and log(
                "ip6",
                f"{tracker} - <WARN>Packet source is unspecified, unable to "
                "replace with valid source, dropping</>",
            )
            return TxStatus.DROPED__IP6__SRC_UNSPECIFIED

        # If nothing above applies return the src address intact
        return ip6__src

    def __validate_dst_ip6_address(
        self,
        *,
        ip6__dst: Ip6Address,
        tracker: Tracker,
    ) -> Ip6Address | TxStatus:
        """
        Make sure destination ip address is valid.
        """

        # Drop packet if the destination address is unspecified
        if ip6__dst.is_unspecified:
            self.packet_stats_tx.ip6__dst_unspecified__drop += 1
            __debug__ and log(
                "ip6",
                f"{tracker} - <WARN>Destination address is unspecified, "
                "dropping</>",
            )
            return TxStatus.DROPED__IP6__DST_UNSPECIFIED

        return ip6__dst
