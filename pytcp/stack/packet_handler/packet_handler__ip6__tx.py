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
This module contains packet handler for the outbound IPv6 packets.

pytcp/subsystems/packet_handler/packet_handler__ip6__tx.py

ver 3.0.3
"""


from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING

from net_addr import Ip6Address, MacAddress
from net_proto import (
    IP6__DEFAULT_HOP_LIMIT,
    Icmp6,
    Icmp6Mld2ReportMessage,
    Icmp6NdMessage,
    Ip6Assembler,
    IpProto,
    RawAssembler,
)

from pytcp import stack
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus


class PacketHandlerIp6Tx(ABC):
    """
    Class implements packet handler for the outbound IPv6 packets.
    """

    if TYPE_CHECKING:
        from net_addr import Ip6Host
        from net_proto import EthernetPayload, Ip6Payload, Tracker

        from pytcp.lib.packet_stats import PacketStatsTx

        _interface_layer: InterfaceLayer
        _packet_stats_tx: PacketStatsTx
        _ip6_host: list[Ip6Host]
        _ip6_multicast: list[Ip6Address]
        _ip6_support: bool
        _interface_mtu: int

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
        def _ip6_unicast(self) -> list[Ip6Address]: ...

    def _phtx_ip6(
        self,
        *,
        ip6__dst: Ip6Address,
        ip6__src: Ip6Address,
        ip6__hop: int = IP6__DEFAULT_HOP_LIMIT,
        ip6__payload: Ip6Payload = RawAssembler(),
    ) -> TxStatus:
        """
        Handle outbound IP packets.
        """

        self._packet_stats_tx.inc("ip6__pre_assemble")

        assert 0 < ip6__hop < 256

        # Check if IPv6 protocol support is enabled, if not then silently
        # drop the packet.
        if not self._ip6_support:
            self._packet_stats_tx.inc("ip6__no_proto_support__drop")
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
        if len(ip6_packet_tx) <= self._interface_mtu:
            self._packet_stats_tx.inc("ip6__mtu_ok__send")
            __debug__ and log(
                "ip6", f"{ip6_packet_tx.tracker} - {ip6_packet_tx}"
            )
            match self._interface_layer:
                case InterfaceLayer.L2:
                    return self._phtx_ethernet(
                        ethernet__src=MacAddress(),
                        ethernet__dst=MacAddress(),
                        ethernet__payload=ip6_packet_tx,
                    )
                case InterfaceLayer.L3:
                    self.__send_out_packet(ip6_packet_tx=ip6_packet_tx)
                    return TxStatus.PASSED__IP6__TO_TX_RING

        # Fragment packet and send out.
        self._packet_stats_tx.inc("ip6__mtu_exceed__frag")
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
            *self._ip6_unicast,
            *self._ip6_multicast,
            Ip6Address(),
        }:
            self._packet_stats_tx.inc("ip6__src_not_owned__drop")
            __debug__ and log(
                "ip6",
                f"{tracker} - <WARN>Unable to sent out IPv6 packet, stack "
                f"doesn't own IPv6 address {ip6__src}, dropping</>",
            )
            return TxStatus.DROPED__IP6__SRC_NOT_OWNED

        # If packet is a response to multicast then replace source address with link
        # local address of the stack.
        if ip6__src in self._ip6_multicast:
            if self._ip6_unicast:
                self._packet_stats_tx.inc("ip6__src_multicast__replace")
                ip6__src = self._ip6_unicast[0]
                __debug__ and log(
                    "ip6",
                    f"{tracker} - Packet is response to multicast, replaced "
                    f"source with stack link local IPv6 address {ip6__src}",
                )
                return ip6__src
            self._packet_stats_tx.inc("ip6__src_multicast__drop")
            __debug__ and log(
                "ip6",
                f"{tracker} - <WARN>Unable to sent out IPv6 packet, no stack "
                "link local unicast IPv6 address available</>",
            )
            return TxStatus.DROPED__IP6__SRC_MULTICAST

        # If source is unspecified and destination belongs to any of local networks
        # then pick source address from that network.
        if ip6__src.is_unspecified:
            for ip6_host in self._ip6_host:
                if ip6__dst in ip6_host.network:
                    self._packet_stats_tx.inc(
                        "ip6__src_network_unspecified__replace_local"
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
            for ip6_host in self._ip6_host:
                if ip6_host.gateway:
                    self._packet_stats_tx.inc(
                        "ip6__src_network_unspecified__replace_external"
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
            self._packet_stats_tx.inc("ip6__src_unspecified__send")
            __debug__ and log(
                "ip6",
                f"{tracker} - Packet source is unspecified, ICMPv6 ND DAD "
                "packet, sending",
            )
            return ip6__src

        # If src is unspecified and stack is sending ICMPv6 MLDv2 report.
        if (
            ip6__src.is_unspecified
            and isinstance(ip6__payload, Icmp6)
            and isinstance(ip6__payload.message, Icmp6Mld2ReportMessage)
        ):
            self._packet_stats_tx.inc("ip6__src_unspecified__send")
            __debug__ and log(
                "ip6",
                f"{tracker} - Packet source is unspecified, ICMPv6 MLDv2 "
                "report, sending",
            )
            return ip6__src

        # If src is unspecified and stack can't replace it.
        if ip6__src.is_unspecified:
            self._packet_stats_tx.inc("ip6__src_unspecified__drop")
            __debug__ and log(
                "ip6",
                f"{tracker} - <WARN>Packet source is unspecified, unable to "
                "replace with valid source, dropping</>",
            )
            return TxStatus.DROPED__IP6__SRC_UNSPECIFIED

        # If nothing above applies return the src address intact.
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

        # Drop packet if the destination address is unspecified.
        if ip6__dst.is_unspecified:
            self._packet_stats_tx.inc("ip6__dst_unspecified__drop")
            __debug__ and log(
                "ip6",
                f"{tracker} - <WARN>Destination address is unspecified, "
                "dropping</>",
            )
            return TxStatus.DROPED__IP6__DST_UNSPECIFIED

        return ip6__dst

    def send_ip6_packet(
        self,
        *,
        ip6__local_address: Ip6Address,
        ip6__remote_address: Ip6Address,
        ip6__next: IpProto,
        ip6__payload: bytes = bytes(),
    ) -> TxStatus:
        """
        Interface method for RAW Socket -> Packet Assembler communication.
        """

        return self._phtx_ip6(
            ip6__src=ip6__local_address,
            ip6__dst=ip6__remote_address,
            ip6__payload=RawAssembler(
                raw__payload=ip6__payload,
                ip_proto=ip6__next,
            ),
        )

    @staticmethod
    def __send_out_packet(ip6_packet_tx: Ip6Assembler) -> None:
        stack.tx_ring.enqueue(ip6_packet_tx)
