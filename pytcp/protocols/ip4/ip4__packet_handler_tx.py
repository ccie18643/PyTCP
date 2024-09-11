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
Module contains packet handler for the outbound IPv4 packets.

pytcp/protocols/ip4/ip4__packet_handler_tx.py

ver 3.0.2
"""


from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING

from net_addr import Ip4Address, MacAddress
from pytcp import config
from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.ip4.ip4__assembler import Ip4Assembler, Ip4FragAssembler
from pytcp.protocols.raw.raw__assembler import RawAssembler
from pytcp.protocols.tcp.tcp__assembler import TcpAssembler
from pytcp.protocols.udp.udp__assembler import UdpAssembler


class Ip4PacketHandlerTx(ABC):
    """
    Abstract class for outbound IPv4 packet handler.
    """

    if TYPE_CHECKING:
        from net_addr import Ip4Host
        from pytcp.lib.packet_stats import PacketStatsTx
        from pytcp.lib.tracker import Tracker
        from pytcp.protocols.ethernet.ethernet__base import EthernetPayload
        from pytcp.protocols.ip4.ip4__base import Ip4Payload

        packet_stats_tx: PacketStatsTx
        ip4_host: list[Ip4Host]
        ip4_multicast: list[Ip4Address]
        ip4_id: int

        # pylint: disable=unused-argument

        def _phtx_ethernet(
            self,
            *,
            ethernet__src: MacAddress = MacAddress(),
            ethernet__dst: MacAddress = MacAddress(),
            ethernet__payload: EthernetPayload = RawAssembler(),
        ) -> TxStatus: ...

        # pylint: disable=missing-function-docstring

        @property
        def ip4_unicast(self) -> list[Ip4Address]: ...

        @property
        def ip4_broadcast(self) -> list[Ip4Address]: ...

    def _phtx_ip4(
        self,
        *,
        ip4__dst: Ip4Address,
        ip4__src: Ip4Address,
        ip4__ttl: int = config.IP4__DEFAULT_TTL,
        ip4__payload: Ip4Payload = RawAssembler(),
    ) -> TxStatus:
        """
        Handle outbound IP packets.
        """

        self.packet_stats_tx.ip4__pre_assemble += 1

        assert 0 < ip4__ttl < 256

        # Check if IPv4 protocol support is enabled, if not then silently drop
        # the packet
        if not config.IP4__SUPPORT_ENABLED:
            self.packet_stats_tx.ip4__no_proto_support__drop += 1
            return TxStatus.DROPED__IP4__NO_PROTOCOL_SUPPORT

        # Validate source address
        result = self.__validate_src_ip4_address(
            ip4__src=ip4__src,
            ip4__dst=ip4__dst,
            ip4__payload=ip4__payload,
        )
        if isinstance(result, TxStatus):
            return result
        ip4__src = result

        # Validate destination address
        result = self.__validate_dst_ip4_address(
            ip4__dst=ip4__dst,
            tracker=ip4__payload.tracker,
        )
        if isinstance(result, TxStatus):
            return result
        ip4__dst = result

        # Assemble IPv4 packet
        ip4_packet_tx = Ip4Assembler(
            ip4__src=ip4__src,
            ip4__dst=ip4__dst,
            ip4__ttl=ip4__ttl,
            ip4__payload=ip4__payload,
        )

        # Send packet out if it's size doesn't exceed mtu
        if len(ip4_packet_tx) <= config.INTERFACE__TAP__MTU:
            self.packet_stats_tx.ip4__mtu_ok__send += 1
            __debug__ and log(
                "ip4", f"{ip4_packet_tx.tracker} - {ip4_packet_tx}"
            )
            return self._phtx_ethernet(
                ethernet__src=MacAddress(),
                ethernet__dst=MacAddress(),
                ethernet__payload=ip4_packet_tx,
            )

        # Fragment packet and send out
        self.packet_stats_tx.ip4__mtu_exceed__frag += 1
        __debug__ and log(
            "ip4",
            f"{ip4_packet_tx.tracker} - IPv4 packet len {len(ip4_packet_tx)} "
            "bytes, fragmentation needed",
        )

        if isinstance(ip4_packet_tx.payload, (TcpAssembler, UdpAssembler)):
            ip4_packet_tx.payload.pshdr_sum = ip4_packet_tx.pshdr_sum

        payload = bytearray(bytes(ip4_packet_tx.payload))

        payload_mtu = (
            config.INTERFACE__TAP__MTU - ip4_packet_tx.hlen
        ) & 0b1111111111111000
        payload_frags = [
            payload[_ : payload_mtu + _]
            for _ in range(0, len(payload), payload_mtu)
        ]
        offset = 0
        self.ip4_id += 1
        ethernet_tx_status: set[TxStatus] = set()
        for payload_frag in payload_frags:
            ip4_frag_tx = Ip4FragAssembler(
                ip4_frag__src=ip4__src,
                ip4_frag__dst=ip4__dst,
                ip4_frag__ttl=ip4__ttl,
                ip4_frag__payload=payload_frag,
                ip4_frag__offset=offset,
                ip4_frag__flag_mf=payload_frag is not payload_frags[-1],
                ip4_frag__id=self.ip4_id,
                ip4_frag__proto=ip4_packet_tx.proto,
            )
            __debug__ and log("ip4", f"{ip4_frag_tx.tracker} - {ip4_frag_tx}")
            offset += len(payload_frag)
            self.packet_stats_tx.ip4__mtu_exceed__frag__send += 1
            ethernet_tx_status.add(
                self._phtx_ethernet(
                    ethernet__src=MacAddress(),
                    ethernet__dst=MacAddress(),
                    ethernet__payload=ip4_frag_tx,
                )
            )

        # Return the most severe code
        for tx_status in [
            TxStatus.DROPED__ETHERNET__DST_RESOLUTION_FAIL,
            TxStatus.DROPED__ETHERNET__DST_NO_GATEWAY_IP4,
            TxStatus.DROPED__ETHERNET__DST_ARP_CACHE_FAIL,
            TxStatus.DROPED__ETHERNET__DST_GATEWAY_ARP_CACHE_FAIL,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
        ]:
            if tx_status in ethernet_tx_status:
                return tx_status

        return TxStatus.DROPED__IP4__UNKNOWN

    def __validate_src_ip4_address(
        self,
        *,
        ip4__src: Ip4Address,
        ip4__dst: Ip4Address,
        ip4__payload: Ip4Payload,
    ) -> Ip4Address | TxStatus:
        """
        Make sure source ip address is valid, supplement with valid one
        as appropriate.
        """

        tracker = ip4__payload.tracker

        # Check if the the source IP address belongs to this stack or is set to all
        # zeros (for DHCP client communication).
        if ip4__src not in {
            *self.ip4_unicast,
            *self.ip4_multicast,
            *self.ip4_broadcast,
            Ip4Address(),
        }:
            self.packet_stats_tx.ip4__src_not_owned__drop += 1
            __debug__ and log(
                "ip4",
                f"{tracker} - <WARN>Unable to sent out IPv4 packet, stack "
                f"doesn't own IPv4 address {ip4__src}, dropping</>",
            )
            return TxStatus.DROPED__IP4__SRC_NOT_OWNED

        # If packet is a response to multicast then replace source address with
        # primary address of the stack
        if ip4__src in self.ip4_multicast:
            if self.ip4_unicast:
                self.packet_stats_tx.ip4__src_multicast__replace += 1
                ip4__src = self.ip4_unicast[0]
                __debug__ and log(
                    "ip4",
                    f"{tracker} - Packet is response to multicast, replaced "
                    f"source with stack primary IPv4 address {ip4__src}",
                )
                return ip4__src
            self.packet_stats_tx.ip4__src_multicast__drop += 1
            __debug__ and log(
                "ip4",
                f"{tracker} - <WARN>Unable to sent out IPv4 packet, no stack "
                f"primary unicast IPv4 address available, dropping</>",
            )
            return TxStatus.DROPED__IP4__SRC_MULTICAST

        # If packet is a response to limited broadcast then replace source address
        # with primary address of the stack
        if ip4__src.is_limited_broadcast:
            if self.ip4_unicast:
                self.packet_stats_tx.ip4__src_limited_broadcast__replace += 1
                ip4__src = self.ip4_unicast[0]
                __debug__ and log(
                    "ip4",
                    f"{tracker} - Packet is response to limited broadcast, "
                    "replaced source with stack primary IPv4 "
                    f"address {ip4__src}",
                )
                return ip4__src
            self.packet_stats_tx.ip4__src_limited_broadcast__drop += 1
            __debug__ and log(
                "ip4",
                f"{tracker} - <WARN>Unable to sent out IPv4 packet, no stack "
                f"primary unicast IPv4 address available, dropping</>",
            )
            return TxStatus.DROPED__IP4__SRC_LIMITED_BROADCAST

        # If packet is a response to network broadcast then replace source address
        # with first stack address that belongs to appropriate subnet
        if ip4__src in self.ip4_broadcast:
            ip4_src_list = [
                ip4_host.address
                for ip4_host in self.ip4_host
                if ip4_host.network.broadcast == ip4__src
            ]
            if ip4_src_list:
                self.packet_stats_tx.ip4__src_network_broadcast__replace += 1
                ip4__src = ip4_src_list[0]
                __debug__ and log(
                    "ip4",
                    f"{tracker} - Packet is response to network broadcast, "
                    f"replaced source with appropriate IPv4 address {ip4__src}",
                )
                return ip4__src

        # If source is unspecified and destination belongs to any of local networks
        # then pick source address from that network.
        if ip4__src.is_unspecified:
            for ip4_host in self.ip4_host:
                if ip4__dst in ip4_host.network:
                    self.packet_stats_tx.ip4__src_network_unspecified__replace_local += (
                        1
                    )
                    ip4__src = ip4_host.address
                    __debug__ and log(
                        "ip4",
                        f"{tracker} - Packet source is unspecified, replaced "
                        f"source with IPv4 address {ip4__src} from the local "
                        "destination subnet",
                    )
                    return ip4__src

        # If source is unspecified and destination is external pick source from
        # first network that has default gateway set.
        if ip4__src.is_unspecified:
            for ip4_host in self.ip4_host:
                if ip4_host.gateway:
                    self.packet_stats_tx.ip4__src_network_unspecified__replace_external += (
                        1
                    )
                    ip4__src = ip4_host.address
                    __debug__ and log(
                        "ip4",
                        f"{tracker} - Packet source is unspecified, replaced "
                        f"source with IPv4 address {ip4__src} that has gateway "
                        "available",
                    )
                    return ip4__src

        # If src is unspecified and stack is sending DHCP packet
        if (
            ip4__src.is_unspecified
            and isinstance(ip4__payload, UdpAssembler)
            and ip4__payload.sport == 68
            and ip4__payload.dport == 67
        ):
            self.packet_stats_tx.ip4__src_unspecified__send += 1
            __debug__ and log(
                "ip4",
                f"{tracker} - Packet source is unspecified, DHCPv4 packet, "
                "sending",
            )
            return ip4__src

        # If src is unspecified and stack can't replace it
        if ip4__src.is_unspecified:
            self.packet_stats_tx.ip4__src_unspecified__drop += 1
            __debug__ and log(
                "ip4",
                f"{tracker} - <WARN>Packet source is unspecified, unable to "
                "replace with valid source, dropping</>",
            )
            return TxStatus.DROPED__IP4__SRC_UNSPECIFIED

        # If nothing above applies return the src address intact
        return ip4__src

    def __validate_dst_ip4_address(
        self,
        *,
        ip4__dst: Ip4Address,
        tracker: Tracker,
    ) -> Ip4Address | TxStatus:
        """
        Make sure destination ip address is valid.
        """

        # Drop packet if the destination address is unspecified
        if ip4__dst.is_unspecified:
            self.packet_stats_tx.ip4__dst_unspecified__drop += 1
            __debug__ and log(
                "ip4",
                f"{tracker} - <WARN>Destination address is unspecified, "
                "dropping</>",
            )
            return TxStatus.DROPED__IP4__DST_UNSPECIFIED

        return ip4__dst
