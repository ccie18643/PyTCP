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
This module contains packet handler for the inbound ICMPv6 packets.

pytcp/subsystems/packet_handler/packet_handler__icmp6__rx.py

ver 3.0.4
"""


import struct
from abc import ABC
from typing import TYPE_CHECKING, cast

from net_addr import Ip6Address, IpVersion
from net_proto import (
    IP6__HEADER__LEN,
    UDP__HEADER__LEN,
    Icmp6DestinationUnreachableMessage,
    Icmp6EchoReplyMessage,
    Icmp6EchoRequestMessage,
    Icmp6NdNeighborAdvertisementMessage,
    Icmp6NdNeighborSolicitationMessage,
    Icmp6NdOptions,
    Icmp6NdOptionTlla,
    Icmp6NdRouterAdvertisementMessage,
    Icmp6NdRouterSolicitationMessage,
    Icmp6Parser,
    Icmp6Type,
    IpProto,
    PacketRx,
    PacketValidationError,
)

from pytcp import stack
from pytcp.lib.logger import log
from pytcp.socket.raw__metadata import RawMetadata
from pytcp.socket.raw__socket import RawSocket
from pytcp.socket.udp__metadata import UdpMetadata
from pytcp.socket.udp__socket import UdpSocket


class PacketHandlerIcmp6Rx(ABC):
    """
    Class implements packet handler for the inbound ICMPv6 packets.
    """

    if TYPE_CHECKING:
        from threading import Semaphore

        from net_addr import Ip6Network, MacAddress
        from net_proto import Icmp6Message, Tracker

        from pytcp.lib.packet_stats import PacketStatsRx
        from pytcp.lib.tx_status import TxStatus

        _packet_stats_rx: PacketStatsRx
        _mac_unicast: MacAddress
        _icmp6_nd_dad__ip6_unicast_candidate: Ip6Address | None
        _icmp6_nd_dad__event: Semaphore
        _icmp6_nd_dad__tlla: MacAddress | None
        _icmp6_ra__event: Semaphore
        _icmp6_ra__prefixes: list[tuple[Ip6Network, Ip6Address]]

        # pylint: disable=unused-argument

        def _phtx_icmp6(
            self,
            *,
            ip6__src: Ip6Address,
            ip6__dst: Ip6Address,
            ip6__hop: int = 64,
            icmp6__message: Icmp6Message,
            echo_tracker: Tracker | None = None,
        ) -> TxStatus: ...

        # pylint: disable=missing-function-docstring

        @property
        def ip6_unicast(self) -> list[Ip6Address]: ...

    def _phrx_icmp6(self, packet_rx: PacketRx, /) -> None:
        """
        Handle inbound ICMPv6 packets.
        """

        self._packet_stats_rx.inc("icmp6__pre_parse")

        try:
            Icmp6Parser(packet_rx)

        except PacketValidationError as error:
            __debug__ and log(
                "icmp6",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            self._packet_stats_rx.inc("icmp6__failed_parse__drop")
            return

        __debug__ and log("icmp6", f"{packet_rx.tracker} - {packet_rx.icmp6}")

        match packet_rx.icmp6.message.type:
            case Icmp6Type.DESTINATION_UNREACHABLE:
                self.__phrx_icmp6__destination_unreachable(packet_rx)
            case Icmp6Type.ECHO_REQUEST:
                self.__phrx_icmp6__echo_request(packet_rx)
            case Icmp6Type.ECHO_REPLY:
                self.__phrx_icmp6__echo_reply(packet_rx)
            case Icmp6Type.ND__ROUTER_SOLICITATION:
                self.__phrx_icmp6__nd_router_solicitation(packet_rx)
            case Icmp6Type.ND__ROUTER_ADVERTISEMENT:
                self.__phrx_icmp6__nd_router_advertisement(packet_rx)
            case Icmp6Type.ND__NEIGHBOR_SOLICITATION:
                self.__phrx_icmp6__nd_neighbor_solicitation(packet_rx)
            case Icmp6Type.ND__NEIGHBOR_ADVERTISEMENT:
                self.__phrx_icmp6__nd_neighbor_advertisement(packet_rx)
            case Icmp6Type.MLD2__REPORT:
                self.__phrx_icmp6__mld2_report(packet_rx)
            case _:
                self.__phrx_icmp6__unknown(packet_rx)

    def __phrx_icmp6__destination_unreachable(
        self, packet_rx: PacketRx
    ) -> None:
        """
        Handle inbound ICMPv6 Port Unreachbale packets.
        """

        assert isinstance(
            packet_rx.icmp6.message, Icmp6DestinationUnreachableMessage
        )

        self._packet_stats_rx.inc("icmp6__destination_unreachable")
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 Unreachable packet "
            f"from {packet_rx.ip6.src}, will try to match UDP socket",
        )

        # Quick and dirty way to validate received data and pull useful
        # information from it.
        # TODO - This will not work in case of IPv6 extension headers present.
        frame = packet_rx.icmp6.message.data
        if (
            len(frame) >= IP6__HEADER__LEN + UDP__HEADER__LEN
            and frame[0] >> 4 == 6
            and frame[6] == int(IpProto.UDP)
        ):
            # Create UdpMetadata object and try to find matching UDP socket.
            udp_offset = IP6__HEADER__LEN
            packet = UdpMetadata(
                ip__ver=IpVersion.IP6,
                ip__local_address=Ip6Address(frame[8:24]),
                ip__remote_address=Ip6Address(frame[24:40]),
                udp__local_port=struct.unpack(
                    "!H", frame[udp_offset + 0 : udp_offset + 2]
                )[0],
                udp__remote_port=struct.unpack(
                    "!H", frame[udp_offset + 2 : udp_offset + 4]
                )[0],
            )

            for socket_id in packet.socket_ids:
                if socket := cast(
                    UdpSocket,
                    stack.sockets.get(socket_id, None),
                ):
                    __debug__ and log(
                        "icmp6",
                        f"{packet_rx.tracker} - <INFO>Found matching "
                        f"listening socket {socket} for Unreachable "
                        f"packet from {packet_rx.ip6.src}</>",
                    )
                    socket.notify_unreachable()
                    return

            # TODO: Need to add here handler for situation where Destination Unreachable
            # message is received as response to TCP SYN packet.
            # Way to reproduce: 'examples/tcp_echo_client.py --remote-ip-address 2600::'
            # Similar handler shlould be added to ICMPv4 as well.

            __debug__ and log(
                "icmp6",
                f"{packet_rx.tracker} - Unreachable data doesn't match "
                "any UDP socket",
            )
            return

        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Unreachable data doesn't pass basic "
            "IPv4/UDP integrity check",
        )

    def __phrx_icmp6__echo_request(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 Echo Request packets.
        """

        assert isinstance(packet_rx.icmp6.message, Icmp6EchoRequestMessage)

        self._packet_stats_rx.inc("icmp6__echo_request__respond_echo_reply")
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - <INFO>Received ICMPv6 Echo Request "
            f"packet from {packet_rx.ip6.src}, sending reply</>",
        )

        self._phtx_icmp6(
            ip6__src=packet_rx.ip6.dst,
            ip6__dst=packet_rx.ip6.src,
            ip6__hop=255,
            icmp6__message=Icmp6EchoReplyMessage(
                id=packet_rx.icmp6.message.id,
                seq=packet_rx.icmp6.message.seq,
                data=packet_rx.icmp6.message.data,
            ),
            echo_tracker=packet_rx.tracker,
        )

    def __phrx_icmp6__echo_reply(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 Echo Reply packets.
        """

        assert isinstance(packet_rx.icmp6.message, Icmp6EchoReplyMessage)

        self._packet_stats_rx.inc("icmp6__echo_reply")
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 Echo Reply packet "
            f"from {packet_rx.ip6.src}",
        )

        # Create RawMetadata object and try to find matching RAW socket.
        packet_rx_md = RawMetadata(
            ip__ver=packet_rx.ip.ver,
            ip__local_address=packet_rx.ip.dst,
            ip__remote_address=packet_rx.ip.src,
            ip__proto=IpProto.ICMP4,
            raw__data=bytes(packet_rx.icmp4.message),
        )

        for socket_id in packet_rx_md.socket_ids:
            if socket := cast(RawSocket, stack.sockets.get(socket_id, None)):
                self._packet_stats_rx.inc("raw__socket_match")
                __debug__ and log(
                    "raw",
                    f"{packet_rx_md.tracker} - <INFO>Found matching listening "
                    f"socket [{socket}]</>",
                )
                socket.process_raw_packet(packet_rx_md)
                return

    def __phrx_icmp6__nd_router_solicitation(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 ND Router Solicitation packets.
        """

        assert isinstance(
            packet_rx.icmp6.message, Icmp6NdRouterSolicitationMessage
        )

        self._packet_stats_rx.inc("icmp6__nd_router_solicitation")
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 Router Solicitation "
            f"packet from {packet_rx.ip6.src}",
        )

    def __phrx_icmp6__nd_router_advertisement(
        self, packet_rx: PacketRx
    ) -> None:
        """
        Handle inbound ICMPv6 ND Router Advertisement packets.
        """

        assert isinstance(
            packet_rx.icmp6.message, Icmp6NdRouterAdvertisementMessage
        )

        self._packet_stats_rx.inc("icmp6__nd_router_advertisement")
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 Router Advertisement "
            f"packet from {packet_rx.ip6.src}",
        )
        # Make note of prefixes that can be used for address autoconfiguration.
        self._icmp6_ra__prefixes = [
            (option.prefix, packet_rx.ip6.src)
            for option in packet_rx.icmp6.message.option_pi
        ]
        self._icmp6_ra__event.release()

    def __phrx_icmp6__nd_neighbor_solicitation(
        self, packet_rx: PacketRx
    ) -> None:
        """
        Handle inbound ICMPv6 ND Neighbor Solicitation packets.
        """

        assert isinstance(
            packet_rx.icmp6.message, Icmp6NdNeighborSolicitationMessage
        )

        self._packet_stats_rx.inc("icmp6__nd_neighbor_solicitation")
        # Check if request is for one of stack's IPv6 unicast addresses.
        if packet_rx.icmp6.message.target_address not in self.ip6_unicast:
            __debug__ and log(
                "icmp6",
                f"{packet_rx.tracker} - Received ICMPv6 Neighbor "
                f"Solicitation packet from {packet_rx.ip6.src}, "
                "not matching any of stack's IPv6 unicast addresses, "
                "dropping",
            )
            self._packet_stats_rx.inc(
                "icmp6__nd_neighbor_solicitation__target_unknown__drop"
            )
            return

        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - <INFO>Received ICMPv6 Neighbor "
            f"Solicitation packet from {packet_rx.ip6.src}, "
            "sending reply</>",
        )

        # Update ICMPv6 ND cache if valid IPv6 source is set and the ND option
        # SLLA is present.
        if (
            not (
                packet_rx.ip6.src.is_unspecified
                or packet_rx.ip6.src.is_multicast
            )
            and packet_rx.icmp6.message.option_slla
        ):
            self._packet_stats_rx.inc(
                "icmp6__nd_neighbor_solicitation__update_nd_cache"
            )
            stack.nd_cache.add_entry(
                ip6_address=packet_rx.ip6.src,
                mac_address=packet_rx.icmp6.message.option_slla,
            )

        # Determine if request is part of DAD request by examining its source
        # address (absence of slla is already tested by sanity check).
        if ip6_nd_dad := packet_rx.ip6.src.is_unspecified:
            self._packet_stats_rx.inc("icmp6__nd_neighbor_solicitation__dad")

        # Send response.
        self._packet_stats_rx.inc(
            "icmp6__nd_neighbor_solicitation__target_stack__respond"
        )
        self._phtx_icmp6(
            ip6__src=packet_rx.icmp6.message.target_address,
            ip6__dst=(
                Ip6Address("ff02::1") if ip6_nd_dad else packet_rx.ip6.src
            ),  # Use ff02::1 destination address when responding to DAD request.
            ip6__hop=255,
            icmp6__message=Icmp6NdNeighborAdvertisementMessage(
                flag_s=not ip6_nd_dad,  # No S flag when responding to DAD request.
                flag_o=ip6_nd_dad,  # The O flag when responding to DAD request (not necessary but Linux uses it).
                target_address=packet_rx.icmp6.message.target_address,
                options=Icmp6NdOptions(
                    Icmp6NdOptionTlla(tlla=self._mac_unicast),
                ),
            ),
            echo_tracker=packet_rx.tracker,
        )
        return

    def __phrx_icmp6__nd_neighbor_advertisement(
        self, packet_rx: PacketRx
    ) -> None:
        """
        Handle inbound ICMPv6 ND Neighbor Advertisement packets.
        """

        assert isinstance(
            packet_rx.icmp6.message, Icmp6NdNeighborAdvertisementMessage
        )

        self._packet_stats_rx.inc("icmp6__nd_neighbor_advertisement")
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 Neighbor Advertisement "
            f"packet for {packet_rx.icmp6.message.target_address} "
            f"from {packet_rx.ip6.src}",
        )

        # Run ND Duplicate Address Detection check.
        if (
            packet_rx.icmp6.message.target_address
            == self._icmp6_nd_dad__ip6_unicast_candidate
        ):
            self._packet_stats_rx.inc(
                "icmp6__nd_neighbor_advertisement__run_dad"
            )
            self._icmp6_nd_dad__tlla = packet_rx.icmp6.message.option_tlla
            self._icmp6_nd_dad__event.release()
            return

        # Update ICMPv6 ND cache.
        if packet_rx.icmp6.message.option_tlla:
            self._packet_stats_rx.inc(
                "icmp6__nd_neighbor_advertisement__update_nd_cache"
            )
            stack.nd_cache.add_entry(
                ip6_address=packet_rx.icmp6.message.target_address,
                mac_address=packet_rx.icmp6.message.option_tlla,
            )
            return

    def __phrx_icmp6__mld2_report(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 MLDv2 Report packets.
        """

        self._packet_stats_rx.inc("icmp6__mld2_report")
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 MLDv2 Report packet "
            f"from {packet_rx.ip6.src}",
        )

    def __phrx_icmp6__unknown(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound unknown ICMPv6 packets.
        """

        self._packet_stats_rx.inc("icmp6__unknown")
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received unknown ICMPv6 packet "
            f"from {packet_rx.ip6.src}",
        )
