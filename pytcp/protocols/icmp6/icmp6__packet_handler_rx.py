#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


"""
Module contains packet handler for the inbound ICMPv6 packets.

pytcp/protocols/icmp6/icmp6__packet_handler_rx.py

ver 3.0.2
"""


from __future__ import annotations

import struct
from abc import ABC
from typing import TYPE_CHECKING

from pytcp.lib import stack
from pytcp.lib.errors import PacketValidationError
from pytcp.lib.ip6_address import Ip6Address
from pytcp.lib.logger import log
from pytcp.protocols.icmp6.icmp6__parser import Icmp6Parser
from pytcp.protocols.icmp6.message.icmp6_message import Icmp6Type
from pytcp.protocols.icmp6.message.icmp6_message__destination_unreachable import (
    Icmp6DestinationUnreachableMessage,
)
from pytcp.protocols.icmp6.message.icmp6_message__echo_reply import (
    Icmp6EchoReplyMessage,
)
from pytcp.protocols.icmp6.message.icmp6_message__echo_request import (
    Icmp6EchoRequestMessage,
)
from pytcp.protocols.icmp6.message.nd.icmp6_nd_message__neighbor_advertisement import (
    Icmp6NdNeighborAdvertisementMessage,
)
from pytcp.protocols.icmp6.message.nd.icmp6_nd_message__neighbor_solicitation import (
    Icmp6NdNeighborSolicitationMessage,
)
from pytcp.protocols.icmp6.message.nd.icmp6_nd_message__router_advertisement import (
    Icmp6NdRouterAdvertisementMessage,
)
from pytcp.protocols.icmp6.message.nd.icmp6_nd_message__router_solicitation import (
    Icmp6NdRouterSolicitationMessage,
)
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_options import (
    Icmp6NdOptions,
    Icmp6NdOptionTlla,
)
from pytcp.protocols.ip6.ip6__enums import Ip6Next
from pytcp.protocols.ip6.ip6__header import IP6__HEADER__LEN
from pytcp.protocols.udp.udp__header import UDP__HEADER__LEN
from pytcp.protocols.udp.udp__metadata import UdpMetadata


class Icmp6PacketHandlerRx(ABC):
    """
    Class implements packet handler for the inbound ICMPv6 packets.
    """

    if TYPE_CHECKING:
        from threading import Semaphore

        from pytcp.lib.ip6_address import Ip6Network
        from pytcp.lib.mac_address import MacAddress
        from pytcp.lib.packet import PacketRx
        from pytcp.lib.packet_stats import PacketStatsRx
        from pytcp.lib.tracker import Tracker
        from pytcp.lib.tx_status import TxStatus
        from pytcp.protocols.icmp6.icmp6__base import Icmp6Message

        packet_stats_rx: PacketStatsRx
        icmp6_ra_event: Semaphore
        icmp6_ra_prefixes: list[tuple[Ip6Network, Ip6Address]]
        icmp6_nd_dad_event: Semaphore
        icmp6_nd_dad_tlla: MacAddress | None
        mac_unicast: MacAddress
        ip6_unicast_candidate: Ip6Address | None

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

    def _phrx_icmp6(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 packets.
        """

        self.packet_stats_rx.icmp6__pre_parse += 1

        try:
            Icmp6Parser(packet_rx)

        except PacketValidationError as error:
            __debug__ and log(
                "icmp6",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            self.packet_stats_rx.icmp6__failed_parse__drop += 1
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

        assert isinstance(packet_rx.icmp6, Icmp6DestinationUnreachableMessage)

        self.packet_stats_rx.icmp6__destination_unreachable += 1
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 Unreachable packet "
            f"from {packet_rx.ip6.src}, will try to match UDP socket",
        )

        # Quick and dirty way to validate received data and pull useful
        # information from it
        # TODO - This will not work in case of IPv6 extension headers present
        frame = packet_rx.icmp6.data
        if (
            len(frame) >= IP6__HEADER__LEN + UDP__HEADER__LEN
            and frame[0] >> 4 == 6
            and frame[6] == int(Ip6Next.UDP)
        ):
            # Create UdpMetadata object and try to find matching UDP socket
            udp_offset = IP6__HEADER__LEN
            packet = UdpMetadata(
                local_ip_address=Ip6Address(frame[8:24]),
                remote_ip_address=Ip6Address(frame[24:40]),
                local_port=struct.unpack(
                    "!H", frame[udp_offset + 0 : udp_offset + 2]
                )[0],
                remote_port=struct.unpack(
                    "!H", frame[udp_offset + 2 : udp_offset + 4]
                )[0],
            )

            for socket_pattern in packet.socket_patterns:
                socket = stack.sockets.get(socket_pattern, None)
                if socket:
                    __debug__ and log(
                        "icmp6",
                        f"{packet_rx.tracker} - <INFO>Found matching "
                        f"listening socket {socket} for Unreachable "
                        f"packet from {packet_rx.ip6.src}</>",
                    )
                    socket.notify_unreachable()
                    return

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
        return

    def __phrx_icmp6__echo_request(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 Echo Request packets.
        """

        assert isinstance(packet_rx.icmp6.message, Icmp6EchoRequestMessage)

        self.packet_stats_rx.icmp6__echo_request__respond_echo_reply += 1
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
        return

    def __phrx_icmp6__echo_reply(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 Echo Reply packets.
        """

        assert isinstance(packet_rx.icmp6.message, Icmp6EchoReplyMessage)

        self.packet_stats_rx.icmp6__echo_reply += 1
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 Echo Reply packet "
            f"from {packet_rx.ip6.src}",
        )
        return

    def __phrx_icmp6__nd_router_solicitation(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 ND Router Solicitation packets.
        """

        assert isinstance(
            packet_rx.icmp6.message, Icmp6NdRouterSolicitationMessage
        )

        self.packet_stats_rx.icmp6__nd_router_solicitation += 1
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 Router Solicitation "
            f"packet from {packet_rx.ip6.src}",
        )
        return

    def __phrx_icmp6__nd_router_advertisement(
        self, packet_rx: PacketRx
    ) -> None:
        """
        Handle inbound ICMPv6 ND Router Advertisement packets.
        """

        assert isinstance(
            packet_rx.icmp6.message, Icmp6NdRouterAdvertisementMessage
        )

        self.packet_stats_rx.icmp6__nd_router_advertisement += 1
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 Router Advertisement "
            f"packet from {packet_rx.ip6.src}",
        )
        # Make note of prefixes that can be used for address autoconfiguration
        self.icmp6_ra_prefixes = [
            (option.prefix, packet_rx.ip6.src)
            for option in packet_rx.icmp6.message.option_pi
        ]
        self.icmp6_ra_event.release()
        return

    def __phrx_icmp6__nd_neighbor_solicitation(
        self, packet_rx: PacketRx
    ) -> None:
        """
        Handle inbound ICMPv6 ND Neighbor Solicitation packets.
        """

        assert isinstance(
            packet_rx.icmp6.message, Icmp6NdNeighborSolicitationMessage
        )

        self.packet_stats_rx.icmp6__nd_neighbor_solicitation += 1
        # Check if request is for one of stack's IPv6 unicast addresses
        if packet_rx.icmp6.message.target_address not in self.ip6_unicast:
            __debug__ and log(
                "icmp6",
                f"{packet_rx.tracker} - Received ICMPv6 Neighbor "
                f"Solicitation packet from {packet_rx.ip6.src}, "
                "not matching any of stack's IPv6 unicast addresses, "
                "dropping",
            )
            self.packet_stats_rx.icmp6__nd_neighbor_solicitation__target_unknown__drop += (
                1
            )
            return

        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - <INFO>Received ICMPv6 Neighbor "
            f"Solicitation packet from {packet_rx.ip6.src}, "
            "sending reply</>",
        )

        # Update ICMPv6 ND cache if valid IPv6 source is set and the ND option
        # SLLA is present
        if (
            not (
                packet_rx.ip6.src.is_unspecified
                or packet_rx.ip6.src.is_multicast
            )
            and packet_rx.icmp6.message.option_slla
        ):
            self.packet_stats_rx.icmp6__nd_neighbor_solicitation__update_nd_cache += (
                1
            )
            stack.nd_cache.add_entry(
                packet_rx.ip6.src, packet_rx.icmp6.message.option_slla
            )

        # Determine if request is part of DAD request by examining its source
        # address (absence of slla is already tested by sanity check)
        if ip6_nd_dad := packet_rx.ip6.src.is_unspecified:
            self.packet_stats_rx.icmp6__nd_neighbor_solicitation__dad += 1

        # Send response
        self.packet_stats_rx.icmp6__nd_neighbor_solicitation__target_stack__respond += (
            1
        )
        self._phtx_icmp6(
            ip6__src=packet_rx.icmp6.message.target_address,
            ip6__dst=(
                Ip6Address("ff02::1") if ip6_nd_dad else packet_rx.ip6.src
            ),  # use ff02::1 destination addriess when responding to DAD request
            ip6__hop=255,
            icmp6__message=Icmp6NdNeighborAdvertisementMessage(
                flag_s=not ip6_nd_dad,  # no S flag when responding to DAD request
                flag_o=ip6_nd_dad,  # O flag when respondidng to DAD request (this is not necessary but Linux uses it)
                target_address=packet_rx.icmp6.message.target_address,
                options=Icmp6NdOptions(
                    Icmp6NdOptionTlla(tlla=self.mac_unicast),
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

        self.packet_stats_rx.icmp6__nd_neighbor_advertisement += 1
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 Neighbor Advertisement "
            f"packet for {packet_rx.icmp6.message.target_address} "
            f"from {packet_rx.ip6.src}",
        )

        # Run ND Duplicate Address Detection check
        if packet_rx.icmp6.message.target_address == self.ip6_unicast_candidate:
            self.packet_stats_rx.icmp6__nd_neighbor_advertisement__run_dad += 1
            self.icmp6_nd_dad_tlla = packet_rx.icmp6.message.option_tlla
            self.icmp6_nd_dad_event.release()
            return

        # Update ICMPv6 ND cache
        if packet_rx.icmp6.message.option_tlla:
            self.packet_stats_rx.icmp6__nd_neighbor_advertisement__update_nd_cache += (
                1
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

        self.packet_stats_rx.icmp6__mld2_report += 1
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 MLDv2 Report packet "
            f"from {packet_rx.ip6.src}",
        )
        return

    def __phrx_icmp6__unknown(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound unknown ICMPv6 packets.
        """

        self.packet_stats_rx.icmp6__unknown += 1
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received unknown ICMPv6 packet "
            f"from {packet_rx.ip6.src}",
        )
        return
