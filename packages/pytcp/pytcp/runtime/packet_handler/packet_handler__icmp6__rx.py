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

pytcp/runtime/packet_handler/packet_handler__icmp6__rx.py

ver 3.0.8
"""

import random
from typing import TYPE_CHECKING, cast

from net_addr import Ip6Address, Ip6Network, IpVersion
from net_proto import (
    Icmp6DestinationUnreachableCode,
    Icmp6MessageDestinationUnreachable,
    Icmp6MessageEchoReply,
    Icmp6MessageEchoRequest,
    Icmp6MessagePacketTooBig,
    Icmp6MessageParameterProblem,
    Icmp6MessageTimeExceeded,
    Icmp6NdMessageNeighborAdvertisement,
    Icmp6NdMessageNeighborSolicitation,
    Icmp6NdMessageRedirect,
    Icmp6NdMessageRouterAdvertisement,
    Icmp6NdMessageRouterSolicitation,
    Icmp6ParameterProblemCode,
    Icmp6Parser,
    Icmp6TimeExceededCode,
    Icmp6Type,
    IpProto,
    PacketRx,
    PacketValidationError,
)
from net_proto.protocols.icmp6.message.mld1.icmp6__mld1__message__query import (
    Icmp6Mld1MessageQuery,
)
from net_proto.protocols.icmp6.message.mld2.icmp6__mld2__message__query import (
    Icmp6Mld2MessageQuery,
)
from pytcp import stack
from pytcp.lib.dad_slot_registry import DadSignalResult
from pytcp.lib.logger import log
from pytcp.protocols.icmp6.icmp6__echo_gate import should_emit_echo_reply
from pytcp.protocols.icmp.icmp__error_demux import EmbeddedL4, parse_embedded_l4
from pytcp.protocols.tcp.tcp__icmp_metadata import IcmpCategory, IcmpMetadata
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.runtime.socket.error_queue import SoEeOrigin
from pytcp.runtime.socket.socket_id import SocketId
from pytcp.runtime.socket.tcp__socket import TcpSocket
from pytcp.runtime.socket.udp__metadata import UdpMetadata
from pytcp.runtime.socket.udp__socket import UdpSocket
from pytcp.stack import sysctl_iface

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandler


# RFC 3810 §9.1 / §9.2 — MLD Robustness Variable and Query Interval
# defaults, used to compute the §9.12 Older Version Querier Present
# Timeout = [Robustness Variable] x [Query Interval] + [Query Response
# Interval] when an MLDv1 Query arms the compatibility timer.
MLD__ROBUSTNESS_VARIABLE = 2
MLD__QUERY_INTERVAL__MS = 125_000


def _mld2_mrc_to_mrd_ms(mrc: int) -> int:
    """
    RFC 3810 §5.1.3 — convert a 16-bit Maximum Response
    Code (MRC) to the corresponding Maximum Response Delay
    (MRD) in milliseconds.

    For mrc < 32768: MRD = mrc (linear ms representation).

    For mrc >= 32768, the field encodes a floating-point
    value:

        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |1| exp |          mant         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        exp  = (mrc >> 12) & 0x7
        mant = mrc & 0xfff
        MRD  = (mant | 0x1000) << (exp + 3)
    """

    if mrc < 32768:
        return mrc
    exp = (mrc >> 12) & 0x7
    mant = mrc & 0xFFF
    return (mant | 0x1000) << (exp + 3)


class Icmp6RxHandler:
    """
    The inbound ICMPv6 packet handler for one interface.
    """

    _if: PacketHandler

    def __init__(self, *, interface: PacketHandler) -> None:
        """
        Bind the handler to its owning interface.
        """

        self._if = interface

    def _phrx_icmp6(self, packet_rx: PacketRx, /) -> None:
        """
        Handle inbound ICMPv6 packets.
        """

        self._if._packet_stats_rx.icmp6__pre_parse += 1

        try:
            Icmp6Parser(packet_rx)

        except PacketValidationError as error:
            __debug__ and log(
                "icmp6",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            self._if._packet_stats_rx.icmp6__failed_parse__drop += 1
            return

        __debug__ and log("icmp6", f"{packet_rx.tracker} - {packet_rx.icmp6}")

        # RFC 6980 §5: Neighbor Discovery and SEcure Neighbor
        # Discovery messages MUST be silently ignored if they
        # arrived as IPv6 fragments. The IPv6 frag-RX handler
        # marks the reassembled PacketRx; the gate here drops
        # any ND-typed message that traversed it.
        if packet_rx.was_fragmented and packet_rx.icmp6.message.type in {
            Icmp6Type.ND__ROUTER_SOLICITATION,
            Icmp6Type.ND__ROUTER_ADVERTISEMENT,
            Icmp6Type.ND__NEIGHBOR_SOLICITATION,
            Icmp6Type.ND__NEIGHBOR_ADVERTISEMENT,
            Icmp6Type.ND__REDIRECT,
        }:
            self._if._packet_stats_rx.icmp6__nd_message__fragmented__drop += 1
            __debug__ and log(
                "icmp6",
                f"{packet_rx.tracker} - <WARN>Dropping fragmented ND message "
                f"(type={packet_rx.icmp6.message.type}); RFC 6980 §5 silent-discard.</>",
            )
            return

        match packet_rx.icmp6.message.type:
            case Icmp6Type.DESTINATION_UNREACHABLE:
                self.__phrx_icmp6__destination_unreachable(packet_rx)
            case Icmp6Type.PACKET_TOO_BIG:
                self.__phrx_icmp6__packet_too_big(packet_rx)
            case Icmp6Type.TIME_EXCEEDED:
                self.__phrx_icmp6__time_exceeded(packet_rx)
            case Icmp6Type.PARAMETER_PROBLEM:
                self.__phrx_icmp6__parameter_problem(packet_rx)
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
            case Icmp6Type.ND__REDIRECT:
                self.__phrx_icmp6__nd_redirect(packet_rx)
            case Icmp6Type.MLD2__REPORT:
                self.__phrx_icmp6__mld2_report(packet_rx)
            case Icmp6Type.MULTICAST_LISTENER_QUERY:
                self.__phrx_icmp6__mld_query(packet_rx)
            case _:
                self.__phrx_icmp6__unknown(packet_rx)

    def __phrx_icmp6__destination_unreachable(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 Port Unreachbale packets.
        """

        assert isinstance(packet_rx.icmp6.message, Icmp6MessageDestinationUnreachable)

        self._if._packet_stats_rx.icmp6__destination_unreachable += 1
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 Unreachable packet "
            f"from {packet_rx.ip6.src}, will try to match UDP socket",
        )

        # IPv6 extension headers in the embedded packet are not
        # supported by the helper — those frames fall through to the
        # 'no demux possible' log path.
        embedded = parse_embedded_l4(packet_rx.icmp6.message.data, IpVersion.IP6)
        if embedded is None:
            __debug__ and log(
                "icmp6",
                f"{packet_rx.tracker} - Unreachable data doesn't pass basic " "IPv4/UDP integrity check",
            )
            return

        message = packet_rx.icmp6.message

        if embedded.proto is IpProto.UDP:
            self.__phrx_icmp6__dispatch_udp_unreachable(
                packet_rx,
                embedded,
                icmp_code=message.code,
                embedded_datagram=bytes(message.data),
            )
            return

        if embedded.proto is IpProto.TCP:
            self.__phrx_icmp6__dispatch_tcp_unreachable(packet_rx, embedded, message)
            return

    def __phrx_icmp6__dispatch_udp_unreachable(
        self,
        packet_rx: PacketRx,
        embedded: EmbeddedL4,
        *,
        icmp_code: Icmp6DestinationUnreachableCode,
        embedded_datagram: bytes,
    ) -> None:
        """
        Route an ICMPv6 Destination Unreachable carrying an embedded
        UDP segment to the matching UdpSocket.notify_unreachable.
        """

        packet = UdpMetadata(
            ip__ver=IpVersion.IP6,
            ip__local_address=cast(Ip6Address, embedded.local_ip),
            ip__remote_address=cast(Ip6Address, embedded.remote_ip),
            udp__local_port=embedded.local_port,
            udp__remote_port=embedded.remote_port,
        )

        for socket_id in packet.socket_ids:
            if socket := cast(
                UdpSocket,
                stack.sockets.get(socket_id, None),
            ):
                __debug__ and log(
                    "icmp6",
                    f"{packet_rx.tracker} - <INFO>Found matching "
                    f"listening UDP socket {socket} for Unreachable "
                    f"packet from {packet_rx.ip6.src}</>",
                )
                socket.notify_unreachable(
                    icmp_origin=SoEeOrigin.ICMP6,
                    icmp_type=Icmp6Type.DESTINATION_UNREACHABLE,
                    icmp_code=icmp_code,
                    offender_ip=packet_rx.ip6.src,
                    embedded_datagram=embedded_datagram,
                )
                return

        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Unreachable data doesn't match " "any UDP socket",
        )

    def __phrx_icmp6__dispatch_tcp_unreachable(
        self,
        packet_rx: PacketRx,
        embedded: EmbeddedL4,
        message: Icmp6MessageDestinationUnreachable,
    ) -> None:
        """
        Route an ICMPv6 Destination Unreachable carrying an embedded
        TCP segment to the matching TcpSession via TcpSocket. Applies
        the RFC 5927 §4 sequence-in-window guard. Also pushes the
        ICMP context onto the matched TcpSocket's IPV6_RECVERR
        error queue.
        """

        socket_id = SocketId(
            address_family=AddressFamily.INET6,
            socket_type=SocketType.STREAM,
            local_address=cast(Ip6Address, embedded.local_ip),
            local_port=embedded.local_port,
            remote_address=cast(Ip6Address, embedded.remote_ip),
            remote_port=embedded.remote_port,
        )

        socket = cast(TcpSocket, stack.sockets.get(socket_id, None))
        if socket is None or (session := socket.tcp_session) is None:
            return

        if embedded.embedded_seq is not None and not session.is_seq_in_window(embedded.embedded_seq):
            self._if._packet_stats_rx.icmp6__destination_unreachable__tcp__seq_out_of_window__drop += 1
            return

        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - <INFO>Found matching TCP session "
            f"for Unreachable packet from {packet_rx.ip6.src}</>",
        )
        session.tcp_fsm(
            icmp=IcmpMetadata(
                category=IcmpCategory.DEST_UNREACHABLE,
                icmp_type=1,
                icmp_code=int(message.code),
                ip_version=6,
            ),
        )
        socket.notify_unreachable(
            icmp_origin=SoEeOrigin.ICMP6,
            icmp_type=Icmp6Type.DESTINATION_UNREACHABLE,
            icmp_code=message.code,
            offender_ip=packet_rx.ip6.src,
            embedded_datagram=bytes(message.data),
        )
        self._if._packet_stats_rx.icmp6__destination_unreachable__tcp__notify += 1

    def __phrx_icmp6__time_exceeded(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 Time Exceeded packets. Routes the
        embedded L4 segment to the matching TCP / UDP socket as a
        soft-error notification per RFC 4443 §3.3 / RFC 5927 §6.
        TCP demux applies the RFC 5927 §4 sequence-in-window guard.
        """

        assert isinstance(packet_rx.icmp6.message, Icmp6MessageTimeExceeded)

        message = packet_rx.icmp6.message

        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 Time Exceeded packet "
            f"from {packet_rx.ip6.src}, code={message.code}",
        )
        self._if._packet_stats_rx.icmp6__time_exceeded += 1

        embedded = parse_embedded_l4(message.data, IpVersion.IP6)
        if embedded is None:
            __debug__ and log(
                "icmp6",
                f"{packet_rx.tracker} - Time Exceeded data doesn't pass basic IPv6/L4 integrity check",
            )
            return

        if embedded.proto is IpProto.UDP:
            self.__phrx_icmp6__time_exceeded__dispatch_udp(
                packet_rx,
                embedded,
                icmp_code=message.code,
                embedded_datagram=bytes(message.data),
            )
            return

        if embedded.proto is IpProto.TCP:
            self.__phrx_icmp6__time_exceeded__dispatch_tcp(packet_rx, embedded, message)
            return

    def __phrx_icmp6__time_exceeded__dispatch_udp(
        self,
        packet_rx: PacketRx,
        embedded: EmbeddedL4,
        *,
        icmp_code: Icmp6TimeExceededCode,
        embedded_datagram: bytes,
    ) -> None:
        """
        Route an ICMPv6 Time Exceeded carrying an embedded UDP segment
        to the matching UdpSocket via notify_time_exceeded().
        """

        packet = UdpMetadata(
            ip__ver=IpVersion.IP6,
            ip__local_address=cast(Ip6Address, embedded.local_ip),
            ip__remote_address=cast(Ip6Address, embedded.remote_ip),
            udp__local_port=embedded.local_port,
            udp__remote_port=embedded.remote_port,
        )

        for socket_id in packet.socket_ids:
            if socket := cast(UdpSocket, stack.sockets.get(socket_id, None)):
                __debug__ and log(
                    "icmp6",
                    f"{packet_rx.tracker} - <INFO>Found matching UDP socket "
                    f"{socket} for Time Exceeded from {packet_rx.ip6.src}</>",
                )
                socket.notify_time_exceeded(
                    icmp_type=Icmp6Type.TIME_EXCEEDED,
                    icmp_code=icmp_code,
                    icmp_origin=SoEeOrigin.ICMP6,
                    offender_ip=packet_rx.ip6.src,
                    embedded_datagram=embedded_datagram,
                )
                self._if._packet_stats_rx.icmp6__time_exceeded__udp__notify += 1
                return

        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Time Exceeded data doesn't match any UDP socket",
        )

    def __phrx_icmp6__time_exceeded__dispatch_tcp(
        self,
        packet_rx: PacketRx,
        embedded: EmbeddedL4,
        message: Icmp6MessageTimeExceeded,
    ) -> None:
        """
        Route an ICMPv6 Time Exceeded carrying an embedded TCP segment
        to the matching TcpSession via TcpSocket. Applies the RFC 5927
        §4 sequence-in-window guard before notifying. Also pushes the
        ICMP context onto the matched TcpSocket's IPV6_RECVERR error
        queue.
        """

        socket_id = SocketId(
            address_family=AddressFamily.INET6,
            socket_type=SocketType.STREAM,
            local_address=cast(Ip6Address, embedded.local_ip),
            local_port=embedded.local_port,
            remote_address=cast(Ip6Address, embedded.remote_ip),
            remote_port=embedded.remote_port,
        )

        socket = cast(TcpSocket, stack.sockets.get(socket_id, None))
        if socket is None or (session := socket.tcp_session) is None:
            return

        if embedded.embedded_seq is not None and not session.is_seq_in_window(embedded.embedded_seq):
            self._if._packet_stats_rx.icmp6__time_exceeded__tcp__seq_out_of_window__drop += 1
            return

        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - <INFO>Found matching TCP session " f"for Time Exceeded from {packet_rx.ip6.src}</>",
        )
        session.tcp_fsm(
            icmp=IcmpMetadata(
                category=IcmpCategory.TIME_EXCEEDED,
                icmp_type=3,
                icmp_code=int(message.code),
                ip_version=6,
            ),
        )
        socket.notify_time_exceeded(
            icmp_type=Icmp6Type.TIME_EXCEEDED,
            icmp_code=message.code,
            icmp_origin=SoEeOrigin.ICMP6,
            offender_ip=packet_rx.ip6.src,
            embedded_datagram=bytes(message.data),
        )
        self._if._packet_stats_rx.icmp6__time_exceeded__tcp__notify += 1

    def __phrx_icmp6__parameter_problem(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 Parameter Problem packets. Routes the
        embedded L4 segment to the matching TCP / UDP socket as a
        soft-error notification per RFC 4443 §3.4 / RFC 5927 §6.
        """

        assert isinstance(packet_rx.icmp6.message, Icmp6MessageParameterProblem)

        message = packet_rx.icmp6.message

        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 Parameter Problem packet "
            f"from {packet_rx.ip6.src}, code={message.code}, pointer={message.pointer}",
        )
        self._if._packet_stats_rx.icmp6__parameter_problem += 1

        embedded = parse_embedded_l4(message.data, IpVersion.IP6)
        if embedded is None:
            __debug__ and log(
                "icmp6",
                f"{packet_rx.tracker} - Parameter Problem data doesn't pass basic IPv6/L4 integrity check",
            )
            return

        if embedded.proto is IpProto.UDP:
            self.__phrx_icmp6__parameter_problem__dispatch_udp(
                packet_rx,
                embedded,
                icmp_code=message.code,
                embedded_datagram=bytes(message.data),
            )
            return

        if embedded.proto is IpProto.TCP:
            self.__phrx_icmp6__parameter_problem__dispatch_tcp(packet_rx, embedded, message)
            return

    def __phrx_icmp6__parameter_problem__dispatch_udp(
        self,
        packet_rx: PacketRx,
        embedded: EmbeddedL4,
        *,
        icmp_code: Icmp6ParameterProblemCode,
        embedded_datagram: bytes,
    ) -> None:
        """
        Route an ICMPv6 Parameter Problem carrying an embedded UDP
        segment to the matching UdpSocket via notify_parameter_problem().
        """

        packet = UdpMetadata(
            ip__ver=IpVersion.IP6,
            ip__local_address=cast(Ip6Address, embedded.local_ip),
            ip__remote_address=cast(Ip6Address, embedded.remote_ip),
            udp__local_port=embedded.local_port,
            udp__remote_port=embedded.remote_port,
        )

        for socket_id in packet.socket_ids:
            if socket := cast(UdpSocket, stack.sockets.get(socket_id, None)):
                __debug__ and log(
                    "icmp6",
                    f"{packet_rx.tracker} - <INFO>Found matching UDP socket "
                    f"{socket} for Parameter Problem from {packet_rx.ip6.src}</>",
                )
                socket.notify_parameter_problem(
                    icmp_type=Icmp6Type.PARAMETER_PROBLEM,
                    icmp_code=icmp_code,
                    icmp_origin=SoEeOrigin.ICMP6,
                    offender_ip=packet_rx.ip6.src,
                    embedded_datagram=embedded_datagram,
                )
                self._if._packet_stats_rx.icmp6__parameter_problem__udp__notify += 1
                return

        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Parameter Problem data doesn't match any UDP socket",
        )

    def __phrx_icmp6__parameter_problem__dispatch_tcp(
        self,
        packet_rx: PacketRx,
        embedded: EmbeddedL4,
        message: Icmp6MessageParameterProblem,
    ) -> None:
        """
        Route an ICMPv6 Parameter Problem carrying an embedded TCP
        segment to the matching TcpSession via TcpSocket. Applies the
        RFC 5927 §4 sequence-in-window guard before notifying. Also
        pushes the ICMP context onto the matched TcpSocket's
        IPV6_RECVERR error queue.
        """

        socket_id = SocketId(
            address_family=AddressFamily.INET6,
            socket_type=SocketType.STREAM,
            local_address=cast(Ip6Address, embedded.local_ip),
            local_port=embedded.local_port,
            remote_address=cast(Ip6Address, embedded.remote_ip),
            remote_port=embedded.remote_port,
        )

        socket = cast(TcpSocket, stack.sockets.get(socket_id, None))
        if socket is None or (session := socket.tcp_session) is None:
            return

        if embedded.embedded_seq is not None and not session.is_seq_in_window(embedded.embedded_seq):
            self._if._packet_stats_rx.icmp6__parameter_problem__tcp__seq_out_of_window__drop += 1
            return

        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - <INFO>Found matching TCP session "
            f"for Parameter Problem from {packet_rx.ip6.src}</>",
        )
        session.tcp_fsm(
            icmp=IcmpMetadata(
                category=IcmpCategory.PARAM_PROBLEM,
                icmp_type=4,
                icmp_code=int(message.code),
                ip_version=6,
            ),
        )
        socket.notify_parameter_problem(
            icmp_type=Icmp6Type.PARAMETER_PROBLEM,
            icmp_code=message.code,
            icmp_origin=SoEeOrigin.ICMP6,
            offender_ip=packet_rx.ip6.src,
            embedded_datagram=bytes(message.data),
        )
        self._if._packet_stats_rx.icmp6__parameter_problem__tcp__notify += 1

    def __phrx_icmp6__packet_too_big(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 Packet Too Big messages — the IPv6
        PMTUD signal. Updates 'stack.pmtu_cache' for the destination
        and notifies the matching UDP socket via 'notify_pmtu' so it
        can refit subsequent sends to the new path MTU.

        Reference: RFC 4443 §3.2 (Packet Too Big Message).
        Reference: RFC 8201 §4 (IPv6 Path MTU Discovery).
        """

        assert isinstance(packet_rx.icmp6.message, Icmp6MessagePacketTooBig)

        message = packet_rx.icmp6.message

        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 Packet Too Big " f"from {packet_rx.ip6.src}, mtu={message.mtu}",
        )
        self._if._packet_stats_rx.icmp6__packet_too_big += 1

        embedded = parse_embedded_l4(message.data, IpVersion.IP6)
        if embedded is None:
            return

        if embedded.proto is IpProto.UDP:
            packet = UdpMetadata(
                ip__ver=IpVersion.IP6,
                ip__local_address=cast(Ip6Address, embedded.local_ip),
                ip__remote_address=cast(Ip6Address, embedded.remote_ip),
                udp__local_port=embedded.local_port,
                udp__remote_port=embedded.remote_port,
            )

            for socket_id in packet.socket_ids:
                if socket := cast(UdpSocket, stack.sockets.get(socket_id, None)):
                    stack.record_classical_pmtu(cast(Ip6Address, embedded.remote_ip), message.mtu)
                    socket.notify_pmtu(
                        next_hop_mtu=message.mtu,
                        icmp_origin=SoEeOrigin.ICMP6,
                        icmp_type=Icmp6Type.PACKET_TOO_BIG,
                        icmp_code=message.code,
                        offender_ip=packet_rx.ip6.src,
                        embedded_datagram=bytes(message.data),
                    )
                    self._if._packet_stats_rx.icmp6__packet_too_big__notify_pmtu += 1
                    return
            return

        if embedded.proto is IpProto.TCP:
            self.__phrx_icmp6__dispatch_tcp_pmtu(packet_rx, embedded, message)
            return

    def __phrx_icmp6__dispatch_tcp_pmtu(
        self,
        packet_rx: PacketRx,
        embedded: EmbeddedL4,
        message: Icmp6MessagePacketTooBig,
    ) -> None:
        """
        Route an ICMPv6 Packet Too Big carrying an embedded TCP
        segment to the matching TcpSession via a PMTU FSM event.
        Applies the RFC 5927 §4 sequence-in-window guard. Also
        pushes the ICMPv6 context onto the matched TcpSocket's
        IPV6_RECVERR error queue (errno=EMSGSIZE,
        ee_info=next_hop_mtu) so 'recvmsg(MSG_ERRQUEUE)'
        applications can read the new MTU.
        """

        socket_id = SocketId(
            address_family=AddressFamily.INET6,
            socket_type=SocketType.STREAM,
            local_address=cast(Ip6Address, embedded.local_ip),
            local_port=embedded.local_port,
            remote_address=cast(Ip6Address, embedded.remote_ip),
            remote_port=embedded.remote_port,
        )

        socket = cast(TcpSocket, stack.sockets.get(socket_id, None))
        if socket is None or (session := socket.tcp_session) is None:
            return

        if embedded.embedded_seq is not None and not session.is_seq_in_window(embedded.embedded_seq):
            self._if._packet_stats_rx.icmp6__packet_too_big__tcp__seq_out_of_window__drop += 1
            return

        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - <INFO>Found matching TCP session "
            f"for Packet Too Big from {packet_rx.ip6.src}, mtu={message.mtu}</>",
        )
        session.tcp_fsm(
            icmp=IcmpMetadata(
                category=IcmpCategory.PMTU,
                icmp_type=2,
                icmp_code=0,
                next_hop_mtu=message.mtu,
                ip_version=6,
            ),
        )
        socket.notify_pmtu(
            next_hop_mtu=message.mtu,
            icmp_origin=SoEeOrigin.ICMP6,
            icmp_type=Icmp6Type.PACKET_TOO_BIG,
            icmp_code=message.code,
            offender_ip=packet_rx.ip6.src,
            embedded_datagram=bytes(message.data),
        )
        self._if._packet_stats_rx.icmp6__packet_too_big__notify_pmtu += 1

    def __phrx_icmp6__echo_request(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 Echo Request packets. Delegates the
        emission decision to the icmp6__echo_gate module so any
        future ICMPv6-specific Echo policy lands in one file rather
        than scattered inline checks.
        """

        assert isinstance(packet_rx.icmp6.message, Icmp6MessageEchoRequest)

        if not should_emit_echo_reply():
            return

        self._if._packet_stats_rx.icmp6__echo_request__respond_echo_reply += 1
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - <INFO>Received ICMPv6 Echo Request "
            f"packet from {packet_rx.ip6.src}, sending reply</>",
        )

        # Build the reply message in the enclosing scope (where the
        # isinstance-narrowing on 'packet_rx.icmp6.message' holds)
        # rather than inside the marshaled closure.
        echo_reply_message = Icmp6MessageEchoReply(
            id=packet_rx.icmp6.message.id,
            seq=packet_rx.icmp6.message.seq,
            data=packet_rx.icmp6.message.data,
        )
        self._if._marshal_tx(
            lambda: self._if._phtx_icmp6(
                ip6__src=packet_rx.ip6.dst,
                ip6__dst=packet_rx.ip6.src,
                ip6__hop=255,
                icmp6__message=echo_reply_message,
                echo_tracker=packet_rx.tracker,
            )
        )

    def __phrx_icmp6__echo_reply(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 Echo Reply packets.
        """

        assert isinstance(packet_rx.icmp6.message, Icmp6MessageEchoReply)

        self._if._packet_stats_rx.icmp6__echo_reply += 1
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 Echo Reply packet " f"from {packet_rx.ip6.src}",
        )

        # An inbound Echo Reply is delivered to matching RAW sockets by
        # the IPv6 RX path ('packet_handler__ip6__rx'), which clones the
        # datagram to every matching raw socket (Linux 'raw6_local_deliver').
        # The host stack itself has nothing further to do with an Echo Reply.

    def __phrx_icmp6__nd_router_solicitation(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 ND Router Solicitation packets.
        """

        assert isinstance(packet_rx.icmp6.message, Icmp6NdMessageRouterSolicitation)

        self._if._packet_stats_rx.icmp6__nd_router_solicitation += 1
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 Router Solicitation " f"packet from {packet_rx.ip6.src}",
        )

    def __phrx_icmp6__nd_router_advertisement(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 ND Router Advertisement packets.

        Reference: RFC 4862 §5.5.3 (PI option processing rules).

        Filters each Prefix Information option per RFC 4862
        §5.5.3 steps (e)(1)-(e)(3) before adding the prefix to
        the SLAAC candidate list:

          - (e)(1) Autonomous flag must be set; otherwise the
            prefix is for on-link determination only and SLAAC
            must not derive an address from it.
          - (e)(2) The link-local prefix is reserved; an RA
            advertising it must not be consumed by SLAAC.
          - (e)(3) preferred_lifetime must not exceed
            valid_lifetime; otherwise the option is malformed.

        # Phase 2: per-prefix lifetime tracking with the 2-hour
        # rule on existing-prefix lifetime extensions (RFC 4862
        # §5.5.3 (e)(6)) requires a SLAAC state machine that
        # tracks per-prefix wall-clock expiry. The current
        # 'list[(prefix, gateway)]' representation is a Phase-1
        # snapshot; the upgrade path is greppable via this
        # marker.
        """

        assert isinstance(packet_rx.icmp6.message, Icmp6NdMessageRouterAdvertisement)

        self._if._packet_stats_rx.icmp6__nd_router_advertisement += 1
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 Router Advertisement " f"packet from {packet_rx.ip6.src}",
        )

        admitted: list[tuple[Ip6Network, Ip6Address]] = []
        accept_pinfo = bool(sysctl_iface.get_for_iface("icmp6.accept_ra_pinfo", self._if._interface_name))
        for option in packet_rx.icmp6.message.pi:
            reason: str | None = None
            if not option.flag_a:
                reason = "RFC 4862 §5.5.3 (e)(1): A flag clear (non-autonomous)"
            elif option.prefix.address.is_link_local:
                reason = "RFC 4862 §5.5.3 (e)(2): link-local prefix reserved"
            elif option.preferred_lifetime > option.valid_lifetime:
                reason = "RFC 4862 §5.5.3 (e)(3): preferred_lifetime > valid_lifetime"
            if reason is not None:
                self._if._packet_stats_rx.icmp6__nd_router_advertisement__prefix_info__drop += 1
                __debug__ and log(
                    "icmp6",
                    f"{packet_rx.tracker} - <WARN>Dropping RA Prefix "
                    f"Information option for {option.prefix} from "
                    f"{packet_rx.ip6.src}: {reason}</>",
                )
                continue
            admitted.append((option.prefix, packet_rx.ip6.src))

            # RFC 4862 §5.5.3 (e)(4)-(e)(6) SLAAC prefix-table
            # maintenance — gated by Linux's accept_ra_pinfo
            # sysctl. Boot-time SLAAC still pulls from
            # '_icmp6_ra__prefixes' below; the new table tracks
            # lifetimes for §12b state-machine work.
            if accept_pinfo:
                self._if._update_icmp6_slaac_address(
                    prefix=option.prefix,
                    valid_lifetime=option.valid_lifetime,
                    preferred_lifetime=option.preferred_lifetime,
                    router_address=packet_rx.ip6.src,
                )
                # RFC 8981 §3.3 temporary-address mint. The
                # mutator is a no-op when 'icmp6.use_tempaddr=0'
                # (default); when enabled it generates a random
                # IID, claims via the §20.1 async DAD worker,
                # and tracks the entry in '_icmp6_temp_addresses'.
                self._if._update_icmp6_temp_address(
                    prefix=option.prefix,
                    valid_lifetime=option.valid_lifetime,
                    preferred_lifetime=option.preferred_lifetime,
                    router_address=packet_rx.ip6.src,
                )
            else:
                self._if._packet_stats_rx.icmp6__nd_router_advertisement__pi__pinfo_disabled__drop += 1

        self._if._icmp6_ra__prefixes = admitted
        self._if._icmp6_ra__event.release()

        # RFC 4861 §6.3.4 default-router list maintenance —
        # independent of the SLAAC prefix path above. Gated by the
        # 'icmp6.accept_ra_defrtr' Linux-parity sysctl: when 0 the
        # host still consumes the prefix-info options but does not
        # learn the RA source as a default router.
        if sysctl_iface.get_for_iface("icmp6.accept_ra_defrtr", self._if._interface_name):
            self._if._update_icmp6_default_router(
                address=packet_rx.ip6.src,
                router_lifetime=packet_rx.icmp6.message.router_lifetime,
                prf=packet_rx.icmp6.message.prf,
            )
        else:
            self._if._packet_stats_rx.icmp6__nd_router_advertisement__defrtr__drop += 1

        # RFC 4861 §6.3.4 host-parameter mirror — Cur-Hop-Limit /
        # Reachable Time / Retrans Timer. Always processed; field
        # value 0 ("unspecified") preserves the prior host value.
        self._if._update_icmp6_ra_parameters(
            cur_hop_limit=packet_rx.icmp6.message.hop,
            reachable_time_ms=packet_rx.icmp6.message.reachable_time,
            retrans_timer_ms=packet_rx.icmp6.message.retrans_timer,
        )

        # RFC 8415 §4 / RFC 4861 §4.2 — the Managed (M) and
        # Other-config (O) flags drive DHCPv6: M=1 requests stateful
        # address configuration, O=1 requests stateless other
        # configuration (DNS, etc.). When a DHCPv6 client is installed
        # on this interface, hand it the flags; the client's worker
        # debounces so a periodic RA does not re-run a completed
        # exchange. When no client is present the flags are parsed but
        # not acted on.
        dhcp6_client = self._if._dhcp6_client
        if dhcp6_client is not None and (packet_rx.icmp6.message.flag_m or packet_rx.icmp6.message.flag_o):
            __debug__ and log(
                "icmp6",
                f"{packet_rx.tracker} - RA Managed/Other flags "
                f"{'M' if packet_rx.icmp6.message.flag_m else '-'}"
                f"{'O' if packet_rx.icmp6.message.flag_o else '-'}; triggering DHCPv6 client",
            )
            dhcp6_client.trigger(
                managed=packet_rx.icmp6.message.flag_m,
                other=packet_rx.icmp6.message.flag_o,
            )

    def __phrx_icmp6__nd_neighbor_solicitation(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 ND Neighbor Solicitation packets.
        """

        assert isinstance(packet_rx.icmp6.message, Icmp6NdMessageNeighborSolicitation)

        self._if._packet_stats_rx.icmp6__nd_neighbor_solicitation += 1

        # RFC 4862 §5.4.3 case (b) — simultaneous-probe DAD conflict:
        # if a peer's NS targets an address we are currently
        # probing (regardless of the peer's IP source — even a
        # probe-form NS with src=:: counts), the address is in
        # use by another node also performing DAD. Abort that
        # DAD claim by setting the per-address Event with
        # 'tlla = None' so the DAD wait-loop picks the conflict
        # signal up. Runs before the 'target not in ip6_unicast'
        # early-return because tentative candidates are NOT in
        # 'ip6_unicast' until DAD passes (under strict DAD) or
        # may already be there as OPTIMISTIC under §20.
        #
        # The slot check + nonce-test + tlla-write + event.set()
        # is atomic under the registry's internal lock so the
        # worker thread cannot tear down the slot between the
        # check and the signal.
        target_address = packet_rx.icmp6.message.target_address
        dad_signal = self._if._icmp6_nd_dad__registry.try_signal_conflict(
            target_address,
            peer_info=None,
            inbound_nonce=packet_rx.icmp6.message.nonce,
        )
        if dad_signal is DadSignalResult.LOOP_HAIRPIN:
            # RFC 7527 §4.2 Enhanced DAD: a Nonce option matching
            # one we emitted for this candidate means this NS is
            # a loop-hairpin echo of our own probe (a switch
            # reflecting traffic back). Drop silently.
            self._if._packet_stats_rx.icmp6__nd_neighbor_solicitation__loop_hairpin__drop += 1
            __debug__ and log(
                "icmp6",
                f"{packet_rx.tracker} - <INFO>Loop-hairpin DAD echo "
                f"detected (Nonce match) for "
                f"{target_address}; dropped</>",
            )
            return
        if dad_signal is DadSignalResult.SIGNALED:
            self._if._packet_stats_rx.icmp6__nd_neighbor_solicitation__dad_conflict += 1
            __debug__ and log(
                "icmp6",
                f"{packet_rx.tracker} - <CRIT>Simultaneous-probe DAD conflict: "
                f"peer {packet_rx.ip6.src} probing our tentative address "
                f"{target_address}; aborting our DAD</>",
            )
            return

        # Check if request is for one of stack's IPv6 unicast addresses.
        if packet_rx.icmp6.message.target_address not in self._if.ip6_unicast:
            __debug__ and log(
                "icmp6",
                f"{packet_rx.tracker} - Received ICMPv6 Neighbor "
                f"Solicitation packet from {packet_rx.ip6.src}, "
                "not matching any of stack's IPv6 unicast addresses, "
                "dropping",
            )
            self._if._packet_stats_rx.icmp6__nd_neighbor_solicitation__target_unknown__drop += 1
            return

        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - <INFO>Received ICMPv6 Neighbor "
            f"Solicitation packet from {packet_rx.ip6.src}, "
            "sending reply</>",
        )

        # Update ICMPv6 ND cache if valid IPv6 source is set and the ND option
        # SLLA is present.
        if not (packet_rx.ip6.src.is_unspecified or packet_rx.ip6.src.is_multicast) and packet_rx.icmp6.message.slla:
            self._if._packet_stats_rx.icmp6__nd_neighbor_solicitation__update_nd_cache += 1
            assert self._if._nd_cache is not None, "Handler updating the ND cache must have one wired."
            self._if._nd_cache.add_entry(
                ip6_address=packet_rx.ip6.src,
                mac_address=packet_rx.icmp6.message.slla,
            )

        # Determine if request is part of DAD request by examining its source
        # address (absence of slla is already tested by sanity check).
        if ip6_nd_dad := packet_rx.ip6.src.is_unspecified:
            self._if._packet_stats_rx.icmp6__nd_neighbor_solicitation__dad += 1

        # Send response. Routes through the public NA emission
        # helper rather than inlining '_phtx_icmp6' (the helper
        # is shared with the DAD-success gratuitous-NA path —
        # see 'send_icmp6_neighbor_advertisement_gratuitous').
        self._if._packet_stats_rx.icmp6__nd_neighbor_solicitation__target_stack__respond += 1
        self._if.send_icmp6_neighbor_advertisement(
            ip6__src=packet_rx.icmp6.message.target_address,
            ip6__dst=(
                Ip6Address("ff02::1") if ip6_nd_dad else packet_rx.ip6.src
            ),  # Use ff02::1 destination address when responding to DAD request.
            target_address=packet_rx.icmp6.message.target_address,
            flag_s=not ip6_nd_dad,  # No S flag when responding to DAD request.
            flag_o=ip6_nd_dad,  # The O flag when responding to DAD request (not necessary but Linux uses it).
            include_tlla=True,
            echo_tracker=packet_rx.tracker,
        )
        return

    def __phrx_icmp6__nd_neighbor_advertisement(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 ND Neighbor Advertisement packets.
        """

        assert isinstance(packet_rx.icmp6.message, Icmp6NdMessageNeighborAdvertisement)

        self._if._packet_stats_rx.icmp6__nd_neighbor_advertisement += 1
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 Neighbor Advertisement "
            f"packet for {packet_rx.icmp6.message.target_address} "
            f"from {packet_rx.ip6.src}",
        )

        # Run ND Duplicate Address Detection check. The
        # slot check + tlla-write + event.set() is atomic
        # under the registry's internal lock so the worker
        # thread cannot tear down the slot between the check
        # and the signal. NA messages carry no Nonce option
        # (RFC 4861 §4.4), so 'inbound_nonce=None' skips the
        # hairpin check.
        target_address = packet_rx.icmp6.message.target_address
        dad_signal = self._if._icmp6_nd_dad__registry.try_signal_conflict(
            target_address,
            peer_info=packet_rx.icmp6.message.tlla,
            inbound_nonce=None,
        )
        if dad_signal is DadSignalResult.SIGNALED:
            self._if._packet_stats_rx.icmp6__nd_neighbor_advertisement__run_dad += 1
            return

        # Update ICMPv6 ND cache.
        if packet_rx.icmp6.message.tlla:
            self._if._packet_stats_rx.icmp6__nd_neighbor_advertisement__update_nd_cache += 1
            assert self._if._nd_cache is not None, "Handler updating the ND cache must have one wired."
            self._if._nd_cache.add_entry(
                ip6_address=packet_rx.icmp6.message.target_address,
                mac_address=packet_rx.icmp6.message.tlla,
            )
            return

    def __phrx_icmp6__nd_redirect(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 ND Redirect packets (RFC 4861 §8).

        The ICMPv6 parser's 'validate_sanity' already enforced the
        parse-time §8.1 gates (Hop Limit = 255, source link-local,
        Destination Address not multicast). This handler enforces
        the runtime-state §8.1 gates plus the §8.3 conceptual-
        data-structure update:

          1. 'icmp6.accept_redirects' sysctl gate (Linux parity).
          2. ICMP Target Address MUST be link-local OR equal to
             ICMP Destination Address (§8.1's "either-or" rule).
          3. If a TLLA option is present, learn (Target, TLLA)
             into the neighbour cache (§8.3).

        Phase 2: §8.1's "IP source MUST be the current first-hop
        router for the specified ICMP Destination Address" check
        is deferred until the default-router list lands
        (nd_linux_parity §11). Without router-state tracking the
        host cannot verify the originator was the actual first-hop
        for the redirected flow.
        """

        assert isinstance(packet_rx.icmp6.message, Icmp6NdMessageRedirect)

        self._if._packet_stats_rx.icmp6__nd_redirect += 1
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 Redirect "
            f"target {packet_rx.icmp6.message.target_address} "
            f"destination {packet_rx.icmp6.message.destination_address} "
            f"from {packet_rx.ip6.src}",
        )

        # 1. 'icmp6.accept_redirects' kill switch.
        if sysctl_iface.get_for_iface("icmp6.accept_redirects", self._if._interface_name) == 0:
            self._if._packet_stats_rx.icmp6__nd_redirect__accept_redirects_zero__drop += 1
            __debug__ and log(
                "icmp6",
                f"{packet_rx.tracker} - <INFO>icmp6.accept_redirects=0 " f"dropped Redirect</>",
            )
            return

        # 2. Target must be link-local or equal to Destination.
        target = packet_rx.icmp6.message.target_address
        destination = packet_rx.icmp6.message.destination_address
        if not target.is_link_local and target != destination:
            self._if._packet_stats_rx.icmp6__nd_redirect__bad_target__drop += 1
            __debug__ and log(
                "icmp6",
                f"{packet_rx.tracker} - <WARN>Redirect Target {target} is "
                f"neither link-local nor equal to Destination {destination} "
                f"— dropping</>",
            )
            return

        # 3. §8.3 cache override: learn (Target, TLLA) if option present.
        tlla = packet_rx.icmp6.message.options.tlla
        if tlla is not None:
            self._if._packet_stats_rx.icmp6__nd_redirect__update_nd_cache += 1
            assert self._if._nd_cache is not None, "Handler updating the ND cache must have one wired."
            self._if._nd_cache.add_entry(ip6_address=target, mac_address=tlla)

    def __phrx_icmp6__mld2_report(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 MLDv2 Report packets.

        Reference: RFC 3810 §5 (MLDv2 querier processing model).

        Host-stack scope (Phase 1): Reports are processed by an
        MLDv2 querier — typically a multicast-aware router. PyTCP
        is a host: it sends Reports (see
        '_send_icmp6_multicast_listener_report') but takes no
        action on inbound Reports beyond accounting. The
        'icmp6__mld2_report' counter records every received
        Report so an operator can observe the link's multicast
        activity.

        # Phase 2: MLDv2 querier role goes here. A router-grade
        # PyTCP would maintain per-multicast-group state, run
        # the General/Multicast-Address-Specific/Multicast-
        # Address-and-Source-Specific Query timers, and update
        # group memberships from inbound Reports.
        """

        self._if._packet_stats_rx.icmp6__mld2_report += 1
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 MLDv2 Report packet " f"from {packet_rx.ip6.src}",
        )

    def __phrx_icmp6__mld_query(self, packet_rx: PacketRx) -> None:
        """
        Handle an inbound ICMPv6 Multicast Listener Query (type
        130) — MLDv1 (24 octets) or MLDv2 (>= 28).

        Reference: RFC 3810 §5.1.10 (listener-side Query
        processing); RFC 3810 §8.2.1 (MLDv1 compatibility).

        Host-stack scope (Phase 1): a listener responds with a
        Report reflecting its current per-interface multicast
        membership. The response is delayed by a uniformly-random
        value in [0, Maximum Response Delay] per §5.1.10 so a
        link with many listeners spreads Report bursts across the
        delay window. The coalescing rule (§5.1.10) absorbs a
        Query whose computed response time is later than an
        already-pending Report, and supersedes a pending Report
        when a new Query would fire sooner.

        An MLDv1 Query additionally arms the §8.2.1 Older Version
        Querier Present timer, putting the interface into MLDv1
        Host Compatibility Mode so the response — and subsequent
        membership Reports — take the MLDv1 Report form (§8.3.1).
        The report form is selected at emit time by
        '_send_icmp6_multicast_listener_report', so the scheduling
        here is version-agnostic.
        """

        self._if._packet_stats_rx.icmp6__mld2_query += 1
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 MLD Query packet from {packet_rx.ip6.src}",
        )

        message = packet_rx.icmp6.message
        if isinstance(message, Icmp6Mld1MessageQuery):
            self._mld_arm_v1_compatibility(message.maximum_response_delay)
            mrd_ms = message.maximum_response_delay
        else:
            assert isinstance(message, Icmp6Mld2MessageQuery)
            mrd_ms = _mld2_mrc_to_mrd_ms(message.maximum_response_code)

        self._mld_query__schedule_response(mrd_ms)

    def _mld_arm_v1_compatibility(self, max_response_delay_ms: int, /) -> None:
        """
        Arm the RFC 3810 §8.2.1 MLDv1 Older Version Querier Present
        timer in response to an MLDv1 Query, holding the interface
        in MLDv1 Host Compatibility Mode. The §9.12 timeout is
        [Robustness Variable] x [Query Interval] + [Query Response
        Interval]; the Query's Maximum Response Delay supplies the
        last term. Written under '_lock__multicast' (the no-GIL
        standing invariant), mirroring the IGMP querier-present
        arming.
        """

        timeout_ms = MLD__ROBUSTNESS_VARIABLE * MLD__QUERY_INTERVAL__MS + max_response_delay_ms
        with self._if._lock__multicast:
            self._if._mld__v1_querier_present_until_ms = stack.timer.now_ms + timeout_ms

    def _mld_query__schedule_response(self, mrd_ms: int, /) -> None:
        """
        Schedule the listener-side Report response to an MLD Query
        with the §5.1.10 random delay + coalescing rules. The
        report form (MLDv1 vs MLDv2) is selected at emit time by
        the Host Compatibility Mode, so this is version-agnostic.
        """

        delay_ms = self._mld2_query__pick_response_delay_ms(mrd_ms)

        # Delay 0 is the special "send right now" case. Bypass
        # the timer registration — the production 'Timer'
        # subsystem ticks remaining_delay from N down to 0 and
        # only fires when it hits 0, so registering with
        # delay=0 would leave the task dangling at -1 forever.
        if delay_ms == 0:
            self._mld2_query__send_now()
            return

        # The pending-response timer state is also cleared by the
        # timer-thread deferred-send, so the read-modify-write below
        # takes the interface multicast lock — without it a
        # free-threaded build could interleave this RX scheduling with
        # the timer-thread clear and orphan a timer handle or lose the
        # coalescing decision. Mirrors the IGMP query-response locking.
        with self._if._lock__multicast:
            response_at = stack.timer.now_ms + delay_ms
            pending = self._if._mld2_query__pending_response_at_ms
            if pending is not None and pending <= response_at:
                # Existing pending Report fires sooner than this new
                # Query would; absorb the Query per §5.1.10
                # coalescing rule.
                return

            if pending is not None:
                # Newer Query supersedes: cancel the old timer.
                if self._if._mld2_query__handle is not None:
                    stack.timer.cancel(self._if._mld2_query__handle)
                self._if._packet_stats_rx.icmp6__mld2_query__superseded += 1

            self._if._mld2_query__pending_response_at_ms = response_at
            self._if._mld2_query__handle = stack.timer.call_later(delay_ms, self._mld2_query__deferred_send)
            self._if._packet_stats_rx.icmp6__mld2_query__scheduled += 1

    def _mld2_query__pick_response_delay_ms(self, mrd_ms: int) -> int:
        """
        RFC 3810 §5.1.10 random-response delay selection:
        return a uniformly-random integer in [0, mrd_ms].
        Extracted as a method so tests can patch it to a
        deterministic value.
        """

        return random.randint(0, mrd_ms)

    def _mld2_query__deferred_send(self) -> None:
        """
        Timer-fired callback that emits the pending MLDv2
        Report and clears the per-handler pending state.
        """

        # Runs on the Timer thread; the pending state it clears is
        # armed by the RX Query handler under the interface multicast
        # lock, so take the same lock here (reentrant — the report
        # emit nested below does not re-enter it).
        with self._if._lock__multicast:
            self._if._mld2_query__pending_response_at_ms = None
            self._if._mld2_query__handle = None
            self._mld2_query__send_now()

    def _mld2_query__send_now(self) -> None:
        """
        Emit the listener-side MLDv2 Report and bump the
        canonical 'icmp6__mld2_query__respond' counter.
        Shared between the immediate-send (delay=0) path and
        the deferred-send (timer-fired) path.
        """

        self._if._send_icmp6_multicast_listener_report()
        self._if._packet_stats_rx.icmp6__mld2_query__respond += 1

    def __phrx_icmp6__unknown(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound unknown ICMPv6 packets.
        """

        self._if._packet_stats_rx.icmp6__unknown += 1
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received unknown ICMPv6 packet " f"from {packet_rx.ip6.src}",
        )
