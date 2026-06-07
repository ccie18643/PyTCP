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
This module contains packet handler for the inbound ICMPv4 packets.

pytcp/runtime/packet_handler/packet_handler__icmp4__rx.py

ver 3.0.8
"""

from typing import TYPE_CHECKING, cast

from net_addr import Ip4Address, IpVersion
from net_proto import (
    Icmp4DestinationUnreachableCode,
    Icmp4MessageDestinationUnreachable,
    Icmp4MessageEchoReply,
    Icmp4MessageEchoRequest,
    Icmp4MessageParameterProblem,
    Icmp4MessageTimeExceeded,
    Icmp4ParameterProblemCode,
    Icmp4Parser,
    Icmp4TimeExceededCode,
    Icmp4Type,
    IpProto,
    PacketRx,
    PacketValidationError,
)
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.icmp4.icmp4__echo_gate import should_emit_echo_reply
from pytcp.protocols.icmp4.icmp4__echo_options import echo_reply_options
from pytcp.protocols.icmp.icmp__error_demux import EmbeddedL4, parse_embedded_l4
from pytcp.protocols.tcp.tcp__icmp_metadata import IcmpCategory, IcmpMetadata
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.runtime.socket.error_queue import SoEeOrigin
from pytcp.runtime.socket.ping__metadata import PingMetadata
from pytcp.runtime.socket.socket_id import SocketId
from pytcp.runtime.socket.tcp__socket import TcpSocket
from pytcp.runtime.socket.udp__metadata import UdpMetadata
from pytcp.runtime.socket.udp__socket import UdpSocket

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandler


class Icmp4RxHandler:
    """
    The inbound ICMPv4 packet handler for one interface.
    """

    _if: PacketHandler

    def __init__(self, *, interface: PacketHandler) -> None:
        """
        Bind the handler to its owning interface.
        """

        self._if = interface

    def _phrx_icmp4(self, packet_rx: PacketRx, /) -> None:
        """
        Handle inbound ICMPv4 packets.
        """

        self._if._packet_stats_rx.icmp4__pre_parse += 1

        try:
            Icmp4Parser(packet_rx)

        except PacketValidationError as error:
            __debug__ and log(
                "icmp4",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            self._if._packet_stats_rx.icmp4__failed_parse__drop += 1
            return

        __debug__ and log("icmp4", f"{packet_rx.tracker} - {packet_rx.icmp4}")

        match packet_rx.icmp4.message.type:
            case Icmp4Type.ECHO_REPLY:
                self.__phrx_icmp4__echo_reply(packet_rx)
            case Icmp4Type.DESTINATION_UNREACHABLE:
                self.__phrx_icmp4__destination_unreachable(packet_rx)
            case Icmp4Type.ECHO_REQUEST:
                self.__phrx_icmp4__echo_request(packet_rx)
            case Icmp4Type.TIME_EXCEEDED:
                self.__phrx_icmp4__time_exceeded(packet_rx)
            case Icmp4Type.PARAMETER_PROBLEM:
                self.__phrx_icmp4__parameter_problem(packet_rx)
            case _:
                self.__phrx_icmp4__unknown(packet_rx)

    def __phrx_icmp4__echo_reply(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv4 Echo Reply packets.
        """

        assert isinstance(packet_rx.icmp4.message, Icmp4MessageEchoReply)

        __debug__ and log(
            "icmp4",
            f"{packet_rx.tracker} - Received ICMPv4 Echo Reply packet " f"from {packet_rx.ip4.src}",
        )
        self._if._packet_stats_rx.icmp4__echo_reply += 1

        # Demux to a ping socket (Linux 'SOCK_DGRAM' / 'IPPROTO_ICMP') by
        # the Echo Reply's ICMP id. The owning socket receives the ICMP
        # message bytes (no IP header) plus the reply's TTL for an
        # 'IP_TTL' cmsg.
        message = packet_rx.icmp4.message
        ping_socket = stack.icmp_echo_sockets.get((AddressFamily.INET4, message.id))
        if ping_socket is not None and ping_socket.accepts_reply_to(packet_rx.ip4.dst):
            ping_socket.process_echo_reply(
                PingMetadata(
                    ip__ver=packet_rx.ip.ver,
                    ip__remote_address=packet_rx.ip4.src,
                    ip__ttl=packet_rx.ip4.ttl,
                    icmp__data=bytes(message),
                )
            )

        # An inbound Echo Reply is also delivered to matching RAW sockets
        # by the IPv4 RX path ('packet_handler__ip4__rx'), which clones the
        # full IPv4 packet to every matching raw socket (Linux
        # 'raw_local_deliver').

    def __phrx_icmp4__destination_unreachable(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv4 Destination Unreachable packets. The
        Code 4 (Fragmentation Needed and DF Set) subcase carries the
        next-hop MTU per RFC 1191 §3 and is dispatched to the PMTUD
        path; every other code routes to the UDP-socket
        notify_unreachable lookup.
        """

        assert isinstance(packet_rx.icmp4.message, Icmp4MessageDestinationUnreachable)

        message = packet_rx.icmp4.message

        __debug__ and log(
            "icmp4",
            f"{packet_rx.tracker} - Received ICMPv4 Destination Unreachable packet "
            f"from {packet_rx.ip4.src}, code={message.code}",
        )
        self._if._packet_stats_rx.icmp4__destination_unreachable += 1

        is_frag_needed = message.code == Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED
        if is_frag_needed:
            self._if._packet_stats_rx.icmp4__destination_unreachable__fragmentation_needed += 1

        embedded = parse_embedded_l4(message.data, IpVersion.IP4)
        if embedded is None:
            __debug__ and log(
                "icmp4",
                f"{packet_rx.tracker} - Unreachable data doesn't pass basic " "IPv4/UDP integrity check",
            )
            return

        if embedded.proto is IpProto.UDP:
            self.__phrx_icmp4__dispatch_udp(packet_rx, embedded, message, is_frag_needed=is_frag_needed)
            return

        if embedded.proto is IpProto.TCP:
            self.__phrx_icmp4__dispatch_tcp(
                packet_rx,
                embedded,
                message,
                is_frag_needed=is_frag_needed,
            )
            return

    def __phrx_icmp4__dispatch_udp(
        self,
        packet_rx: PacketRx,
        embedded: EmbeddedL4,
        message: Icmp4MessageDestinationUnreachable,
        *,
        is_frag_needed: bool,
    ) -> None:
        """
        Route an ICMPv4 Destination Unreachable carrying an embedded
        UDP segment to the matching UdpSocket. Code-4 Frag-Needed
        triggers notify_pmtu; every other code triggers
        notify_unreachable.
        """

        packet = UdpMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=cast(Ip4Address, embedded.local_ip),
            ip__remote_address=cast(Ip4Address, embedded.remote_ip),
            udp__local_port=embedded.local_port,
            udp__remote_port=embedded.remote_port,
        )

        for socket_id in packet.socket_ids:
            if socket := cast(UdpSocket, stack.sockets.get(socket_id, None)):
                __debug__ and log(
                    "icmp4",
                    f"{packet_rx.tracker} - <INFO>Found matching "
                    f"listening UDP socket {socket}, for Unreachable "
                    f"packet from {packet_rx.ip4.src}</>",
                )
                embedded_datagram = bytes(message.data)
                offender_ip = packet_rx.ip4.src
                if is_frag_needed and message.mtu is not None:
                    stack.record_classical_pmtu(cast(Ip4Address, embedded.remote_ip), message.mtu)
                    socket.notify_pmtu(
                        next_hop_mtu=message.mtu,
                        icmp_origin=SoEeOrigin.ICMP,
                        icmp_type=Icmp4Type.DESTINATION_UNREACHABLE,
                        icmp_code=message.code,
                        offender_ip=offender_ip,
                        embedded_datagram=embedded_datagram,
                    )
                    self._if._packet_stats_rx.icmp4__destination_unreachable__fragmentation_needed__notify_pmtu += 1
                else:
                    socket.notify_unreachable(
                        icmp_origin=SoEeOrigin.ICMP,
                        icmp_type=Icmp4Type.DESTINATION_UNREACHABLE,
                        icmp_code=message.code,
                        offender_ip=offender_ip,
                        embedded_datagram=embedded_datagram,
                    )
                return

        __debug__ and log(
            "icmp4",
            f"{packet_rx.tracker} - Unreachable data doesn't match " "any UDP socket",
        )

    def __phrx_icmp4__dispatch_tcp(
        self,
        packet_rx: PacketRx,
        embedded: EmbeddedL4,
        message: Icmp4MessageDestinationUnreachable,
        *,
        is_frag_needed: bool,
    ) -> None:
        """
        Route an ICMPv4 Destination Unreachable carrying an embedded
        TCP segment to the matching TcpSession via TcpSocket. Applies
        the RFC 5927 §4 sequence-in-window guard. Code-4 Frag-Needed
        with a non-None mtu drives the PMTU FSM event; every other
        code drives a DEST_UNREACHABLE FSM event. In addition, the
        matched TcpSocket is notified via 'notify_pmtu' /
        'notify_unreachable' so 'recvmsg(MSG_ERRQUEUE)' applications
        with IP_RECVERR set see the ICMP context.
        """

        socket_id = SocketId(
            address_family=AddressFamily.INET4,
            socket_type=SocketType.STREAM,
            local_address=cast(Ip4Address, embedded.local_ip),
            local_port=embedded.local_port,
            remote_address=cast(Ip4Address, embedded.remote_ip),
            remote_port=embedded.remote_port,
        )

        socket = cast(TcpSocket, stack.sockets.get(socket_id, None))
        if socket is None or (session := socket.tcp_session) is None:
            return

        # RFC 5927 §4 sequence-in-window guard.
        if embedded.embedded_seq is not None and not session.is_seq_in_window(embedded.embedded_seq):
            self._if._packet_stats_rx.icmp4__destination_unreachable__tcp__seq_out_of_window__drop += 1
            return

        embedded_datagram = bytes(message.data)
        offender_ip = packet_rx.ip4.src

        if is_frag_needed and message.mtu is not None:
            __debug__ and log(
                "icmp4",
                f"{packet_rx.tracker} - <INFO>Found matching TCP session "
                f"for Frag-Needed from {packet_rx.ip4.src}, mtu={message.mtu}</>",
            )
            session.tcp_fsm(
                icmp=IcmpMetadata(
                    category=IcmpCategory.PMTU,
                    icmp_type=3,
                    icmp_code=4,
                    next_hop_mtu=message.mtu,
                    ip_version=4,
                ),
            )
            socket.notify_pmtu(
                next_hop_mtu=message.mtu,
                icmp_origin=SoEeOrigin.ICMP,
                icmp_type=Icmp4Type.DESTINATION_UNREACHABLE,
                icmp_code=message.code,
                offender_ip=offender_ip,
                embedded_datagram=embedded_datagram,
            )
            self._if._packet_stats_rx.icmp4__destination_unreachable__fragmentation_needed__notify_pmtu += 1
            return

        __debug__ and log(
            "icmp4",
            f"{packet_rx.tracker} - <INFO>Found matching TCP session "
            f"for Unreachable packet from {packet_rx.ip4.src}</>",
        )
        session.tcp_fsm(
            icmp=IcmpMetadata(
                category=IcmpCategory.DEST_UNREACHABLE,
                icmp_type=3,
                icmp_code=int(message.code),
                ip_version=4,
            ),
        )
        socket.notify_unreachable(
            icmp_origin=SoEeOrigin.ICMP,
            icmp_type=Icmp4Type.DESTINATION_UNREACHABLE,
            icmp_code=message.code,
            offender_ip=offender_ip,
            embedded_datagram=embedded_datagram,
        )
        self._if._packet_stats_rx.icmp4__destination_unreachable__tcp__notify += 1

    def __phrx_icmp4__time_exceeded(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv4 Time Exceeded packets. Routes the
        embedded L4 segment to the matching TCP / UDP socket as a
        soft-error notification per RFC 1122 §3.2.2.4 and RFC 5927
        §6. TCP demux applies the RFC 5927 §4 sequence-in-window
        guard to mitigate forged off-path errors.
        """

        assert isinstance(packet_rx.icmp4.message, Icmp4MessageTimeExceeded)

        message = packet_rx.icmp4.message

        __debug__ and log(
            "icmp4",
            f"{packet_rx.tracker} - Received ICMPv4 Time Exceeded packet "
            f"from {packet_rx.ip4.src}, code={message.code}",
        )
        self._if._packet_stats_rx.icmp4__time_exceeded += 1

        embedded = parse_embedded_l4(message.data, IpVersion.IP4)
        if embedded is None:
            __debug__ and log(
                "icmp4",
                f"{packet_rx.tracker} - Time Exceeded data doesn't pass basic IPv4/L4 integrity check",
            )
            return

        if embedded.proto is IpProto.UDP:
            self.__phrx_icmp4__time_exceeded__dispatch_udp(
                packet_rx,
                embedded,
                icmp_code=message.code,
                embedded_datagram=bytes(message.data),
            )
            return

        if embedded.proto is IpProto.TCP:
            self.__phrx_icmp4__time_exceeded__dispatch_tcp(packet_rx, embedded, message)
            return

    def __phrx_icmp4__time_exceeded__dispatch_udp(
        self,
        packet_rx: PacketRx,
        embedded: EmbeddedL4,
        *,
        icmp_code: Icmp4TimeExceededCode,
        embedded_datagram: bytes,
    ) -> None:
        """
        Route an ICMPv4 Time Exceeded carrying an embedded UDP segment
        to the matching UdpSocket via notify_time_exceeded().
        """

        packet = UdpMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=cast(Ip4Address, embedded.local_ip),
            ip__remote_address=cast(Ip4Address, embedded.remote_ip),
            udp__local_port=embedded.local_port,
            udp__remote_port=embedded.remote_port,
        )

        for socket_id in packet.socket_ids:
            if socket := cast(UdpSocket, stack.sockets.get(socket_id, None)):
                __debug__ and log(
                    "icmp4",
                    f"{packet_rx.tracker} - <INFO>Found matching UDP socket "
                    f"{socket} for Time Exceeded from {packet_rx.ip4.src}</>",
                )
                socket.notify_time_exceeded(
                    icmp_type=Icmp4Type.TIME_EXCEEDED,
                    icmp_code=icmp_code,
                    icmp_origin=SoEeOrigin.ICMP,
                    offender_ip=packet_rx.ip4.src,
                    embedded_datagram=embedded_datagram,
                )
                self._if._packet_stats_rx.icmp4__time_exceeded__udp__notify += 1
                return

        __debug__ and log(
            "icmp4",
            f"{packet_rx.tracker} - Time Exceeded data doesn't match any UDP socket",
        )

    def __phrx_icmp4__time_exceeded__dispatch_tcp(
        self,
        packet_rx: PacketRx,
        embedded: EmbeddedL4,
        message: Icmp4MessageTimeExceeded,
    ) -> None:
        """
        Route an ICMPv4 Time Exceeded carrying an embedded TCP segment
        to the matching TcpSession via TcpSocket. Applies the RFC 5927
        §4 sequence-in-window guard before notifying the session, and
        also pushes the ICMP context onto the matched TcpSocket's
        IP_RECVERR error queue.
        """

        socket_id = SocketId(
            address_family=AddressFamily.INET4,
            socket_type=SocketType.STREAM,
            local_address=cast(Ip4Address, embedded.local_ip),
            local_port=embedded.local_port,
            remote_address=cast(Ip4Address, embedded.remote_ip),
            remote_port=embedded.remote_port,
        )

        socket = cast(TcpSocket, stack.sockets.get(socket_id, None))
        if socket is None or (session := socket.tcp_session) is None:
            return

        if embedded.embedded_seq is not None and not session.is_seq_in_window(embedded.embedded_seq):
            self._if._packet_stats_rx.icmp4__time_exceeded__tcp__seq_out_of_window__drop += 1
            return

        __debug__ and log(
            "icmp4",
            f"{packet_rx.tracker} - <INFO>Found matching TCP session " f"for Time Exceeded from {packet_rx.ip4.src}</>",
        )
        session.tcp_fsm(
            icmp=IcmpMetadata(
                category=IcmpCategory.TIME_EXCEEDED,
                icmp_type=11,
                icmp_code=int(message.code),
                ip_version=4,
            ),
        )
        socket.notify_time_exceeded(
            icmp_type=Icmp4Type.TIME_EXCEEDED,
            icmp_code=message.code,
            icmp_origin=SoEeOrigin.ICMP,
            offender_ip=packet_rx.ip4.src,
            embedded_datagram=bytes(message.data),
        )
        self._if._packet_stats_rx.icmp4__time_exceeded__tcp__notify += 1

    def __phrx_icmp4__parameter_problem(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv4 Parameter Problem packets. Routes the
        embedded L4 segment to the matching TCP / UDP socket as a
        soft-error notification per RFC 1122 §3.2.2.5 and RFC 5927
        §6. TCP demux applies the RFC 5927 §4 sequence-in-window
        guard to mitigate forged off-path errors.
        """

        assert isinstance(packet_rx.icmp4.message, Icmp4MessageParameterProblem)

        message = packet_rx.icmp4.message

        __debug__ and log(
            "icmp4",
            f"{packet_rx.tracker} - Received ICMPv4 Parameter Problem packet "
            f"from {packet_rx.ip4.src}, code={message.code}, pointer={message.pointer}",
        )
        self._if._packet_stats_rx.icmp4__parameter_problem += 1

        embedded = parse_embedded_l4(message.data, IpVersion.IP4)
        if embedded is None:
            __debug__ and log(
                "icmp4",
                f"{packet_rx.tracker} - Parameter Problem data doesn't pass basic IPv4/L4 integrity check",
            )
            return

        if embedded.proto is IpProto.UDP:
            self.__phrx_icmp4__parameter_problem__dispatch_udp(
                packet_rx,
                embedded,
                icmp_code=message.code,
                embedded_datagram=bytes(message.data),
            )
            return

        if embedded.proto is IpProto.TCP:
            self.__phrx_icmp4__parameter_problem__dispatch_tcp(packet_rx, embedded, message)
            return

    def __phrx_icmp4__parameter_problem__dispatch_udp(
        self,
        packet_rx: PacketRx,
        embedded: EmbeddedL4,
        *,
        icmp_code: Icmp4ParameterProblemCode,
        embedded_datagram: bytes,
    ) -> None:
        """
        Route an ICMPv4 Parameter Problem carrying an embedded UDP
        segment to the matching UdpSocket via notify_parameter_problem().
        """

        packet = UdpMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=cast(Ip4Address, embedded.local_ip),
            ip__remote_address=cast(Ip4Address, embedded.remote_ip),
            udp__local_port=embedded.local_port,
            udp__remote_port=embedded.remote_port,
        )

        for socket_id in packet.socket_ids:
            if socket := cast(UdpSocket, stack.sockets.get(socket_id, None)):
                __debug__ and log(
                    "icmp4",
                    f"{packet_rx.tracker} - <INFO>Found matching UDP socket "
                    f"{socket} for Parameter Problem from {packet_rx.ip4.src}</>",
                )
                socket.notify_parameter_problem(
                    icmp_type=Icmp4Type.PARAMETER_PROBLEM,
                    icmp_code=icmp_code,
                    icmp_origin=SoEeOrigin.ICMP,
                    offender_ip=packet_rx.ip4.src,
                    embedded_datagram=embedded_datagram,
                )
                self._if._packet_stats_rx.icmp4__parameter_problem__udp__notify += 1
                return

        __debug__ and log(
            "icmp4",
            f"{packet_rx.tracker} - Parameter Problem data doesn't match any UDP socket",
        )

    def __phrx_icmp4__parameter_problem__dispatch_tcp(
        self,
        packet_rx: PacketRx,
        embedded: EmbeddedL4,
        message: Icmp4MessageParameterProblem,
    ) -> None:
        """
        Route an ICMPv4 Parameter Problem carrying an embedded TCP
        segment to the matching TcpSession via TcpSocket. Applies
        the RFC 5927 §4 sequence-in-window guard before notifying.
        Also pushes the ICMP context onto the matched TcpSocket's
        IP_RECVERR error queue.
        """

        socket_id = SocketId(
            address_family=AddressFamily.INET4,
            socket_type=SocketType.STREAM,
            local_address=cast(Ip4Address, embedded.local_ip),
            local_port=embedded.local_port,
            remote_address=cast(Ip4Address, embedded.remote_ip),
            remote_port=embedded.remote_port,
        )

        socket = cast(TcpSocket, stack.sockets.get(socket_id, None))
        if socket is None or (session := socket.tcp_session) is None:
            return

        if embedded.embedded_seq is not None and not session.is_seq_in_window(embedded.embedded_seq):
            self._if._packet_stats_rx.icmp4__parameter_problem__tcp__seq_out_of_window__drop += 1
            return

        __debug__ and log(
            "icmp4",
            f"{packet_rx.tracker} - <INFO>Found matching TCP session "
            f"for Parameter Problem from {packet_rx.ip4.src}</>",
        )
        session.tcp_fsm(
            icmp=IcmpMetadata(
                category=IcmpCategory.PARAM_PROBLEM,
                icmp_type=12,
                icmp_code=int(message.code),
                ip_version=4,
            ),
        )
        socket.notify_parameter_problem(
            icmp_type=Icmp4Type.PARAMETER_PROBLEM,
            icmp_code=message.code,
            icmp_origin=SoEeOrigin.ICMP,
            offender_ip=packet_rx.ip4.src,
            embedded_datagram=bytes(message.data),
        )
        self._if._packet_stats_rx.icmp4__parameter_problem__tcp__notify += 1

    def __phrx_icmp4__echo_request(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv4 Echo Request packets. Drops requests
        whose IPv4 destination is a broadcast or multicast address
        (Smurf-attack mitigation, RFC 1122 §3.2.2.6 / RFC 1812
        §4.3.3.6); replies to all other requests.
        """

        assert isinstance(packet_rx.icmp4.message, Icmp4MessageEchoRequest)

        if not should_emit_echo_reply(
            dst_is_broadcast=packet_rx.ip4.dst.is_limited_broadcast,
            dst_is_multicast=packet_rx.ip4.dst.is_multicast,
        ):
            self._if._packet_stats_rx.icmp4__echo_request__bcast_or_mcast__drop += 1
            __debug__ and log(
                "icmp4",
                f"{packet_rx.tracker} - <WARN>Dropping ICMPv4 Echo Request "
                f"from {packet_rx.ip4.src} to {packet_rx.ip4.dst} "
                f"(bcast/mcast destination — Smurf mitigation)</>",
            )
            return

        __debug__ and log(
            "icmp4",
            f"{packet_rx.tracker} - <INFO>Received ICMPv4 Echo Request "
            f"packet from {packet_rx.ip4.src}, sending reply</>",
        )
        self._if._packet_stats_rx.icmp4__echo_request__respond_echo_reply += 1

        # Build the reply message in the enclosing scope (where the
        # isinstance-narrowing on 'packet_rx.icmp4.message' holds)
        # rather than inside the marshaled closure.
        echo_reply_message = Icmp4MessageEchoReply(
            id=packet_rx.icmp4.message.id,
            seq=packet_rx.icmp4.message.seq,
            data=packet_rx.icmp4.message.data,
        )
        echo_reply_options_ = echo_reply_options(packet_rx.ip4.options)
        # A reply to a multicast / broadcast Echo Request (reachable only
        # when 'icmp4.echo_ignore_broadcasts' is 0) cannot be sourced from
        # the group / broadcast destination — source it from the
        # interface's unicast address instead (RFC 1122 §3.2.2.6).
        if (packet_rx.ip4.dst.is_multicast or packet_rx.ip4.dst.is_limited_broadcast) and self._if._ip4_unicast:
            reply_src = self._if._ip4_unicast[0]
        else:
            reply_src = packet_rx.ip4.dst
        self._if._marshal_tx(
            lambda: self._if._phtx_icmp4(
                ip4__src=reply_src,
                ip4__dst=packet_rx.ip4.src,
                ip4__options=echo_reply_options_,
                icmp4__message=echo_reply_message,
                echo_tracker=packet_rx.tracker,
            )
        )

    def __phrx_icmp4__unknown(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv4 packets with unknown type.
        """

        __debug__ and log(
            "icmp4",
            f"{packet_rx.tracker} - Received unknown ICMPv4 packet " f"from {packet_rx.ip4.src}",
        )
        self._if._packet_stats_rx.icmp4__unknown += 1
