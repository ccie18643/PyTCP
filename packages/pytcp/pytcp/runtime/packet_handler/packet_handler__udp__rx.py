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
This module contains packet handler for the inbound UDP packets.

pytcp/runtime/packet_handler/packet_handler__udp__rx.py

ver 3.0.8
"""

import time
from typing import TYPE_CHECKING, cast

from net_addr import IpVersion
from net_proto import (
    Icmp4DestinationUnreachableCode,
    Icmp4MessageDestinationUnreachable,
    Icmp6DestinationUnreachableCode,
    Icmp6MessageDestinationUnreachable,
    PacketRx,
    PacketValidationError,
    UdpParser,
)
from net_proto.protocols.udp.udp__errors import UdpZeroCksumIp6Error
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.icmp.icmp__error_emitter import try_emit_icmp_error
from pytcp.protocols.icmp.icmp__inbound_classifier import classify_inbound
from pytcp.runtime.socket.udp__metadata import UdpMetadata
from pytcp.runtime.socket.udp__socket import UdpSocket

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandler


class UdpRxHandler:
    """
    The inbound UDP packet handler for one interface.
    """

    _if: PacketHandler

    def __init__(self, *, interface: PacketHandler) -> None:
        """
        Bind the handler to its owning interface.
        """

        self._if = interface

    def __phrx_udp__retry_zero_cksum_ip6(self, packet_rx: PacketRx) -> bool:
        """
        Look up any socket bound to the destination port with
        'UDP_NO_CHECK6_RX' set; if one exists, retry the parser
        with 'accept_zero_cksum_ip6=True' so the RFC 6935 §5
        alternative-mode datagram is accepted. Returns True when
        the retry succeeded (caller continues normal delivery)
        and False when no opted-in socket was found (caller
        drops with the default-mode counter bump).
        """

        # UDP header byte layout (RFC 768): bytes 0-1 = sport,
        # 2-3 = dport. Peek both directly from the raw frame;
        # the parser raised before 'packet_rx.udp' could be set.
        raw_sport = int.from_bytes(packet_rx.frame[0:2])
        raw_dport = int.from_bytes(packet_rx.frame[2:4])

        candidate_md = UdpMetadata(
            ip__ver=packet_rx.ip.ver,
            ip__local_address=packet_rx.ip.dst,
            udp__local_port=raw_dport,
            ip__remote_address=packet_rx.ip.src,
            udp__remote_port=raw_sport,
        )
        for socket_id in candidate_md.socket_ids:
            socket = cast(
                UdpSocket | None, stack.sockets.get_for_ingress(socket_id, ifindex=self._if._ifindex, default=None)
            )
            if socket is not None and socket.udp_no_check6_rx:
                UdpParser(packet_rx, accept_zero_cksum_ip6=True)
                return True
        return False

    def __phrx_udp__multicast_source_allowed(self, socket: UdpSocket, packet_rx: PacketRx) -> bool:
        """
        Apply the RFC 3376 §3.1 data-plane source-delivery filter (Linux
        'ip_mc_sf_allow') for a candidate socket. An IPv4 multicast
        datagram is admitted only if the socket's source filter for this
        (interface, group) admits the datagram's source; a socket with no
        per-(interface, group) source filter keeps the existing
        any-source delivery. Non-multicast and IPv6 datagrams are never
        gated here.
        """

        if packet_rx.ip.ver is not IpVersion.IP4 or not packet_rx.ip4.dst.is_multicast:
            return True

        # Delegate to the lock-guarded per-socket source-admit gate so
        # the RX read of the socket's source-filter map is serialized
        # against an application-thread setsockopt under no-GIL.
        return socket.ip4_multicast_source_admits(
            ifindex=self._if._ifindex,
            group=packet_rx.ip4.dst,
            source=packet_rx.ip4.src,
        )

    def _phrx_udp(self, packet_rx: PacketRx, /) -> None:
        """
        Handle inbound UDP packets.
        """

        self._if._packet_stats_rx.udp__pre_parse += 1

        try:
            UdpParser(packet_rx)

        except UdpZeroCksumIp6Error as error:
            # RFC 8200 §8.1 / RFC 6935 §5: default-mode silent
            # discard. Before dropping, check the RFC 6935 §5
            # per-port opt-in: if any socket bound to the
            # destination port has 'UDP_NO_CHECK6_RX' set, the
            # tunnel-encapsulation alternative mode accepts
            # the datagram and the parse retries with the
            # bypass enabled. Peek dport from the raw UDP
            # header (bytes 2-3) — the parser raised before
            # 'packet_rx.udp' was set.
            if not self.__phrx_udp__retry_zero_cksum_ip6(packet_rx):
                self._if._packet_stats_rx.udp__ip6_zero_cksum__drop += 1
                __debug__ and log(
                    "udp",
                    f"{packet_rx.tracker} - <CRIT>{error}</>",
                )
                return

        except PacketValidationError as error:
            self._if._packet_stats_rx.udp__failed_parse__drop += 1
            __debug__ and log(
                "udp",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            return

        __debug__ and log("udp", f"{packet_rx.tracker} - {packet_rx.udp}")

        # Ensure that UDP payload type is memoryview.
        assert isinstance(
            packet_rx.udp.payload, memoryview
        ), f"The payload must be a memoryview. Got {type(packet_rx.udp.payload)}"

        # Create UdpMetadata object and try to find matching UDP
        # socket. 'ip4__options' surfaces the inbound IPv4 options
        # block (RFC 1122 §4.1.3.2) to recvmsg-emitted IP_OPTIONS
        # cmsg; 'None' for IPv6 datagrams and for IPv4 datagrams
        # without options. 'ip__tos' carries the combined
        # DSCP+ECN byte (RFC 1122 §4.1.4 / RFC 3542 §6.5) for
        # recvmsg-emitted IP_TOS / IPV6_TCLASS cmsg.
        ip4__options = packet_rx.ip4.options if packet_rx.ip.ver is IpVersion.IP4 and packet_rx.ip4.options else None
        packet_rx_md = UdpMetadata(
            ip__ver=packet_rx.ip.ver,
            ip__local_address=packet_rx.ip.dst,
            udp__local_port=packet_rx.udp.dport,
            ip__remote_address=packet_rx.ip.src,
            udp__remote_port=packet_rx.udp.sport,
            udp__data=packet_rx.udp.payload,
            ip4__options=ip4__options,
            ip__tos=(packet_rx.ip.dscp << 2) | packet_rx.ip.ecn,
            tracker=packet_rx.tracker,
        )

        for socket_id in packet_rx_md.socket_ids:
            socket = cast(
                UdpSocket | None, stack.sockets.get_for_ingress(socket_id, ifindex=self._if._ifindex, default=None)
            )
            if socket is None:
                continue
            # RFC 3376 §3.1 / Linux 'ip_mc_sf_allow' data-plane
            # source filter: an IPv4 multicast datagram is delivered
            # to a socket only if the socket's source filter for this
            # (interface, group) admits the source. A socket with no
            # source filter (no source-API join) keeps the existing
            # any-source delivery; a filtered-out source falls through
            # to the next candidate socket.
            if not self.__phrx_udp__multicast_source_allowed(socket, packet_rx):
                self._if._packet_stats_rx.udp__multicast_source_filtered__drop += 1
                __debug__ and log(
                    "udp",
                    f"{packet_rx_md.tracker} - <INFO>Source {packet_rx.ip.src} filtered "
                    f"for socket [{socket}] on group {packet_rx.ip.dst}</>",
                )
                continue
            self._if._packet_stats_rx.udp__socket_match += 1
            __debug__ and log(
                "udp",
                f"{packet_rx_md.tracker} - <INFO>Found matching listening " f"socket [{socket}]</>",
            )
            socket.process_udp_packet(packet_rx_md)
            return

        # Silently drop packet if it's source address is unspecified.
        if packet_rx.ip.src.is_unspecified:
            self._if._packet_stats_rx.udp__ip_source_unspecified += 1
            __debug__ and log(
                "udp",
                f"{packet_rx_md.tracker} - Received UDP packet from "
                f"{packet_rx.ip.src}, port {packet_rx.udp.sport} to "
                f"{packet_rx.ip.dst}, port {packet_rx.udp.dport}, dropping",
            )
            return

        # Handle the UDP Echo operation in case its enabled
        # (used for packet flow unit testing only).
        if stack.UDP__ECHO_NATIVE and packet_rx.udp.dport == 7:
            self._if._packet_stats_rx.udp__echo_native__respond_udp += 1
            __debug__ and log(
                "udp",
                f"{packet_rx_md.tracker} - <INFO>Performing native " "UDP Echo operation</>",
            )

            self._if._marshal_tx(
                lambda: self._if._phtx_udp(
                    ip__src=packet_rx.ip.dst,
                    ip__dst=packet_rx.ip.src,
                    udp__sport=packet_rx.udp.dport,
                    udp__dport=packet_rx.udp.sport,
                    udp__payload=packet_rx.udp.payload,
                )
            )
            return

        # Respond with ICMP Port Unreachable message if no matching
        # socket has been found, subject to the host-requirements
        # gates and the outbound rate limit.
        rate_limiter = (
            stack.icmp4_error_rate_limiter if packet_rx.ip.ver is IpVersion.IP4 else stack.icmp6_error_rate_limiter
        )
        verdict = try_emit_icmp_error(
            classify_inbound(packet_rx),
            rate_limiter=rate_limiter,
            now=time.monotonic(),
        )
        if verdict is not None:
            if packet_rx.ip.ver is IpVersion.IP4:
                self._if._packet_stats_rx.udp__no_socket_match__icmp4_unreachable_suppressed += 1
            else:
                self._if._packet_stats_rx.udp__no_socket_match__icmp6_unreachable_suppressed += 1
            __debug__ and log(
                "udp",
                f"{packet_rx_md.tracker} - <WARN>Suppressing ICMP Port-Unreachable "
                f"to {packet_rx.ip.src}: {verdict}</>",
            )
            return

        __debug__ and log(
            "udp",
            f"{packet_rx_md.tracker} - Received UDP packet from "
            f"{packet_rx.ip.src} to closed port "
            f"{packet_rx.udp.dport}, sending ICMPv4 Port Unreachable",
        )

        match packet_rx.ip.ver:
            case IpVersion.IP6:
                self._if._packet_stats_rx.udp__no_socket_match__respond_icmp6_unreachable += 1
                self._if._marshal_tx(
                    lambda: self._if._phtx_icmp6(
                        ip6__src=packet_rx.ip6.dst,
                        ip6__dst=packet_rx.ip6.src,
                        icmp6__message=Icmp6MessageDestinationUnreachable(
                            code=Icmp6DestinationUnreachableCode.PORT,
                            data=packet_rx.ip.packet_bytes,
                        ),
                        echo_tracker=packet_rx.tracker,
                    )
                )
            case IpVersion.IP4:
                self._if._packet_stats_rx.udp__no_socket_match__respond_icmp4_unreachable += 1
                self._if._marshal_tx(
                    lambda: self._if._phtx_icmp4(
                        ip4__src=packet_rx.ip4.dst,
                        ip4__dst=packet_rx.ip4.src,
                        icmp4__message=Icmp4MessageDestinationUnreachable(
                            code=Icmp4DestinationUnreachableCode.PORT,
                            data=packet_rx.ip.packet_bytes,
                        ),
                        echo_tracker=packet_rx.tracker,
                    )
                )
