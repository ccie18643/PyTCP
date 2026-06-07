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
This module contains packet handler for the inbound TCP packets.

pytcp/runtime/packet_handler/packet_handler__tcp__rx.py

ver 3.0.8
"""

from typing import TYPE_CHECKING, cast

from net_addr import IpVersion
from net_proto import PacketRx, PacketValidationError, TcpParser
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.runtime.socket import AddressFamily
from pytcp.runtime.socket.tcp__metadata import TcpMetadata
from pytcp.runtime.socket.tcp__socket import TcpSocket

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandler


class TcpRxHandler:
    """
    The inbound TCP packet handler for one interface.
    """

    _if: PacketHandler

    def __init__(self, *, interface: PacketHandler) -> None:
        """
        Bind the handler to its owning interface.
        """

        self._if = interface

    def _phrx_tcp(self, packet_rx: PacketRx, /) -> None:
        """
        Handle inbound TCP packets.
        """

        self._if._packet_stats_rx.tcp__pre_parse += 1

        try:
            TcpParser(packet_rx)

        except PacketValidationError as error:
            self._if._packet_stats_rx.tcp__failed_parse__drop += 1
            __debug__ and log(
                "tcp",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            return

        __debug__ and log("tcp", f"{packet_rx.tracker} - {packet_rx.tcp}")

        # Ensure that TCP payload type is memoryview.
        assert isinstance(
            packet_rx.tcp.payload, memoryview
        ), f"The payload must be a memoryview. Got {type(packet_rx.tcp.payload)}"

        # Create TcpMetadata object for further processing by TCP FSM.
        packet_rx_md = TcpMetadata(
            ip__ver=packet_rx.ip.ver,
            ip__ecn=packet_rx.ip.ecn,
            ip__local_address=packet_rx.ip.dst,
            tcp__local_port=packet_rx.tcp.dport,
            ip__remote_address=packet_rx.ip.src,
            tcp__remote_port=packet_rx.tcp.sport,
            tcp__flag_syn=packet_rx.tcp.flag_syn,
            tcp__flag_ack=packet_rx.tcp.flag_ack,
            tcp__flag_fin=packet_rx.tcp.flag_fin,
            tcp__flag_rst=packet_rx.tcp.flag_rst,
            tcp__flag_ece=packet_rx.tcp.flag_ece,
            tcp__flag_cwr=packet_rx.tcp.flag_cwr,
            tcp__flag_ns=packet_rx.tcp.flag_ns,
            tcp__seq=packet_rx.tcp.seq,
            tcp__ack=packet_rx.tcp.ack,
            tcp__win=packet_rx.tcp.win,
            tcp__wscale=packet_rx.tcp.wscale,
            tcp__mss=packet_rx.tcp.mss,
            tcp__sackperm=packet_rx.tcp.sackperm,
            tcp__sack_blocks=(
                ()
                if (sack_blocks := packet_rx.tcp.options.sack) is None
                else tuple((block.left, block.right) for block in sack_blocks)
            ),
            tcp__tsval=(timestamps.tsval if (timestamps := packet_rx.tcp.options.timestamps) is not None else None),
            tcp__tsecr=(
                packet_rx.tcp.options.timestamps.tsecr if packet_rx.tcp.options.timestamps is not None else None
            ),
            tcp__fastopen_cookie=packet_rx.tcp.options.fastopen,
            tcp__accecn0_counters=(
                None if (accecn := packet_rx.tcp.options.accecn) is None else (accecn.ee0b, accecn.eceb, accecn.ee1b)
            ),
            tcp__data=packet_rx.tcp.payload,
            tracker=packet_rx.tracker,
        )

        # Check if incoming packet matches active TCP socket.
        if tcp_socket := cast(TcpSocket, stack.sockets.get(packet_rx_md.socket_id, None)):
            self._if._packet_stats_rx.tcp__socket_match_active__forward_to_socket += 1
            __debug__ and log(
                "tcp",
                f"{packet_rx_md.tracker} - <INFO>TCP packet is part of active " f"socket [{tcp_socket}]</>",
            )
            tcp_socket.process_tcp_packet(packet_rx_md)
            return

        # Check if incoming packet is an initial SYN packet and if it matches any
        # listening TCP socket.
        if all({packet_rx_md.tcp__flag_syn}) and not any(
            {
                packet_rx_md.tcp__flag_ack,
                packet_rx_md.tcp__flag_fin,
                packet_rx_md.tcp__flag_rst,
            }
        ):
            for tcp_listening_socket_pattern in packet_rx_md.listening_socket_ids:
                if tcp_socket := cast(
                    TcpSocket,
                    stack.sockets.get(tcp_listening_socket_pattern, None),
                ):
                    # H3 Phase 3b cross-family dual-stack filter: an
                    # IPv4 inbound matching an AF_INET6 listener (via
                    # the wildcard '::' pattern emitted by
                    # 'listening_socket_ids') requires that listener
                    # to have 'IPV6_V6ONLY = 0'. A 'V6ONLY = 1'
                    # listener keeps its strict-IPv6 namespace —
                    # skip the match so the IPv4 inbound either
                    # finds a same-family AF_INET listener earlier
                    # in the patterns list or falls through to the
                    # no-listener drop path.
                    if (
                        tcp_socket.address_family is AddressFamily.INET6
                        and packet_rx_md.ip__local_address.version is IpVersion.IP4
                        and tcp_socket.ipv6_v6only
                    ):
                        continue
                    self._if._packet_stats_rx.tcp__socket_match_listening__forward_to_socket += 1
                    __debug__ and log(
                        "tcp",
                        f"{packet_rx_md.tracker} - <INFO>TCP packet matches " f"listening socket [{tcp_socket}]</>",
                    )
                    tcp_socket.process_tcp_packet(packet_rx_md)
                    return

        # In case packet doesn't match any active or listening socket
        # and it carries RST flag then drop it silently.
        if packet_rx_md.tcp__flag_rst:
            self._if._packet_stats_rx.tcp__no_socket_match__rst__drop += 1
            __debug__ and log(
                "tcp",
                f"{packet_rx.tracker} - TCP RST packet from {packet_rx.ip.src} to "
                f"closed port {packet_rx.tcp.dport}, dropping.",
            )
            return

        # In case packet doesn't match any session send RST packet
        # in response to it. RFC 9293 §3.10.7.1 (CLOSED state, but the
        # same rules apply to any unmatched segment) prescribes two
        # different response shapes depending on whether the offending
        # segment carries the ACK bit:
        #
        #   - ACK bit OFF: <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
        #     (We synthesize an ACK number so the offending sender's
        #      acceptability check accepts our RST.)
        #
        #   - ACK bit ON:  <SEQ=SEG.ACK><CTL=RST>
        #     (We echo the offending segment's ACK number as our SEQ
        #      so it is accepted by the sender's checks. The ACK flag
        #      is intentionally NOT set; the response is a bare RST.)
        #
        # The previous unconditional 'RST,ACK with SEQ=0, ACK=SEG.SEQ+1'
        # form was correct only for ACK-less offending segments; for
        # ACK-bearing ones (such as SYN+ACK or rogue bare ACK arriving
        # at a listening port) the spec requires the bare-RST form.
        self._if._packet_stats_rx.tcp__no_socket_match__respond_rst += 1
        __debug__ and log(
            "tcp",
            f"{packet_rx.tracker} - TCP packet from {packet_rx.ip.src} to "
            f"closed port {packet_rx.tcp.dport}, responding with TCP RST "
            "packet.",
        )
        if packet_rx.tcp.flag_ack:
            self._if._marshal_tx(
                lambda: self._if._phtx_tcp(
                    ip__src=packet_rx.ip.dst,
                    ip__dst=packet_rx.ip.src,
                    tcp__sport=packet_rx.tcp.dport,
                    tcp__dport=packet_rx.tcp.sport,
                    tcp__seq=packet_rx.tcp.ack,
                    tcp__ack=0,
                    tcp__flag_rst=True,
                    tcp__flag_ack=False,
                    echo_tracker=packet_rx.tracker,
                )
            )
        else:
            self._if._marshal_tx(
                lambda: self._if._phtx_tcp(
                    ip__src=packet_rx.ip.dst,
                    ip__dst=packet_rx.ip.src,
                    tcp__sport=packet_rx.tcp.dport,
                    tcp__dport=packet_rx.tcp.sport,
                    tcp__seq=0,
                    tcp__ack=(
                        packet_rx.tcp.seq + packet_rx.tcp.flag_syn + packet_rx.tcp.flag_fin + len(packet_rx.tcp.payload)
                    ),
                    tcp__flag_rst=True,
                    tcp__flag_ack=True,
                    echo_tracker=packet_rx.tracker,
                )
            )
