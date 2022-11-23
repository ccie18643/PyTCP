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

# pylint: disable = expression-not-assigned
# pylint: disable = protected-access

"""
Module contains packet handler for the inbound TCP packets.

pytcp/protocols/tcp/phrx.py

ver 2.7
"""


from __future__ import annotations

from typing import TYPE_CHECKING

from pytcp.lib import stack
from pytcp.lib.logger import log
from pytcp.lib.packet import PacketRx
from pytcp.protocols.tcp.fpp import TcpParser
from pytcp.protocols.tcp.metadata import TcpMetadata

if TYPE_CHECKING:
    from pytcp.subsystems.packet_handler import PacketHandler


def _phrx_tcp(self: PacketHandler, packet_rx: PacketRx) -> None:
    """
    Handle inbound TCP packets.
    """

    self.packet_stats_rx.tcp__pre_parse += 1

    TcpParser(packet_rx)

    if packet_rx.parse_failed:
        self.packet_stats_rx.tcp__failed_parse__drop += 1
        __debug__ and log(
            "tcp",
            f"{packet_rx.tracker} - <CRIT>{packet_rx.parse_failed}</>",
        )
        return

    __debug__ and log("tcp", f"{packet_rx.tracker} - {packet_rx.tcp}")

    assert isinstance(
        packet_rx.tcp.data, memoryview
    )  # memoryview: data type check point

    # Create TcpMetadata object for further processing by TCP FSM
    packet_rx_md = TcpMetadata(
        local_ip_address=packet_rx.ip.dst,
        local_port=packet_rx.tcp.dport,
        remote_ip_address=packet_rx.ip.src,
        remote_port=packet_rx.tcp.sport,
        flag_syn=packet_rx.tcp.flag_syn,
        flag_ack=packet_rx.tcp.flag_ack,
        flag_fin=packet_rx.tcp.flag_fin,
        flag_rst=packet_rx.tcp.flag_rst,
        seq=packet_rx.tcp.seq,
        ack=packet_rx.tcp.ack,
        win=packet_rx.tcp.win,
        wscale=packet_rx.tcp.wscale,
        mss=packet_rx.tcp.mss,
        data=packet_rx.tcp.data,  # memoryview: passing as memoryview for tcp
        # session to consume, no need to convert to
        # bytes here
        tracker=packet_rx.tracker,
    )

    # Check if incoming packet matches active TCP socket.
    if tcp_socket := stack.sockets.get(str(packet_rx_md), None):
        self.packet_stats_rx.tcp__socket_match_active__forward_to_socket += 1
        __debug__ and log(
            "tcp",
            f"{packet_rx_md.tracker} - <INFO>TCP packet is part of active "
            f"socket [{tcp_socket}]</>",
        )
        tcp_socket.process_tcp_packet(packet_rx_md)
        return

    # Check if incoming packet is an initial SYN packet and if it matches any
    # listening TCP socket.
    if all({packet_rx_md.flag_syn}) and not any(
        {packet_rx_md.flag_ack, packet_rx_md.flag_fin, packet_rx_md.flag_rst}
    ):
        for (
            tcp_listening_socket_pattern
        ) in packet_rx_md.tcp_listening_socket_patterns:
            if tcp_socket := stack.sockets.get(
                tcp_listening_socket_pattern, None
            ):
                self.packet_stats_rx.tcp__socket_match_listening__forward_to_socket += (
                    1
                )
                __debug__ and log(
                    "tcp",
                    f"{packet_rx_md.tracker} - <INFO>TCP packet matches "
                    f"listening socket [{tcp_socket}]</>",
                )
                tcp_socket.process_tcp_packet(packet_rx_md)
                return

    # In case packet doesn't match any session send RST packet
    # in response to it.
    self.packet_stats_rx.tcp__no_socket_match__respond_rst += 1
    __debug__ and log(
        "tcp",
        f"{packet_rx.tracker} - TCP packet from {packet_rx.ip.src} to "
        f"closed port {packet_rx.tcp.dport}, responding with TCP RST "
        "packet",
    )
    self._phtx_tcp(
        ip_src=packet_rx.ip.dst,
        ip_dst=packet_rx.ip.src,
        tcp_sport=packet_rx.tcp.dport,
        tcp_dport=packet_rx.tcp.sport,
        tcp_seq=0,
        tcp_ack=packet_rx.tcp.seq
        + packet_rx.tcp.flag_syn
        + packet_rx.tcp.flag_fin
        + len(packet_rx.tcp.data),
        tcp_flag_rst=True,
        tcp_flag_ack=True,
        echo_tracker=packet_rx.tracker,
    )

    return
