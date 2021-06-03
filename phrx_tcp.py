#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-2021  Sebastian Majewski                             #
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

##############################################################################################
#                                                                                            #
#  This program is a work in progress and it changes on daily basis due to new features      #
#  being implemented, changes being made to already implemented features, bug fixes, etc.    #
#  Therefore if the current version is not working as expected try to clone it again the     #
#  next day or shoot me an email describing the problem. Any input is appreciated. Also      #
#  keep in mind that some features may be implemented only partially (as needed for stack    #
#  operation) or they may be implemented in sub-optimal or not 100% RFC compliant way (due   #
#  to lack of time) or last but not least they may contain bug(s) that i didn't notice yet.  #
#                                                                                            #
##############################################################################################


#
# phrx_tcp.py - packet handler for inbound TCP packets
#

import fpp_tcp
import stack
from tcp_metadata import TcpMetadata

PACKET_LOSS = False


def _phrx_tcp(self, packet_rx):
    """Handle inbound TCP packets"""

    fpp_tcp.TcpPacket(packet_rx)

    if packet_rx.parse_failed:
        if __debug__:
            self._logger.critical(f"{self.tracker} - {packet_rx.parse_failed}")
        return

    if __debug__:
        self._logger.opt(ansi=True).info(f"<green>{packet_rx.tracker}</green> - {packet_rx.tcp}")

    # Create TcpPacket object for further processing by TCP FSM
    packet = TcpMetadata(
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
        data=packet_rx.tcp.data,
        tracker=packet_rx.tracker,
    )

    # Check if packet should be dropped due to random packet loss enabled (for TCP retansmission testing)
    if PACKET_LOSS:
        from random import randint

        if randint(0, 99) == 7:
            if __debug__:
                self._logger.critical("SIMULATED LOST RX DATA PACKET")
            return

    # Check if incoming packet matches active TCP session
    if tcp_session := stack.tcp_sessions.get(packet.tcp_session_id, None):
        if __debug__:
            self._logger.debug(f"{packet.tracker} - TCP packet is part of active session {tcp_session.tcp_session_id}")
        tcp_session.tcp_fsm(packet=packet)
        return

    # Check if incoming packet is an initial SYN packet and if it matches any listening TCP session
    if all({packet.flag_syn}) and not any({packet.flag_ack, packet.flag_fin, packet.flag_rst}):
        for tcp_session_id_pattern in packet.tcp_session_listening_patterns:
            if tcp_session := stack.tcp_sessions.get(tcp_session_id_pattern, None):
                if __debug__:
                    self._logger.debug(f"{packet.tracker} - TCP packet matches listening session {tcp_session.tcp_session_id}")
                tcp_session.tcp_fsm(packet=packet)
                return

    # In case packet doesn't match any session send RST packet in response to it
    if __debug__:
        self._logger.debug(f"Received TCP packet from {packet_rx.ip.src} to closed port {packet_rx.tcp.dport}, responding with TCP RST packet")
    self._phtx_tcp(
        ip_src=packet_rx.ip.dst,
        ip_dst=packet_rx.ip.src,
        tcp_sport=packet_rx.tcp.dport,
        tcp_dport=packet_rx.tcp.sport,
        tcp_seq=0,
        tcp_ack=packet_rx.tcp.seq + packet_rx.tcp.flag_syn + packet_rx.tcp.flag_fin + len(packet_rx.tcp.data),
        tcp_flag_rst=True,
        tcp_flag_ack=True,
        echo_tracker=packet_rx.tracker,
    )

    return
