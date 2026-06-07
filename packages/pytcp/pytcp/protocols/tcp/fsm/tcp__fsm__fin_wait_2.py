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
# pyright: reportPrivateUsage=false, reportUnusedExpression=false

"""
This module contains the TCP FSM FIN_WAIT_2 state handler.

pytcp/protocols/tcp/fsm/tcp__fsm__fin_wait_2.py

ver 3.0.8
"""

from typing import TYPE_CHECKING

from pytcp.lib.logger import log
from pytcp.protocols.tcp import tcp__constants
from pytcp.protocols.tcp.tcp__enums import FsmState
from pytcp.protocols.tcp.tcp__seq import gt32, in_range32
from pytcp.runtime.socket.tcp__metadata import TcpMetadata

if TYPE_CHECKING:
    from pytcp.protocols.tcp.session import TcpSession


def fsm__fin_wait_2__packet(session: TcpSession, packet_rx_md: TcpMetadata) -> None:
    """
    TCP FSM FIN_WAIT_2 state packet handler.
    """

    # Got SYN-bearing segment in a synchronized state -> Send a
    # challenge ACK per RFC 9293 §3.10.7.4 / RFC 5961 §4.
    if packet_rx_md.tcp__flag_syn:
        session._emit_challenge_ack()
        __debug__ and log(
            "tcp-ss",
            f"[{session}] - Sent challenge ACK for SYN-in-fin_wait_2 (RFC 9293 §3.10.7.4)",
        )
        return

    # RFC 9293 §3.10.7.4 step 1 receive-window acceptability
    # check; on unacceptable segments the helper emits the
    # mandated ACK reply and returns False, the caller drops.
    if not session._check_segment_acceptability(packet_rx_md):
        return

    # Got ACK packet -> Process data.
    if all({packet_rx_md.tcp__flag_ack}) and not any(
        {
            packet_rx_md.tcp__flag_syn,
            packet_rx_md.tcp__flag_rst,
            packet_rx_md.tcp__flag_fin,
        }
    ):
        # Packet sanity check.
        if packet_rx_md.tcp__seq == session._rcv_seq.nxt and in_range32(
            packet_rx_md.tcp__ack, session._snd_seq.una, session._snd_seq.max
        ):
            session._process_ack_packet(packet_rx_md)
            # Immediately acknowledge the received data if any.
            if packet_rx_md.tcp__data:
                session._transmit_packet(flag_ack=True)
            return
        # RFC 9293 §3.10.7.4 step 5 empty-ACK reply on
        # 'ack > SND.MAX'. Same gap as fixed in CLOSING /
        # FIN_WAIT_1.
        if gt32(packet_rx_md.tcp__ack, session._snd_seq.max):
            session._emit_challenge_ack()
        return

    # Got FIN + ACK packet -> Send ACK packet / change state to TIME_WAIT.
    if all({packet_rx_md.tcp__flag_fin, packet_rx_md.tcp__flag_ack}) and not any(
        {packet_rx_md.tcp__flag_syn, packet_rx_md.tcp__flag_rst}
    ):
        # Packet sanity check.
        if packet_rx_md.tcp__seq == session._rcv_seq.nxt and in_range32(
            packet_rx_md.tcp__ack, session._snd_seq.una, session._snd_seq.max
        ):
            session._process_ack_packet(packet_rx_md)
            # Send out final ACK packet.
            session._transmit_packet(flag_ack=True)
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - Sent final ACK ({session._rcv_seq.nxt}) packet",
            )
            # Change state to TIME_WAIT.
            session._change_state(FsmState.TIME_WAIT)
            # Initialize TIME_WAIT delay
            session._arm_timer("time_wait", tcp__constants.TCP__TIME_WAIT__DELAY_MS)
            return

    # Got RST (bare or RST+ACK) -> Process per RFC 9293 §3.10.7.4
    # three-way classification via the shared helper.
    if packet_rx_md.tcp__flag_rst and not any({packet_rx_md.tcp__flag_fin, packet_rx_md.tcp__flag_syn}):
        if session._check_rst_acceptability(packet_rx_md):
            session._change_state(FsmState.CLOSED)
