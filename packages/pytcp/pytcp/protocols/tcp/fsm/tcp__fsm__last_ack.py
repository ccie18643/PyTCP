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
This module contains the TCP FSM LAST_ACK state handler.

pytcp/protocols/tcp/fsm/tcp__fsm__last_ack.py

ver 3.0.8
"""

from typing import TYPE_CHECKING

from pytcp.lib.logger import log
from pytcp.protocols.tcp.tcp__enums import FsmState
from pytcp.protocols.tcp.tcp__seq import gt32, in_range32

if TYPE_CHECKING:
    from pytcp.protocols.tcp.session import TcpSession
    from pytcp.runtime.socket.tcp__metadata import TcpMetadata


def fsm__last_ack__timer(session: TcpSession) -> None:
    """
    TCP FSM LAST_ACK state timer handler.

    Run retransmit-timeout machinery and drain any remaining
    TX buffer (typically the final FIN that we are awaiting
    an ACK for).
    """

    session._retransmit_packet_timeout()
    session._transmit_data()


def fsm__last_ack__packet(session: TcpSession, packet_rx_md: TcpMetadata) -> None:
    """
    TCP FSM LAST_ACK state packet handler.
    """

    # Got SYN-bearing segment in a synchronized state -> Send a
    # challenge ACK per RFC 9293 §3.10.7.4 / RFC 5961 §4.
    if packet_rx_md.tcp__flag_syn:
        session._emit_challenge_ack()
        __debug__ and log(
            "tcp-ss",
            f"[{session}] - Sent challenge ACK for SYN-in-last_ack (RFC 9293 §3.10.7.4)",
        )
        return

    # RFC 9293 §3.10.7.4 step 1 receive-window acceptability
    # check; on unacceptable segments the helper emits the
    # mandated ACK reply and returns False, the caller drops.
    if not session._check_segment_acceptability(packet_rx_md):
        return

    # Got ACK packet -> Change state to CLOSED.
    if all({packet_rx_md.tcp__flag_ack}) and not any(
        {
            packet_rx_md.tcp__flag_syn,
            packet_rx_md.tcp__flag_fin,
            packet_rx_md.tcp__flag_rst,
        }
    ):
        # Packet sanity check.
        if packet_rx_md.tcp__ack == session._snd_seq.nxt and in_range32(
            packet_rx_md.tcp__ack, session._snd_seq.una, session._snd_seq.max
        ):
            session._change_state(FsmState.CLOSED)
            return
        # RFC 9293 §3.10.7.4 step 5 empty-ACK reply on
        # 'ack > SND.MAX'. Same gap as fixed in CLOSING /
        # FIN_WAIT_1 / FIN_WAIT_2.
        if gt32(packet_rx_md.tcp__ack, session._snd_seq.max):
            session._emit_challenge_ack()
        return

    # Got RST (bare or RST+ACK) -> Process per RFC 9293 §3.10.7.4
    # three-way classification via the shared helper.
    if packet_rx_md.tcp__flag_rst and not any({packet_rx_md.tcp__flag_fin, packet_rx_md.tcp__flag_syn}):
        if session._check_rst_acceptability(packet_rx_md):
            session._change_state(FsmState.CLOSED)
