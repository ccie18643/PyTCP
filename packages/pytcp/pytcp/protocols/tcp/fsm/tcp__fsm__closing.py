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
This module contains the TCP FSM CLOSING state handler.

pytcp/protocols/tcp/fsm/tcp__fsm__closing.py

ver 3.0.8
"""

from typing import TYPE_CHECKING

from pytcp.lib.logger import log
from pytcp.protocols.tcp import tcp__constants
from pytcp.protocols.tcp.tcp__enums import FsmState
from pytcp.protocols.tcp.tcp__seq import ge32, gt32, in_range32
from pytcp.runtime.socket.tcp__metadata import TcpMetadata

if TYPE_CHECKING:
    from pytcp.protocols.tcp.session import TcpSession


def fsm__closing__packet(session: TcpSession, packet_rx_md: TcpMetadata) -> None:
    """
    TCP FSM CLOSING state packet handler.
    """

    # Got SYN-bearing segment in a synchronized state -> Send a
    # challenge ACK per RFC 9293 §3.10.7.4 / RFC 5961 §4.
    if packet_rx_md.tcp__flag_syn:
        session._emit_challenge_ack()
        __debug__ and log(
            "tcp-ss",
            f"[{session}] - Sent challenge ACK for SYN-in-closing (RFC 9293 §3.10.7.4)",
        )
        return

    # RFC 9293 §3.10.7.4 step 1 receive-window acceptability
    # check; on unacceptable segments the helper emits the
    # mandated ACK reply and returns False, the caller drops.
    if not session._check_segment_acceptability(packet_rx_md):
        return

    # Got ACK packet -> ESTABLISHED-style ACK processing per
    # RFC 9293 §3.10.7.4 ("CLOSING STATE: In addition to the
    # processing for the ESTABLISHED state, if our FIN is now
    # acknowledged then enter the TIME-WAIT state, otherwise
    # ignore the segment."). Mirrors the FIN_WAIT_1 /
    # FIN_WAIT_2 / LAST_ACK shape: '_process_ack_packet'
    # handles SND.UNA advance, scoreboard prune, retransmit-
    # counter purge, and persist-timer reset; the FIN-acked
    # check uses 'ge32(snd_una, snd_fin)' on the post-update
    # SND.UNA. The strict 'tcp__ack == self._snd_seq.nxt' check
    # used previously was equivalent in the canonical
    # simultaneous-close flow but silently dropped 'ack >
    # snd_max' cases that RFC §3.10.7.4 step 5 mandates an
    # empty-ACK reply for; the new shape inherits the
    # sibling-state empty-ACK fallback below.
    if all({packet_rx_md.tcp__flag_ack}) and not any(
        {
            packet_rx_md.tcp__flag_fin,
            packet_rx_md.tcp__flag_syn,
            packet_rx_md.tcp__flag_rst,
        }
    ):
        if packet_rx_md.tcp__seq == session._rcv_seq.nxt and in_range32(
            packet_rx_md.tcp__ack, session._snd_seq.una, session._snd_seq.max
        ):
            session._process_ack_packet(packet_rx_md)
            # If our FIN is now acked, enter TIME_WAIT.
            if ge32(session._snd_seq.una, session._snd_seq.fin):
                session._change_state(FsmState.TIME_WAIT)
                session._arm_timer("time_wait", tcp__constants.TCP__TIME_WAIT__DELAY_MS)
            return
        # RFC 9293 §3.10.7.4 step 5: an ACK acknowledging
        # data we have never sent (ack > SND.MAX) MUST elicit
        # an empty-ACK reply carrying our current SND.NXT and
        # RCV.NXT. The strict-equality predecessor of this
        # branch silently dropped these.
        if gt32(packet_rx_md.tcp__ack, session._snd_seq.max):
            session._emit_challenge_ack()
        return

    # Got RST (bare or RST+ACK) -> Process per RFC 9293 §3.10.7.4
    # three-way classification via the shared helper.
    if packet_rx_md.tcp__flag_rst and not any({packet_rx_md.tcp__flag_fin, packet_rx_md.tcp__flag_syn}):
        if session._check_rst_acceptability(packet_rx_md):
            session._change_state(FsmState.CLOSED)
