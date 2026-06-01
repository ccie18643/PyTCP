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
This module contains the TCP FSM TIME_WAIT state handler.

pytcp/protocols/tcp/fsm/tcp__fsm__time_wait.py

ver 3.0.8
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pytcp.lib.logger import log
from pytcp.protocols.tcp import tcp__constants
from pytcp.protocols.tcp.tcp__enums import FsmState
from pytcp.protocols.tcp.tcp__seq import add32, gt32

if TYPE_CHECKING:
    from pytcp.protocols.tcp.session import TcpSession
    from pytcp.socket.tcp__metadata import TcpMetadata


def fsm__time_wait__timer(session: TcpSession) -> None:
    """
    TCP FSM TIME_WAIT state timer handler.

    Run the TIME_WAIT delay: when the named '-time_wait'
    timer expires, transition to CLOSED.
    """

    if session._timer_expired("time_wait"):
        session._change_state(FsmState.CLOSED)


def fsm__time_wait__packet(session: TcpSession, packet_rx_md: TcpMetadata) -> None:
    """
    TCP FSM TIME_WAIT state packet handler.

    Implements the RFC 1337 'TIME-WAIT Assassination Hazards'
    mitigations:

      Hazard #1 (old duplicate FIN): re-ACK and restart the
        2*MSL timer (RFC 9293 §3.10.7.5; explicit branch
        below).
      Hazard #2 (old duplicate RST): silently drop. The
        handler does not recognise RST as a recognised
        segment type, so it falls through to the implicit
        no-op return at the end - PyTCP's TIME-WAIT cannot
        be "assassinated" by a delayed or maliciously-
        injected RST. Pinned by
        'TestTcpClose__TimeWaitRfc1337::test__rfc1337__rst_in_time_wait_does_not_terminate'.
      Hazard #3 (new SYN): elicit a challenge ACK without
        transitioning out of TIME-WAIT (RFC 9293 §3.10.7.4 /
        RFC 5961 §4; explicit branch below).

    The PAWS check shipped in RFC 7323 §5 (commit '79ed38e')
    extends Hazard #2 to ALSO drop stale-TSval segments, not
    just RSTs - any segment from an earlier seq cycle that
    has been delayed in the network is rejected at the
    inbound dispatch.
    """

    # Capture '_ts_recent' BEFORE the PAWS helper runs - the
    # helper updates '_ts_recent' to the segment's TSval as a
    # side effect on any non-stale TSopt-bearing segment, and
    # the RFC 6191 §3 strict-greater comparison below must be
    # against the value cached AT ENTRY (not the just-updated
    # one, which would always compare equal).
    ts_recent_at_entry = session._ts.ts_recent

    # RFC 7323 §5 PAWS: a delayed segment from a previous
    # incarnation, with stale TSval, MUST be dropped before
    # the FIN-retransmit handler re-arms the TIME_WAIT timer.
    # This is the strongest form of RFC 1337 TIME-WAIT
    # assassination protection: PAWS catches the stale
    # segment regardless of seq.
    if not session._check_paws_and_update_ts_recent(packet_rx_md):
        return

    # RFC 6191 §2 TIME-WAIT 4-tuple reuse, Linux-style OR'd
    # predicate covering sub-cases A.1, A.2, A.3, B.1, B.2 in
    # one expression: a SYN whose TSval is strictly greater
    # than '_ts_recent' (TSval evidence — sub-cases A.1/B.1)
    # OR whose seq is strictly greater than RCV.NXT (seq
    # evidence — sub-cases A.2/A.3/B.2) proves it cannot be a
    # delayed segment from the previous incarnation: either
    # the TS clock has advanced past anything we ever ACKed,
    # or the seq is past anything we ever expected. Terminate
    # this TIME-WAIT instance and accept the SYN as a fresh
    # connection without waiting the full 2*MSL. Linux's
    # tcp_timewait_state_process uses the same OR'd predicate
    # — accept on either axis independently rather than RFC
    # 6191 §2's tabular A-vs-B distinction. Sub-cases A.4 and
    # B.3 (no evidence on either axis) fall through to the
    # RFC 1337 / RFC 9293 §3.10.7.4 challenge-ACK path below.
    if (
        packet_rx_md.tcp__flag_syn
        and not packet_rx_md.tcp__flag_ack
        and not packet_rx_md.tcp__flag_rst
        and (
            gt32(packet_rx_md.tcp__seq, session._rcv_seq.nxt)
            or (packet_rx_md.tcp__tsval is not None and gt32(packet_rx_md.tcp__tsval, ts_recent_at_entry))
        )
    ):
        __debug__ and log(
            "tcp-ss",
            f"[{session}] - RFC 6191 §2 reuse: peer SYN "
            f"seq={packet_rx_md.tcp__seq} (> RCV.NXT="
            f"{session._rcv_seq.nxt}) or TSval="
            f"{packet_rx_md.tcp__tsval} (> _ts_recent="
            f"{ts_recent_at_entry}); terminating TIME_WAIT and "
            "accepting fresh SYN",
        )
        session._reinit_for_rfc6191_reuse(packet_rx_md)
        session._change_state(FsmState.SYN_RCVD)
        session._transmit_packet(flag_syn=True, flag_ack=True)
        return

    # Got peer FIN retransmit -> Acknowledge it and restart the
    # TIME_WAIT timer per RFC 9293 §3.10.7.5: 'The only thing
    # that can arrive in this state is a retransmission of the
    # remote FIN. Acknowledge it, and restart the 2 MSL
    # timeout.' The FIN's seq does not advance with retransmits,
    # so peer is replaying the same byte of sequence space we
    # already accepted (RCV.NXT - 1).
    if packet_rx_md.tcp__flag_fin and add32(packet_rx_md.tcp__seq, 1) == session._rcv_seq.nxt:
        session._transmit_packet(flag_ack=True)
        session._arm_timer("time_wait", tcp__constants.TCP__TIME_WAIT__DELAY_MS)
        __debug__ and log(
            "tcp-ss",
            f"[{session}] - Re-ACKed peer's FIN retransmit and restarted TIME_WAIT timer",
        )
        return

    # Got SYN-bearing segment in TIME_WAIT -> Send a challenge
    # ACK per RFC 9293 §3.10.7.4 / RFC 5961 §4. PyTCP does not
    # implement the Timestamp Option (PAWS), so RFC 9293's
    # TIME_WAIT-special connection-recycling path is unreachable
    # and the default challenge-ACK behaviour applies.
    if packet_rx_md.tcp__flag_syn:
        session._emit_challenge_ack()
        __debug__ and log(
            "tcp-ss",
            f"[{session}] - Sent challenge ACK for SYN-in-time_wait (RFC 9293 §3.10.7.4)",
        )
