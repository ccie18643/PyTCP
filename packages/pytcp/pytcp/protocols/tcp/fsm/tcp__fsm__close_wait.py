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
This module contains the TCP FSM CLOSE_WAIT state handler.

pytcp/protocols/tcp/fsm/tcp__fsm__close_wait.py

ver 3.0.8
"""

from typing import TYPE_CHECKING

from pytcp.lib.logger import log
from pytcp.protocols.tcp import tcp__constants
from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
from pytcp.protocols.tcp.tcp__seq import gt32, in_range32

if TYPE_CHECKING:
    from pytcp.protocols.tcp.session import TcpSession
    from pytcp.runtime.socket.tcp__metadata import TcpMetadata


def fsm__close_wait__timer(session: TcpSession) -> None:
    """
    TCP FSM CLOSE_WAIT state timer handler.

    Send out data and run Delayed ACK mechanism. When the
    application has called CLOSE and the TX buffer has fully
    drained, transition to LAST_ACK to emit the FIN.
    """

    session._retransmit_packet_timeout()
    session._transmit_data()
    session._delayed_ack()
    if session._closing and not session._tx.buffer:
        session._change_state(FsmState.LAST_ACK)


def fsm__close_wait__syscall(session: TcpSession, syscall: SysCall) -> None:
    """
    TCP FSM CLOSE_WAIT state syscall handler.

    Got CLOSE syscall in CLOSE_WAIT -> mark the session
    closing so the post-half-close FIN emission can fire
    from LAST_ACK once the TX buffer drains, per RFC 9293
    §3.10.4. The actual transition to LAST_ACK is deferred
    via the timer-branch 'self._closing and not
    self._tx.buffer' check (mirrors the ESTABLISHED CLOSE
    handler above).
    """

    if syscall is SysCall.CLOSE:
        session._closing = True


def fsm__close_wait__packet(session: TcpSession, packet_rx_md: TcpMetadata) -> None:
    """
    TCP FSM CLOSE_WAIT state packet handler.
    """

    # Got SYN-bearing segment in a synchronized state -> Send a
    # challenge ACK per RFC 9293 §3.10.7.4 / RFC 5961 §4.
    if packet_rx_md.tcp__flag_syn:
        session._emit_challenge_ack()
        __debug__ and log(
            "tcp-ss",
            f"[{session}] - Sent challenge ACK for SYN-in-close_wait (RFC 9293 §3.10.7.4)",
        )
        return

    # RFC 9293 §3.10.7.4 step 1 receive-window acceptability
    # check. The same helper used in ESTABLISHED catches
    # fully-duplicate retransmits of pre-FIN data and out-of-
    # window forward segments, emits the mandated ACK reply
    # so peer's retransmit machinery sees fresh activity, and
    # returns False for the caller to drop.
    if not session._check_segment_acceptability(packet_rx_md):
        return

    # Got ACK packet.
    if all({packet_rx_md.tcp__flag_ack}) and not any(
        {
            packet_rx_md.tcp__flag_syn,
            packet_rx_md.tcp__flag_rst,
            packet_rx_md.tcp__flag_fin,
        }
    ):
        # Inbound ACK with the dup-ACK wire shape ('seq ==
        # RCV.NXT, ack == SND.UNA, no data'). Per RFC 5681 §2(e)
        # the segment is a TRUE duplicate ACK only when the
        # advertised window matches the previous ACK; if peer's
        # window changed, the segment is a window update per
        # RFC 9293 §3.10.7.4 step 5 and MUST update SND.WND
        # without contributing to the fast-retransmit threshold
        # (otherwise three standalone wnd-updates at the same
        # SEG.ACK would spuriously trigger fast-retransmit on
        # the third one). SND.EWN is intentionally left alone
        # on the wnd-update path: cwnd grows on cum-ACK progress
        # per RFC 5681 §3.1, not on wnd-update. SACK info is
        # still ingested in case peer piggybacked OOO state on
        # the wnd-update.
        if (
            packet_rx_md.tcp__seq == session._rcv_seq.nxt
            and packet_rx_md.tcp__ack == session._snd_seq.una
            and not packet_rx_md.tcp__data
        ):
            new_wnd = packet_rx_md.tcp__win << session._win.snd_wsc
            if new_wnd != session._win.snd_wnd:
                __debug__ and log(
                    "tcp-ss",
                    f"[{session}] - Updated sending window size " f"{session._win.snd_wnd} -> {new_wnd} (wnd-update)",
                )
                session._win.snd_wnd = new_wnd
                if session._win.snd_wnd > 0 and session._persist.active:
                    __debug__ and log(
                        "tcp-ss",
                        f"[{session}] - Persist: peer reopened window via wnd-update, deactivating timer",
                    )
                    session._persist.active = False
                    session._persist.timeout = tcp__constants.TCP__RTO__INITIAL_MS
                session._ingest_sack_info(packet_rx_md)
                return
            # Window unchanged -> true duplicate ACK per RFC
            # 5681 §2(e). Hand off to the fast-retransmit
            # machinery.
            session._retransmit_packet_request(packet_rx_md)
            return
        # OOO data above RCV.NXT in CLOSE_WAIT is doubly-
        # illegal: peer FIN'd (so they shouldn't send more
        # data) AND the bytes can never reach the
        # application even if we buffered them (RCV.NXT
        # cannot advance past peer's FIN seq + 1, so the OOO
        # queue would never drain). Don't store, don't
        # accumulate dup-ACK retransmit-request state, just
        # ACK to nudge peer's retransmit machinery toward
        # backoff. Distinct from ESTABLISHED's OOO branch
        # which queues the segment with DSACK case-2
        # detection (commit 'b69e8b1') because RCV.NXT in
        # ESTABLISHED can still advance to fill the gap.
        if gt32(packet_rx_md.tcp__seq, session._rcv_seq.nxt) and in_range32(
            packet_rx_md.tcp__ack, session._snd_seq.una, session._snd_seq.max
        ):
            session._transmit_packet(flag_ack=True)
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - OOO post-FIN data in CLOSE_WAIT (RFC violation by peer); "
                f"acked at RCV.NXT={session._rcv_seq.nxt} without queueing",
            )
            return
        # Regular ACK packet (no data) -> ACK-field processing.
        if (
            packet_rx_md.tcp__seq == session._rcv_seq.nxt
            and in_range32(packet_rx_md.tcp__ack, session._snd_seq.una, session._snd_seq.max)
            and not packet_rx_md.tcp__data
        ):
            session._process_ack_packet(packet_rx_md)
            return
        # In-window data segment -> peer is RFC-violatingly
        # sending data after their own FIN (RFC 9293 §3.10.7.4
        # step 7 omits CLOSE_WAIT from the states that deliver
        # segment text to the application). ACK to stop peer's
        # retransmit machinery but do NOT enqueue the data or
        # advance RCV.NXT - appending fresh bytes after the
        # FIN's EOF signal would break BSD socket semantics
        # (recv() returns b"" once peer FIN'd; bytes appearing
        # after that violate the contract). The cum-ACK we
        # emit carries our current RCV.NXT (= peer's FIN seq
        # + 1, unchanged), which signals peer "we acknowledge
        # receipt but cannot consume past your FIN".
        if packet_rx_md.tcp__seq == session._rcv_seq.nxt and in_range32(
            packet_rx_md.tcp__ack, session._snd_seq.una, session._snd_seq.max
        ):
            session._transmit_packet(flag_ack=True)
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - Post-FIN data in CLOSE_WAIT (RFC violation by peer); "
                f"acked at RCV.NXT={session._rcv_seq.nxt} without enqueue",
            )
            return
        return

    # Got RST packet -> Process per RFC 9293 §3.10.7.4
    # three-way classification via the shared helper. Any RST
    # in a synchronized state aborts the connection regardless
    # of the ACK flag - conformant TCPs always set ACK on RST
    # per RFC convention, so excluding 'tcp__flag_ack' from
    # the predicate would (and previously did) make this
    # branch never fire in real traffic.
    if packet_rx_md.tcp__flag_rst and not any(
        {
            packet_rx_md.tcp__flag_fin,
            packet_rx_md.tcp__flag_syn,
        }
    ):
        if session._check_rst_acceptability(packet_rx_md):
            session._change_state(FsmState.CLOSED)
