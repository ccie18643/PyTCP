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
This module contains the TCP FSM ESTABLISHED state handler.

pytcp/protocols/tcp/fsm/tcp__fsm__established.py

ver 3.0.8
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pytcp.lib.logger import log
from pytcp.protocols.tcp import tcp__constants
from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
from pytcp.protocols.tcp.tcp__seq import add32, ge32, gt32, in_range32, le32, lt32, sub32

if TYPE_CHECKING:
    from pytcp.protocols.tcp.session import TcpSession
    from pytcp.runtime.socket.tcp__metadata import TcpMetadata


def fsm__established__timer(session: TcpSession) -> None:
    """
    TCP FSM ESTABLISHED state timer handler.

    Send out data and run Delayed ACK mechanism. Service
    keep-alive, RACK reordering, and TLP PTO timers. When
    the application has called CLOSE and the TX buffer has
    fully drained, transition to FIN_WAIT_1 to emit the FIN.
    """

    session._retransmit_packet_timeout()
    session._transmit_data()
    session._delayed_ack()
    session._keepalive_tick()
    # RFC 8985 §6.2 step 5 reordering-timer service.
    # When the 'f"{session}-rack"' timer has expired,
    # re-run rack_detect_loss + arm a fresh timer if
    # more pending candidates exist.
    session._rack_reorder_tick()
    # RFC 8985 §7.3 Tail Loss Probe service. When the
    # f'{session}-tlp' timer expires, send a probe -
    # retransmit of the highest-seq segment (most common
    # tail-loss case after _transmit_data has drained the
    # buffer). The new-data branch fires only when fresh
    # bytes arrive between TLP arming and PTO expiry.
    session._tlp_pto_tick()
    if session._closing and not session._tx.buffer:
        session._change_state(FsmState.FIN_WAIT_1)


def fsm__established__syscall(session: TcpSession, syscall: SysCall) -> None:
    """
    TCP FSM ESTABLISHED state syscall handler.

    Got CLOSE syscall in ESTABLISHED -> mark the session
    closing; the actual transition to FIN_WAIT_1 (and the
    FIN emission from there) is deferred until the TX buffer
    drains, per RFC 9293 §3.10.4 ("a CLOSE call should ...
    cause outstanding SENDs to be transmitted"). The
    ESTABLISHED timer branch checks 'self._closing and not
    self._tx.buffer' to fire the state change.
    """

    if syscall is SysCall.CLOSE:
        session._closing = True


def fsm__established__packet(session: TcpSession, packet_rx_md: TcpMetadata) -> None:
    """
    TCP FSM ESTABLISHED state packet handler.
    """

    # Got SYN-bearing segment in a synchronized state -> Send a challenge ACK
    # per RFC 9293 §3.10.7.4 (folding RFC 5961 §4). A SYN flag set on a segment
    # from an already-established 4-tuple is either a legitimate handshake
    # retransmit by the peer (because they did not see our third-leg ACK),
    # a stale segment from a prior connection, or a blind injection attack.
    # In all three cases we respond with an ACK keyed to our current SND.NXT
    # / RCV.NXT; the legitimate peer accepts it and proceeds, the stale
    # segment is harmless, and the attacker learns nothing about our state.
    # The branch must precede the receive-window check below because a
    # retransmitted SYN+ACK carries SEG.SEQ = peer_ISS, one byte before our
    # current RCV.NXT, and would otherwise be silently dropped.
    if packet_rx_md.tcp__flag_syn:
        session._emit_challenge_ack()
        __debug__ and log(
            "tcp-ss",
            f"[{session}] - Sent challenge ACK for SYN-in-established (RFC 9293 §3.10.7.4)",
        )
        return

    # RFC 9293 §3.10.7.4 step 1 receive-window acceptability
    # check; on unacceptable segments the helper emits the
    # mandated ACK reply and returns False, the caller drops.
    if not session._check_segment_acceptability(packet_rx_md):
        return

    # RFC 7323 §5 PAWS + §4.3 '_ts_recent' refresh applied
    # at the dispatch boundary so the dup-ACK fast-retransmit
    # branch and OOO-queue branch below benefit from the same
    # protection as the regular '_process_ack_packet' path.
    if not session._check_paws_and_update_ts_recent(packet_rx_md):
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
            # RFC 1122 §4.2.3.6: any peer ACK at SND.UNA - whether
            # a wnd-update, a true dup-ACK, or a keep-alive probe-
            # ack - signals peer is alive. Reset the keep-alive
            # idle timer regardless of which sub-branch handles
            # the segment below.
            session._keepalive_arm_idle()
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
            # Idle session (SND.UNA == SND.NXT) with an ACK at
            # SND.UNA: this is a keep-alive probe-ack (RFC 1122
            # §4.2.3.6) - peer is responding to a probe we sent at
            # SND.NXT-1, or sending an unsolicited liveness ACK.
            # Either way the keep-alive timer above has been reset;
            # absorb the segment without contributing to the dup-
            # ACK fast-retransmit count (there is nothing to
            # retransmit anyway, and three such probe-acks would
            # otherwise spuriously enter recovery).
            if session._snd_seq.una == session._snd_seq.nxt:
                return
            # Window unchanged AND data is in flight -> true
            # duplicate ACK per RFC 5681 §2(e). Hand off to the
            # fast-retransmit machinery.
            session._retransmit_packet_request(packet_rx_md)
            return
        # Packet with higher SEQ than what we are expecting -> Store it and
        # send 'fast retransmit' request (don't send more than two).
        # Modular comparators per RFC 9293 §3.4.
        if (
            gt32(packet_rx_md.tcp__seq, session._rcv_seq.nxt)
            and le32(session._snd_seq.una, packet_rx_md.tcp__ack)
            and le32(packet_rx_md.tcp__ack, session._snd_seq.max)
        ):
            # RFC 2883 DSACK case 2: detect overlap of the
            # inbound segment with any existing OOO-queue
            # entry BEFORE the dict store overwrites or adds.
            # The overlap range is stashed in
            # '_pending_dsack' so the next outbound ACK
            # reports it as the FIRST SACK block per RFC 2883
            # §4 - the peer's spurious-retransmit detector
            # (RFC 3522 / 4015 Eifel) uses this to roll back
            # a needless cwnd halving when its RTO fired
            # spuriously and retransmitted bytes that were
            # already buffered on our side. Only the first
            # contiguous overlap is reported per ACK; any
            # additional disjoint overlaps are still
            # representable through the regular OOO-queue
            # blocks that follow the DSACK marker.
            if session._advertise.send_sack:
                seg_left = packet_rx_md.tcp__seq
                seg_right = add32(seg_left, len(packet_rx_md.tcp__data))
                for existing_seq, existing_md in session._ooo_packet_queue.items():
                    existing_left = existing_seq
                    existing_right = add32(existing_left, len(existing_md.tcp__data))
                    ovl_left = existing_left if ge32(existing_left, seg_left) else seg_left
                    ovl_right = existing_right if le32(existing_right, seg_right) else seg_right
                    if lt32(ovl_left, ovl_right):
                        session._pending_dsack = (ovl_left, ovl_right)
                        break
            session._ooo_packet_queue[packet_rx_md.tcp__seq] = packet_rx_md
            # RFC 5681 §4.2: a TCP receiver MUST send an
            # immediate duplicate ACK on every out-of-order
            # segment arrival - no per-gap rate limit. The
            # ACKs convey the missing-segment seq to the
            # sender peer; once peer sees three duplicate ACKs
            # at the same value, peer's RFC 5681 §3.2 fast-
            # retransmit fires. OOO arrivals are naturally
            # rate-limited by peer's send cadence so emitting
            # one ACK per arrival cannot flood the wire.
            session._transmit_packet(flag_ack=True)
            return
        # Regular data/ACK packet -> Process data. Match either an
        # exactly in-order segment ('SEG.SEQ == RCV.NXT', which
        # covers both new-data segments and bare ACKs of our sent
        # data) OR an overlap-with-new-bytes segment ('SEG.SEQ <
        # RCV.NXT < SEG.SEQ + SEG.LEN', covering retransmits whose
        # tail extends past RCV.NXT) per RFC 9293 §3.10.7.4. The
        # already-received prefix of an overlap segment is sliced
        # off inside '_process_ack_packet'. All seq/ack
        # comparisons are modular per RFC 9293 §3.4.
        seg_seq = packet_rx_md.tcp__seq
        seg_end = add32(
            seg_seq,
            len(packet_rx_md.tcp__data),
            packet_rx_md.tcp__flag_syn,
            packet_rx_md.tcp__flag_fin,
        )
        in_order = seg_seq == session._rcv_seq.nxt
        overlap_with_new = lt32(seg_seq, session._rcv_seq.nxt) and lt32(session._rcv_seq.nxt, seg_end)
        if (
            (in_order or overlap_with_new)
            and le32(session._snd_seq.una, packet_rx_md.tcp__ack)
            and le32(packet_rx_md.tcp__ack, session._snd_seq.max)
        ):
            session._process_ack_packet(packet_rx_md)
            return
        # RFC 9293 §3.10.7.4: an unacceptable ACK (acknowledging
        # data we have never sent, i.e. ACK > SND.MAX modularly)
        # must elicit an empty-ACK reply containing our current
        # SND.NXT and RCV.NXT, and the offending segment is
        # discarded; the connection state is unchanged. This
        # catches forged or stale ACKs that none of the inner
        # branches above match. (ACK < SND.UNA is a stale
        # duplicate per RFC §3.10.7.4 and is silently discarded
        # - the existing fall-through handles that path.)
        if gt32(packet_rx_md.tcp__ack, session._snd_seq.max):
            session._emit_challenge_ack()
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - Sent empty ACK reply for unacceptable "
                f"ACK={packet_rx_md.tcp__ack} > SND.MAX={session._snd_seq.max}",
            )
            return
        # RFC 5961 §5 lower-bound ACK acceptability: an ACK
        # below 'SND.UNA - MAX.SND.WND' is an off-path blind
        # injection (or a wedged peer with a very stale view).
        # Emit a rate-limited challenge ACK so the legitimate
        # peer can re-sync; without this gate, very-stale ACKs
        # would be silently dropped.
        ack_lower_bound = sub32(session._snd_seq.una, session._win.max_window)
        if lt32(packet_rx_md.tcp__ack, ack_lower_bound):
            session._emit_challenge_ack()
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - Sent challenge ACK for unacceptable "
                f"ACK={packet_rx_md.tcp__ack} < SND.UNA - MAX.SND.WND="
                f"{ack_lower_bound} (RFC 5961 §5)",
            )
        return

    # Got FIN + ACK packet -> Send ACK packet (let delayed ACK mechanism
    # do it) / change state to CLOSE_WAIT / notify app that peer closed
    # connection.
    if all({packet_rx_md.tcp__flag_fin, packet_rx_md.tcp__flag_ack}) and not any(
        {packet_rx_md.tcp__flag_syn, packet_rx_md.tcp__flag_rst}
    ):
        # Packet sanity check.
        if packet_rx_md.tcp__seq == session._rcv_seq.nxt and in_range32(
            packet_rx_md.tcp__ack, session._snd_seq.una, session._snd_seq.max
        ):
            session._process_ack_packet(packet_rx_md)
            # Immediately acknowledge the received data if any.
            if packet_rx_md.tcp__data:
                session._transmit_packet(flag_ack=True)
            # Let application know that remote peer closed connection
            # (let receive syscall bypass semaphore).
            session._event__rx_buffer.set()
            # Change state to CLOSE_WAIT.
            session._change_state(FsmState.CLOSE_WAIT)
        return

    # Got RST (bare or RST+ACK) -> Process per RFC 9293 §3.10.7.4
    # (folding RFC 5961 §3.2 blind-RST attack mitigation) via
    # the shared '_check_rst_acceptability' helper which runs
    # the three-way classification (case 1 reset / case 2
    # challenge ACK / case 3 silent drop). On case 1 we
    # additionally wake any blocked 'recv()' caller so the
    # application sees the connection-reset signal without
    # blocking forever on the rx-buffer event.
    if packet_rx_md.tcp__flag_rst and not any({packet_rx_md.tcp__flag_fin, packet_rx_md.tcp__flag_syn}):
        if session._check_rst_acceptability(packet_rx_md):
            session._event__rx_buffer.set()
            session._change_state(FsmState.CLOSED)
