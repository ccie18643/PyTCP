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
This module contains the per-session TCP retransmitter —
'TcpRetransmitter' — which owns the RFC 6298 §5 RTO timeout
path, the RFC 5681 §3.2 / RFC 6675 §3 fast-retransmit-request
path, the RFC 8985 §7.3 Tail Loss Probe firing path, and the
RFC 8985 §6.2 RACK reorder-window + per-ACK update helpers.
Phase 5 of the TcpSession god-class decomposition.

Pure structural extraction — no behaviour change, no new lock.
The retransmitter holds a back-reference to the session and
reads/writes every shared state dataclass via
'self._session.<state>', matching the idiom 'fsm/' and the
Phase-1/2/3/4 collaborators already use. The session keeps
thin delegators for every method moved here so 'fsm/' handlers
and the Phase-3 ACK processor continue to call them unchanged.

This is the final phase of the TcpSession decomposition.

packages/pytcp/pytcp/protocols/tcp/session/tcp__session__retransmit.py

ver 3.0.8
"""

import time
from typing import TYPE_CHECKING

from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.tcp import tcp__constants
from pytcp.protocols.tcp.tcp__cubic import cubic_compute_K, cubic_loss_event_ssthresh
from pytcp.protocols.tcp.tcp__cwnd import compute_loss_event_ssthresh
from pytcp.protocols.tcp.tcp__enums import CcMode, ConnError, FsmState
from pytcp.protocols.tcp.tcp__loss_recovery import is_lost, next_seg
from pytcp.protocols.tcp.tcp__rack import (
    INFINITE_TS,
    RackSegment,
    rack_compute_reo_wnd,
    rack_detect_loss,
    rack_update,
)
from pytcp.protocols.tcp.tcp__rto import back_off
from pytcp.protocols.tcp.tcp__seq import gt32, le32, lt32, sub32
from pytcp.runtime.socket.tcp__metadata import TcpMetadata

if TYPE_CHECKING:
    from pytcp.protocols.tcp.session import TcpSession


class TcpRetransmitter:
    """
    Per-session TCP retransmitter — owns the RTO timeout, fast-
    retransmit request, TLP firing, and RACK per-ACK helpers.
    """

    def __init__(self, session: "TcpSession", /) -> None:
        """
        Initialize the retransmitter with a back-reference to the
        owning session.
        """

        self._session: TcpSession = session

    # ------------------------------------------------------------------
    # Public surface — called via session delegators from fsm/ handlers
    # (retransmit_packet_timeout / retransmit_packet_request /
    # rack_reorder_tick / tlp_pto_tick) and from the Phase-3 ACK
    # processor (rack_process_ack).
    # ------------------------------------------------------------------

    def retransmit_packet_timeout(self) -> None:
        """
        Retransmit packet after expired timeout.

        RFC 6298 §5 specifies the timer's lifecycle:
            §5.1 Arm on data send if not running.
            §5.2 Stop on cum-ACK that drains all in-flight.
            §5.3 Restart on cum-ACK that advances SND.UNA.
            §5.4 Retransmit the earliest unacked segment.
            §5.5 Back off RTO (cap at MAX_RTO_MS).
            §5.6 Re-arm with the new RTO.
        """

        session = self._session
        # RFC 6298 §5: only act when the session-level retransmit
        # timer has fired. '_timer_expired' is True only when the
        # timer was armed and its deadline has passed (an unarmed
        # timer is NOT expired), so the second guard 'snd_una !=
        # snd_max' is the genuine RFC 6298 §5 "nothing in flight"
        # condition — do not retransmit when there is no unacked
        # data — not a disambiguation crutch.
        if not session._timer_expired("retransmit"):
            return
        if session._snd_seq.una == session._snd_seq.max:
            return

        # RFC 1122 §4.2.3.5 R2: after the retransmit budget is
        # exhausted without progress, abort the connection. The
        # budget is normally 'TCP__RETRANSMIT__MAX_COUNT' (a
        # consecutive-timeout count); when the application has
        # set 'TCP_USER_TIMEOUT' (Linux ms-budget, propagated as
        # 'session._user_timeout_ms'), the time budget is
        # approximated as 'max(1, _user_timeout_ms //
        # current_rto_ms)' so the abort fires after the user's
        # wall-time budget elapses under the current RTO. The
        # counter resets on every cum-ACK that advances SND.UNA
        # in '_process_ack_packet', so the abort is gated on
        # prolonged silence, not lifetime retransmits.
        if session._user_timeout_ms > 0:
            current_rto_ms = max(1, session._rto_state.rto_ms)
            budget = max(1, session._user_timeout_ms // current_rto_ms)
        else:
            budget = tcp__constants.TCP__RETRANSMIT__MAX_COUNT
        if session._retransmit_count >= budget:
            # Send RST to peer iff peer was actually contacted
            # (i.e. we processed at least one inbound segment
            # post-handshake-start). The check uses the explicit
            # '_peer_contacted' flag rather than 'RCV.NXT > 0'
            # because 'RCV.NXT' is a Seq32 that legitimately
            # takes the value 0 when peer's ISN happened to be
            # 0xFFFF_FFFF ('add32(peer_isn, 1)' wraps to 0); a
            # raw '> 0' comparison would suppress the RST in
            # that case.
            if session._peer_contacted:
                session._transmit_packet(flag_rst=True, flag_ack=True, seq=session._snd_seq.una)
                __debug__ and log(
                    "tcp-ss",
                    f"[{session}] - Packet retransmit counter expired, resetting session",
                )
            else:
                __debug__ and log(
                    "tcp-ss",
                    f"[{session}] - Packet retransmit counter expired",
                )
            # If in any state with established connection inform socket
            # about connection failure.
            if session._state in {
                FsmState.ESTABLISHED,
                FsmState.FIN_WAIT_1,
                FsmState.FIN_WAIT_2,
                FsmState.CLOSE_WAIT,
            }:
                session._connection_error = ConnError.TIMEOUT
                session._event__rx_buffer.set()
                session._socket._signal_readable()
            # If in SYN_SENT state inform CONNECT syscall that the
            # connection related event happened.
            if session._state is FsmState.SYN_SENT:
                session._connection_error = ConnError.TIMEOUT
                session._event__connect.release()
            # Change state to CLOSED
            session._change_state(FsmState.CLOSED)
            return

        # RFC 6298 §3 (Karn): if the segment now being
        # retransmitted carries a pending RTT sample, taint
        # the sample so the harvest hook in
        # '_process_ack_packet' clears the tracker without
        # folding the (now-ambiguous) RTT into '_rto_state'.
        # The pending sample's send-time and seq remain set
        # so the harvest path can recognise the covering
        # ACK; only the "skip update" flag flips.
        if session._rtt.seq is not None and session._rtt.seq == session._snd_seq.una:
            session._rtt.taint()

        # RFC 8985 §6.3: on RTO, mark all in-flight segments
        # lost. Subsequent retransmit walking treats them as
        # the loss set; the existing _transmit_data
        # machinery (with snd_nxt rewound to snd_una below)
        # will re-fire them. Replace each entry with the
        # 'lost=True / xmit_ts=INFINITE_TS' form per
        # RFC 8985 §5.2.
        session._rack_tlp.rack_segments = {
            seq: RackSegment(
                end_seq=seg.end_seq,
                xmit_ts=INFINITE_TS,
                retransmitted=seg.retransmitted,
                lost=True,
            )
            for seq, seg in session._rack_tlp.rack_segments.items()
        }

        # RFC 6298 §5.5 binary backoff and §5.6 re-arm with the
        # new RTO. 'back_off' caps at 'MAX_RTO_MS' so a long-
        # silent peer cannot drive 'rto_ms' to overflow.
        session._rto_state = back_off(session._rto_state)
        session._retransmit_count += 1
        # PLPMTUD adapter: declare any in-flight probe lost so
        # the engine sees the RTO event as a probe-loss
        # signal. No-op when no probes were in flight (RFC
        # 4821 §7.5 — data-RTO alone does not feed
        # probe-loss).
        session._plpmtud_adapter.on_rto_timeout(now=time.monotonic())
        # RFC 6298 §5.7 second-clause SYN-retransmit counter.
        # Increment when the retransmit fires while the
        # handshake is still in progress: SYN_SENT (active
        # open's SYN) or SYN_RCVD (passive / simultaneous
        # open's SYN+ACK). Survives '_process_ack_packet's
        # cum-ACK reset of '_retransmit_count' so the §5.7
        # floor checks at the ESTABLISHED-transition sites
        # see the count regardless of evaluation order.
        if session._state in {FsmState.SYN_SENT, FsmState.SYN_RCVD}:
            session._syn_retransmit_count += 1
            # RFC 7413 §4.4: SYN retransmits MUST NOT carry the
            # TFO option or SYN-data. Mark the connection so
            # '_transmit_packet' suppresses TFO emission on the
            # retransmit. Set in SYN_SENT only; the peer side
            # (SYN_RCVD) doesn't replay TFO on its SYN+ACK
            # retransmit by construction.
            if session._state is FsmState.SYN_SENT and session._advertise.fastopen:
                session._fastopen.syn_retransmitted = True
                # RFC 7413 §4.1.3.1: a SYN-RTO during TFO
                # active-open is a strong signal that the path
                # drops TFO-bearing SYNs. Add the peer to the
                # negative-response cache so future active-
                # opens to the same peer skip TFO entirely.
                stack.tcp_stack.mark_fastopen_negative(session._remote_ip_address)
        session._arm_timer("retransmit", session._rto_state.rto_ms)
        __debug__ and log(
            "tcp-ss",
            f"[{session}] - RFC 6298 §5.5 back-off: rto_ms -> "
            f"{session._rto_state.rto_ms} (retry "
            f"#{session._retransmit_count})",
        )

        # RFC 5682 §2.1 step 1: snapshot pre-RTO state and
        # store SND.MAX into 'recover' (= '_frto_pre_snd_max'
        # in PyTCP's vocabulary). The already-in-RTO gate
        # (§2.1 step 1: "If the TCP sender is already in RTO
        # recovery AND 'recover' is larger than or equal to
        # SND.UNA, do not enter step 2 of this algorithm.
        # Instead, store the highest sequence number
        # transmitted so far in variable 'recover'") fires
        # when a second RTO arrives while the first F-RTO is
        # still pending and SND.UNA has not yet covered the
        # original recover marker. In that case, only the
        # recover marker is updated; the original pre-RTO
        # cwnd / ssthresh / CUBIC snapshots are preserved so
        # the eventual restoration anchors at the genuine
        # pre-loss values rather than the post-first-RTO
        # collapsed values.
        already_in_frto = session._cc.frto_step != 0 and not lt32(session._cc.frto_pre_snd_max, session._snd_seq.una)
        if already_in_frto:
            # Update recover only; preserve original snapshots.
            session._cc.frto_pre_snd_max = session._snd_seq.max
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - RFC 5682 §2.1 already-in-RTO gate: "
                f"recover updated to {session._cc.frto_pre_snd_max}; "
                "step 2 skipped (preserving original pre-RTO snapshot)",
            )
        else:
            session._cc.save_frto_snapshot(snd_max=session._snd_seq.max)

        # RFC 5681 §3.1 step 1: on RTO, halve ssthresh so the
        # post-RTO slow-start exits at the previously-observed
        # loss point. The 'max(FlightSize/2, 2*SMSS)' floor
        # prevents a single tiny in-flight segment from
        # collapsing ssthresh below the canonical minimum and
        # prematurely terminating slow-start. FlightSize is
        # computed BEFORE the SND.NXT rewind below so it
        # reflects the unacked-bytes count at the moment of
        # loss detection. Modular subtraction per RFC 9293 §3.4
        # so the value is correct across the 32-bit wrap.
        flight_size = (session._snd_seq.max - session._snd_seq.una) & 0xFFFF_FFFF
        # RFC 9438 §4.6 + §4.7: in CUBIC mode, replace the RFC
        # 5681 §3.1 0.5 halving with beta_cubic = 0.7 and
        # update '_cubic_w_max' / '_cubic_K_ms' /
        # '_cubic_epoch_start_ms' so the post-RTO CA growth
        # curve has a fresh anchor. Fast convergence (§4.7) is
        # active by default: when the new cwnd is smaller than
        # the W_max from the prior loss event, W_max is reduced
        # further to release bandwidth to new flows.
        if session._cc.cc_mode is CcMode.CUBIC:
            prior_w_max = session._cc.cubic_w_max
            session._cc.ssthresh, session._cc.cubic_w_max = cubic_loss_event_ssthresh(
                cwnd=max(session._cc.cwnd, session._win.snd_mss),
                smss=session._win.snd_mss,
                fast_conv_active=True,
                prior_w_max=prior_w_max,
            )
            session._cc.cubic_w_last_max = prior_w_max
            # Curve epoch reset: post-RTO cwnd = 1 SMSS, so
            # cwnd_epoch = SMSS for the cube-root computation.
            session._cc.cubic_K_ms = cubic_compute_K(
                w_max=session._cc.cubic_w_max,
                cwnd_epoch=session._win.snd_mss,
                smss=session._win.snd_mss,
            )
            session._cc.cubic_epoch_start_ms = stack.timer.now_ms
            session._cc.cubic_in_ca = False
            # RFC 9438 §4.3: reset W_est so the next CA stage
            # bootstraps from cwnd_epoch (re-init on first CA
            # cum-ACK in '_process_ack_packet').
            session._cc.cubic_w_est = 0
        else:
            session._cc.ssthresh = compute_loss_event_ssthresh(flight_size, session._win.snd_mss)
        # RFC 5681 §3.1: cwnd collapses to LW = 1 SMSS for
        # slow-start re-entry. RFC 9293 §3.8.6.1 / RFC 1122
        # §4.2.2.16 still require respecting peer's advertised
        # window: a 0-window peer means '_snd_ewn = 0' so
        # '_transmit_data' falls through to the persist branch.
        session._cc.cwnd = session._win.snd_mss
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)
        session._snd_seq.nxt = session._snd_seq.una
        # RFC 5681 §3.1 hard reset: an RTO is a fresh loss
        # event, distinct from the dup-ACK-driven fast-
        # retransmit recovery. The RFC 6675 §5 RecoveryPoint
        # marker (the SND.MAX at fast-retransmit entry) is
        # meaningless once SND.NXT has been rewound to
        # SND.UNA above; leaving it set would inhibit the
        # next dup-ACK from re-entering recovery via the
        # one-shot guard in '_retransmit_packet_request'.
        session._cc.recovery_point = 0
        # RFC 6675 §5.1: "A SACK TCP sender SHOULD utilize all
        # SACK information made available during the loss
        # recovery following an RTO." PyTCP retains the SACK
        # scoreboard across the RTO so the post-RTO recovery
        # can use the prior SACK reports to skip already-
        # delivered ranges, matching the RFC 6675 modern
        # interpretation that supersedes RFC 2018 §5's older
        # "turn off SACKed bits" guidance. Reneging by the
        # peer would violate RFC 8985 RACK-TLP's xmit_ts
        # invariants and would be detected separately.
        # RFC 6582 §3.2 step 4: record the highest SND.MAX
        # transmitted before the RTO so a subsequent burst of
        # dup-ACKs (often produced by the post-RTO retransmit
        # storm) cannot re-trigger fast retransmit until the
        # cum-ACK has progressed past the recover marker.
        # Setting this AFTER '_recovery_point = 0' so the
        # '_retransmit_packet_request' entry gate keys on the
        # recover marker rather than the now-cleared
        # recovery point.
        session._cc.recover_seq = session._snd_seq.max
        # SYN and FIN consume one byte of sequence space but do
        # not occupy a slot in the TX buffer. After
        # '_transmit_packet' fired the original SYN/FIN it
        # incremented '_tx_buffer_seq_mod' by 1 to account for
        # that phantom byte; on retransmit we walk the offset
        # back so the packet builder finds the pre-SYN/FIN
        # alignment again. The FIN branch compares against
        # 'sub32(_snd_fin, 1)' because '_snd_fin' carries the
        # post-FIN-seq (assigned in '_transmit_packet' AFTER
        # 'SND.NXT' was already advanced past the FIN's byte),
        # while the rewind above sets 'SND.NXT = SND.UNA =
        # FIN_seq = _snd_fin - 1' on the canonical "FIN sent,
        # peer ACKed everything before it but not the FIN"
        # path. The branch is gated on '_fin_sent' to prevent
        # the sentinel '_snd_fin = 0' from colliding with a
        # post-wrap 'SND.NXT == 0xFFFF_FFFF' (which would
        # otherwise walk '_tx_buffer_seq_mod' back spuriously
        # and silently corrupt subsequent transmissions).
        if session._snd_seq.nxt == session._snd_seq.ini or (
            session._snd_seq.fin_sent and session._snd_seq.nxt == sub32(session._snd_seq.fin, 1)
        ):
            session._tx.seq_mod = sub32(session._tx.seq_mod, 1)
        __debug__ and log(
            "tcp-ss",
            f"[{session}] - Got retransmit timeout, sending segment "
            f"{session._snd_seq.nxt}, resetting snd_ewn to {session._cc.snd_ewn}",
        )

    def retransmit_packet_request(self, packet_rx_md: TcpMetadata) -> None:
        """
        Retransmit packet after receiving fast-retransmit request from
        peer (RFC 5681 §3.2: third duplicate ACK, one-shot per loss
        event).
        """

        session = self._session
        # Ingest any SACK blocks carried on this dup-ACK before the
        # fast-retransmit decision so IsLost() sees the latest
        # peer-reported scoreboard state. SND.UNA does not advance
        # on a dup-ACK so no prune is needed here.
        session._ingest_sack_info(packet_rx_md)

        # RFC 8985 §6.2 step 1-2 RACK fold + step 5 loss
        # detection on the dup-ACK path. SACK-acked segments
        # advance RACK.xmit_ts even when the cum-ACK does not
        # advance, so a SACK-only dup-ACK can still drive
        # time-based loss detection per RFC 8985 §6.2.
        self.rack_process_ack(packet_rx_md)

        session._tx.retransmit_request_counter[packet_rx_md.tcp__ack] = (
            session._tx.retransmit_request_counter.get(packet_rx_md.tcp__ack, 0) + 1
        )

        # RFC 5681 §3.2 / RFC 6675 §5: enter recovery exactly
        # once per loss event. While 'recovery_point > 0' we are
        # still recovering from an earlier trigger; further
        # dup-ACKs MUST NOT re-fire the retransmit. Cwnd
        # inflation on each dup-ACK is now driven by RFC 6937
        # PRR: a bare dup-ACK delivers no new bytes
        # (DeliveredData = 0) so prr_delivered is unchanged
        # and cwnd stays steady - PRR's proportional pacing
        # replaces the legacy RFC 5681 §3.2 step 4 'cwnd +=
        # SMSS per dup-ACK' rule, which over-inflated cwnd on
        # bare dup-ACK bursts and caused the post-recovery
        # send burst PRR is designed to smooth. SACK-bearing
        # dup-ACKs that delivered new bytes update
        # 'prr_delivered' inside '_ingest_sack_info' and the
        # cwnd recompute on cum-ACK in '_process_ack_packet'
        # picks them up.
        if session._cc.recovery_point != 0:
            return

        # RFC 6582 §3.2 step 4 / step 2 post-RTO gate. After an
        # RTO recorded SND.MAX into '_recover_seq', refuse fast-
        # retransmit entry until SND.UNA has advanced to or past
        # the marker. This prevents the post-RTO retransmit
        # storm's dup-ACK echoes (which carry an old 'ack' value
        # still below the marker) from spuriously triggering a
        # second fast retransmit on top of the just-completed
        # RTO recovery. The 0 sentinel means "no recover marker
        # set" so a fresh connection's first loss event still
        # enters FR.
        if session._cc.recover_seq != 0 and lt32(session._snd_seq.una, session._cc.recover_seq):
            return

        # Two independent triggers, either of which enters
        # recovery:
        #   - Count-based (RFC 5681 §3.2): the third duplicate
        #     ACK at the same 'ack' value.
        #   - SACK byte-rule (RFC 6675 §3 IsLost): the
        #     receiver has reported MORE THAN '(dup_thresh - 1)
        #     * SMSS' bytes SACKed above SND.UNA. This rule
        #     can fire on the very first dup-ACK if peer
        #     reports a single large SACK block, recovering
        #     faster than the count-based threshold on bursty
        #     loss patterns.
        count_trigger = session._tx.retransmit_request_counter[packet_rx_md.tcp__ack] == 3
        sack_trigger = session._advertise.send_sack and is_lost(
            session._snd_seq.una,
            scoreboard=session._sack_scoreboard,
            snd_una=session._snd_seq.una,
            mss=session._win.snd_mss,
        )
        # RFC 3042 Limited Transmit: on the first two
        # duplicate ACKs, send one new segment from the TX
        # buffer if budget permits. The budget is
        # 'cwnd + 2*SMSS' total - one extra segment per
        # dup-ACK (1st and 2nd). Limited Transmit injects
        # new segments into the pipe so a small-window
        # flow can still generate three dup-ACKs at the
        # peer and trigger fast retransmit on real loss
        # rather than waiting for an RTO. The third dup-ACK
        # falls through to the count_trigger path below
        # and runs RFC 5681 §3.2 fast retransmit instead.
        count = session._tx.retransmit_request_counter[packet_rx_md.tcp__ack]
        if count in (1, 2) and len(session._tx.buffer) > 0:
            saved_ewn = session._cc.snd_ewn
            session._cc.snd_ewn = min(session._cc.cwnd + count * session._win.snd_mss, session._win.snd_wnd)
            session._transmit_data()
            session._cc.snd_ewn = saved_ewn

        if not (count_trigger or sack_trigger):
            return

        # RFC 5681 §3.2 step 2: ssthresh = max(FlightSize/2,
        # 2*SMSS). Captures the just-observed loss point so
        # the post-recovery slow-start exits at this boundary.
        flight_size = (session._snd_seq.max - session._snd_seq.una) & 0xFFFF_FFFF
        # RFC 9438 §4.6 + §4.7: in CUBIC mode, ssthresh halves
        # by beta_cubic = 0.7 (vs RFC 5681's 0.5). Records
        # '_cubic_w_max' = cwnd-at-loss for the post-recovery
        # cubic curve. Fast convergence (§4.7) reduces W_max
        # further when the new cwnd is smaller than the prior
        # W_max anchor.
        if session._cc.cc_mode is CcMode.CUBIC:
            prior_w_max = session._cc.cubic_w_max
            # RFC 9438 §4.9.2 spurious-fast-retransmit snapshot:
            # capture the pre-FR CUBIC state so a DSACK during
            # this recovery episode can roll back the
            # multiplicative decrease + curve re-anchor below.
            session._cc.save_fr_cubic_snapshot()
            session._cc.ssthresh, session._cc.cubic_w_max = cubic_loss_event_ssthresh(
                cwnd=session._cc.cwnd,
                smss=session._win.snd_mss,
                fast_conv_active=True,
                prior_w_max=prior_w_max,
            )
            session._cc.cubic_w_last_max = prior_w_max
            session._cc.cubic_K_ms = cubic_compute_K(
                w_max=session._cc.cubic_w_max,
                cwnd_epoch=session._cc.ssthresh,
                smss=session._win.snd_mss,
            )
            session._cc.cubic_epoch_start_ms = stack.timer.now_ms
            session._cc.cubic_in_ca = True
            # RFC 9438 §4.3: reset W_est so the next CA stage
            # bootstraps from the post-recovery cwnd anchor.
            session._cc.cubic_w_est = 0
        else:
            session._cc.ssthresh = compute_loss_event_ssthresh(flight_size, session._win.snd_mss)

        # RFC 6937 §3.1 PRR per-recovery state initialisation:
        # snapshot pipe at entry as 'RecoverFS' so the per-ACK
        # send-pacing math has the denominator for the
        # 'prr_delivered * ssthresh / RecoverFS' ratio. Reset
        # the prr_delivered / prr_out counters to zero so the
        # accumulators only cover this recovery episode.
        session._cc.recover_fs = flight_size
        session._cc.prr_delivered = 0
        session._cc.prr_out = 0

        # RFC 6937 §3.1: at entry 'prr_delivered = 0' and
        # 'prr_out = 0' so the per-ACK formula yields
        # 'sndcnt = 0 - 0 = 0' and 'cwnd = pipe + 0 = pipe'.
        # Pipe at entry equals 'flight_size' (no SACKs ingested
        # this ACK). This replaces the legacy RFC 5681 §3.2
        # step 3 'cwnd = ssthresh + 3*SMSS' coarse approximation
        # with PRR's data-driven per-ACK pacing - subsequent
        # ACKs recompute cwnd via the proportional ratio in
        # '_process_ack_packet'.
        session._cc.cwnd = flight_size
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        # Mark RecoveryPoint at SND.MAX so subsequent dup-ACKs
        # within the loss event do not re-trigger; '_process_ack_packet'
        # clears it once the cumulative ACK has fully recovered.
        # Setting to 'max(SND.MAX, 1)' guarantees the marker is
        # non-zero even when SND.MAX wraps to 0; the actual
        # comparison is modular.
        session._cc.recovery_point = session._snd_seq.max if session._snd_seq.max != 0 else 1

        # RFC 6675 §3 NextSeg() chooses the smallest unsacked
        # seq in '[SND.UNA, SND.MAX)' that IsLost() flags as
        # lost. When bilateral SACK is enabled and the
        # scoreboard's contents satisfy IsLost, NextSeg returns
        # the actual gap; in single-gap scenarios this equals
        # 'SND.UNA' (matching the count-based path). When SACK
        # is disabled or the scoreboard is below IsLost
        # thresholds, fall back to '_snd_una' so the count-based
        # RFC 5681 path remains intact for non-SACK peers.
        ns = (
            next_seg(
                scoreboard=session._sack_scoreboard,
                snd_una=session._snd_seq.una,
                snd_max=session._snd_seq.max,
                mss=session._win.snd_mss,
            )
            if session._advertise.send_sack
            else None
        )
        session._snd_seq.nxt = ns if ns is not None else session._snd_seq.una
        __debug__ and log(
            "tcp-ss",
            f"[{session}] - Got retransmit request, sending segment "
            f"{session._snd_seq.nxt}, keeping snd_ewn at {session._cc.snd_ewn}, "
            f"recovery_point {session._cc.recovery_point}",
        )

    def tlp_pto_tick(self) -> None:
        """
        Per-tick service for the RFC 8985 §7.3 Tail Loss
        Probe. Fires when the f'{session}-tlp' timer expires
        and there is data in flight. Prefers sending new data
        from the TX buffer (when available); falls back to
        retransmitting the highest-seq in-flight segment.

        On emission, marks '_tlp_is_retrans' (True for
        retransmit, False for new-data probe) and stashes the
        post-probe SND.MAX in '_tlp_end_seq' so the §7.4
        loss-detection path can reason about the probe's fate.
        Re-arms the RTO timer at 'rto_state.rto_ms' so the
        connection still has a timeout-driven recovery path
        if the probe itself is lost.
        """

        session = self._session
        # tlp_armed gates the firing path: only when the
        # arming logic in '_transmit_packet' actually armed
        # the TLP timer should this tick treat a
        # '_timer_expired' result as a real timer expiration.
        # Without this gate a session that armed a TLP, let it
        # fire, and never re-armed would still satisfy the
        # downstream expiry check and _tlp_pto_tick would
        # spuriously fire a retransmit on every FSM tick.
        if not session._rack_tlp.tlp_armed:
            return
        if not session._timer_expired("tlp"):
            return
        if session._snd_seq.una == session._snd_seq.max:
            # Nothing in flight - no tail to probe.
            return
        # RFC 8985 §7 once-per-tail gate: TLP fires at most one
        # probe per outstanding tail. '_tlp_end_seq' is set on
        # probe emission and cleared by §7.4 loss-detection
        # logic (Phase 8) once the probe outcome is determined,
        # OR by '_process_ack_packet' when a cum-ACK drains all
        # in-flight bytes (no tail left).
        if session._rack_tlp.tlp_end_seq is not None:
            return
        # RFC 8985 §8 timer arbitration: if RTO recovery is in
        # progress (this tick's _retransmit_packet_timeout
        # incremented _retransmit_count, OR a fast-recovery is
        # underway, OR F-RTO is active), TLP yields. The
        # ongoing recovery machinery handles the loss already;
        # a TLP probe would race it and emit a duplicate.
        if session._retransmit_count > 0 or session._cc.recovery_point != 0 or session._cc.frto_active:
            return

        # New-data probe path: the TX buffer has bytes past
        # SND.MAX (i.e. data the application has queued but
        # the wire has not yet seen). When this is the case
        # we send the next segment from SND.MAX rather than
        # retransmitting an already-sent one. Compute the
        # buffer offset of SND.MAX modularly so a wrapped
        # session is handled correctly.
        tx_buffer_max = sub32(session._snd_seq.max, session._tx.seq_mod)
        new_data_available = tx_buffer_max < len(session._tx.buffer) and session._cc.snd_ewn > tx_buffer_max
        if new_data_available:
            # Force '_transmit_data' to start at SND.MAX (the
            # bytes immediately past the highest-seq sent).
            session._snd_seq.nxt = session._snd_seq.max
            session._rack_tlp.tlp_is_retrans = False
        else:
            # Retransmit-style probe: walk SND.NXT back by one
            # MSS (or less if in-flight is shorter) so
            # _transmit_data re-sends the highest-seq segment.
            flight_size = (session._snd_seq.max - session._snd_seq.una) & 0xFFFF_FFFF
            walk_back = min(session._win.snd_mss, flight_size)
            session._snd_seq.nxt = sub32(session._snd_seq.max, walk_back)
            session._rack_tlp.tlp_is_retrans = True

        session._transmit_data()
        session._rack_tlp.tlp_end_seq = session._snd_seq.max
        # Probe is in flight; clear armed flag so the next
        # tick's _tlp_pto_tick early-returns. The flag is
        # re-set by '_transmit_packet' when a fresh TLP timer
        # arms, e.g. on a subsequent data send.
        session._rack_tlp.tlp_armed = False

        # RFC 8985 §7.3: re-arm the RTO timer after probe so
        # the connection retains its timeout fallback.
        session._arm_timer("retransmit", session._rto_state.rto_ms)

    def rack_reorder_tick(self) -> None:
        """
        Per-tick service for the RFC 8985 §6.2 step 5
        reordering timer. When the f'{session}-rack' timer
        has expired, re-run rack_detect_loss with the current
        scalars and reo_wnd to mark any pending 'sent before'
        segments lost. Subsequent ticks may re-arm the timer
        if more candidates exist.
        """

        session = self._session
        if not session._timer_expired("rack"):
            return
        if session._rack_tlp.rack_xmit_ts == 0:
            return
        reo_wnd_ms = rack_compute_reo_wnd(
            reordering_seen=session._rack_tlp.rack_reordering_seen,
            reo_wnd_mult=session._rack_tlp.rack_reo_wnd_mult,
            min_rtt_ms=session._rack_tlp.rack_min_rtt_ms,
        )
        session._rack_tlp.rack_segments, rack_timeout_ms = rack_detect_loss(
            segments=session._rack_tlp.rack_segments,
            rack_xmit_ts=session._rack_tlp.rack_xmit_ts,
            rack_end_seq=session._rack_tlp.rack_end_seq,
            reo_wnd_ms=reo_wnd_ms,
            now_ms=stack.timer.now_ms,
        )
        if rack_timeout_ms > 0:
            session._arm_timer("rack", rack_timeout_ms)

    def rack_process_ack(self, packet_rx_md: TcpMetadata) -> None:
        """
        Apply RFC 8985 §6.2 step 1-2 (rack_update) + step 5
        (rack_detect_loss) on every accepted ACK. Called from
        both '_process_ack_packet' (cum-ACK path) and
        '_retransmit_packet_request' (SACK-only / dup-ACK
        path) after SACK ingest so the scoreboard reflects
        the latest peer-reported state.

        The 'newly acknowledged' set per §6.2 includes BOTH
        cum-ACKed AND SACK-acked segments delivered for the
        first time on this ACK. The '_rack_acked_seqs' guard
        ensures each segment contributes to the rack_update
        scalars exactly once across multiple ACKs.

        For Phase 3 the loss-detection helper is called with
        'reo_wnd_ms=0' (no reordering tolerance); Phase 4
        will compute reo_wnd dynamically via
        'rack_compute_reo_wnd'.
        """

        session = self._session
        newly_acked: list[RackSegment] = []
        for seq, seg in session._rack_tlp.rack_segments.items():
            if seq in session._rack_tlp.rack_acked_seqs:
                continue
            cum_acked = le32(seg.end_seq, session._snd_seq.una)
            sack_acked = session._advertise.send_sack and session._sack_scoreboard.is_sacked(sub32(seg.end_seq, 1))
            if cum_acked or sack_acked:
                newly_acked.append(seg)
                session._rack_tlp.rack_acked_seqs.add(seq)
        if newly_acked:
            # RFC 8985 §6.2 step 3 reordering detection. For
            # each newly-acked segment, compare its 'end_seq'
            # to '_rack_fack' (the highest end_seq we have
            # seen acked so far). A delivered segment whose
            # end_seq is strictly below fack means the network
            # has reordered: a later-sent segment was already
            # acked before this one. Once 'reordering_seen' is
            # True it stays True; the §6.2 step 4 reo_wnd
            # computation uses it to switch from the dup-ACK
            # trigger (reo_wnd=0) to the time-based trigger
            # (reo_wnd = min_RTT / 4 * reo_wnd_mult).
            for seg in newly_acked:
                if session._rack_tlp.rack_fack != 0 and lt32(seg.end_seq, session._rack_tlp.rack_fack):
                    session._rack_tlp.rack_reordering_seen = True
                if gt32(seg.end_seq, session._rack_tlp.rack_fack):
                    session._rack_tlp.rack_fack = seg.end_seq
            (
                session._rack_tlp.rack_min_rtt_ms,
                session._rack_tlp.rack_rtt_ms,
                session._rack_tlp.rack_xmit_ts,
                session._rack_tlp.rack_end_seq,
            ) = rack_update(
                newly_acked_segments=newly_acked,
                now_ms=stack.timer.now_ms,
                ts_recent_echo_ms=(packet_rx_md.tcp__tsecr if packet_rx_md.tcp__tsecr else None),
                prior_min_rtt_ms=session._rack_tlp.rack_min_rtt_ms,
                prior_rack_rtt_ms=session._rack_tlp.rack_rtt_ms,
                prior_rack_xmit_ts=session._rack_tlp.rack_xmit_ts,
                prior_rack_end_seq=session._rack_tlp.rack_end_seq,
            )

        if session._rack_tlp.rack_xmit_ts > 0:
            # RFC 8985 §6.2 step 4 dynamic reo_wnd via
            # rack_compute_reo_wnd. Phase 3 used 0; Phase 4
            # adapts based on observed reordering and DSACK
            # rounds.
            reo_wnd_ms = rack_compute_reo_wnd(
                reordering_seen=session._rack_tlp.rack_reordering_seen,
                reo_wnd_mult=session._rack_tlp.rack_reo_wnd_mult,
                min_rtt_ms=session._rack_tlp.rack_min_rtt_ms,
            )
            session._rack_tlp.rack_segments, rack_timeout_ms = rack_detect_loss(
                segments=session._rack_tlp.rack_segments,
                rack_xmit_ts=session._rack_tlp.rack_xmit_ts,
                rack_end_seq=session._rack_tlp.rack_end_seq,
                reo_wnd_ms=reo_wnd_ms,
                now_ms=stack.timer.now_ms,
            )
            # RFC 8985 §6.2 step 5 reordering-timer arming.
            # When rack_detect_loss leaves any 'sent before'
            # segment within its reo_wnd (timeout_ms > 0),
            # arm a single session-level timer at the earliest
            # 'xmit_ts + reo_wnd - now_ms' so the FSM tick can
            # re-run the loss-detection check and mark the
            # segment lost once the window has elapsed.
            if rack_timeout_ms > 0:
                session._arm_timer("rack", rack_timeout_ms)
