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
This module contains the per-session TCP inbound-ACK processor —
'TcpAckProcessor' — which owns the inbound-ACK pipeline:
'process_ack_packet' (the entry point called from the FSM
handlers) + the five '_phase1..5' helpers (cum-ACK side effects,
F-RTO spurious-RTO detection, RTT-sample harvest, loss-detection
+ recovery-exit, segment consume + delayed-ACK postprocess).
Phase 3 of the TcpSession god-class decomposition.

Pure structural extraction — no behaviour change, no new lock.
The processor holds a back-reference to the session and
reads/writes every shared state dataclass via
'self._session.<state>', matching the idiom 'fsm/' and the
Phase-2 TX engine already use. The session keeps a thin
'_process_ack_packet' delegator so 'fsm/' handlers and other
callers continue to call it unchanged.

packages/pytcp/pytcp/protocols/tcp/session/tcp__session__ack.py

ver 3.0.8
"""

import time
from typing import TYPE_CHECKING

from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.tcp import tcp__constants
from pytcp.protocols.tcp.tcp__cubic import cubic_grow_per_ack, cubic_w_est
from pytcp.protocols.tcp.tcp__cwnd import compute_loss_event_ssthresh, cwnd_grow_per_ack
from pytcp.protocols.tcp.tcp__enums import CcMode
from pytcp.protocols.tcp.tcp__hystart import (
    css_growth_increment,
    fold_rtt_sample,
    resume_slow_start,
    rotate_round,
)
from pytcp.protocols.tcp.tcp__loss_recovery import pipe
from pytcp.protocols.tcp.tcp__rack import tlp_process_ack
from pytcp.protocols.tcp.tcp__rto import update
from pytcp.protocols.tcp.tcp__seq import add32, ge32, gt32, le32, lt32

if TYPE_CHECKING:
    from pytcp.protocols.tcp.session import TcpSession
    from pytcp.socket.tcp__metadata import TcpMetadata


class TcpAckProcessor:
    """
    Per-session TCP inbound-ACK processor — owns the five-phase
    'process_ack_packet' pipeline.
    """

    def __init__(self, session: "TcpSession", /) -> None:
        """
        Initialize the ACK processor with a back-reference to
        the owning session.
        """

        self._session: TcpSession = session

    # ------------------------------------------------------------------
    # Public surface — called via the session's _process_ack_packet
    # delegator from 'fsm/' state handlers.
    # ------------------------------------------------------------------

    def process_ack_packet(self, packet_rx_md: "TcpMetadata") -> None:
        """
        Process regular data/ACK packet.
        """

        session = self._session
        # RFC 7323 §5 PAWS + §4.3 '_ts_recent' refresh: handled
        # by '_check_paws_and_update_ts_recent' so the same
        # gate applies on every inbound dispatch path
        # (dup-ACK fast-retransmit, OOO insert, TIME_WAIT late
        # segments, etc.). Stale-TSval segments are silently
        # dropped per RFC 7323 §5.4.
        if not session._check_paws_and_update_ts_recent(packet_rx_md):
            return

        # RFC 1122 §4.2.3.6: peer activity (ACK and / or data)
        # resets the keep-alive idle timer. No-op when keep-alive
        # is disabled.
        session._keepalive_arm_idle()

        self._phase1_cum_ack_side_effects(packet_rx_md)
        self._phase3_harvest_rtt_samples(packet_rx_md)
        # SACK scoreboard maintenance per RFC 6675 §3 / RFC 2018
        # §3: prune any blocks now absorbed by the cumulative ACK,
        # then ingest fresh blocks the peer reported on this
        # segment. Both are no-ops when '_send_sack' is False.
        session._prune_sack_scoreboard()
        session._ingest_sack_info(packet_rx_md)
        self._phase4_loss_detection_and_recovery_exit(packet_rx_md)
        self._phase5_consume_segment_and_postprocess(packet_rx_md)

    # ------------------------------------------------------------------
    # Private processor helpers — phases of 'process_ack_packet'.
    # ------------------------------------------------------------------

    def _phase1_cum_ack_side_effects(self, packet_rx_md: "TcpMetadata") -> None:
        """
        Phase 1 of the inbound-ACK pipeline. Process the side-
        effects of a cum-ACK that advances SND.UNA: bytes_acked
        compute, SND.UNA advance, RFC 9406 round-boundary rotate,
        RFC 6582 recover_seq decay, RFC 6937 PRR delivered
        accumulation, RFC 9438 / 5681 / 6928 cwnd growth (CUBIC
        vs Reno + HyStart CSS override), RFC 9293 §3.8.4 snd_ewn
        recompute, RFC 6298 retransmit-timer manage, RFC 8985
        §7.2 / §7.4 TLP loss-detect / repair / cancel, and the
        RFC 5682 §2.1 F-RTO step 2 / step 3 spurious-RTO
        detection (delegated to phase 2).

        Returns early when the inbound ACK does not advance
        SND.UNA — dup-ACKs and stale ACKs do not exercise any
        of these side-effects.

        Reference: RFC 5681 §3.1 (slow-start vs CA growth).
        Reference: RFC 5681 §3.2 step 4 (per-dup-ACK inflation).
        Reference: RFC 6298 §5.2 (retransmit-timer off on full drain).
        Reference: RFC 6298 §5.3 (retransmit-timer restart on advance).
        Reference: RFC 6582 §3.2 step 4 (NewReno recover decay).
        Reference: RFC 6928 (initial-window slow-start).
        Reference: RFC 6937 §3.1 (PRR proportional pacing).
        Reference: RFC 8985 §7.2 (TLP cancellation on cum-ACK drain).
        Reference: RFC 8985 §7.4 (TLP loss-detection on inbound ACK).
        Reference: RFC 8985 §7.4.2 (TLP probe-repair CC response).
        Reference: RFC 9293 §3.4 (modular SND.UNA arithmetic).
        Reference: RFC 9293 §3.8.4 (snd_ewn = min(cwnd, snd_wnd)).
        Reference: RFC 9406 §4.2 (HyStart++ round-boundary + CSS).
        Reference: RFC 9438 §4.3 (W_est Reno-friendly tracker).
        Reference: RFC 9438 §4.4 (CUBIC growth in CA).
        Reference: RFC 9438 §4.5 (CUBIC slow-start path).
        """

        session = self._session
        # Make note of the local SEQ that has been acked by peer.
        # Modular 'max': SND.UNA advances iff peer's ack is
        # "ahead" of it in the 32-bit modular sense. Plain 'max()'
        # uses numerical order, which is wrong across the wrap.
        if not lt32(session._snd_seq.una, packet_rx_md.tcp__ack):
            return

        # RFC 4861 §7.3.1 upper-layer reachability confirmation:
        # an in-window cum-ACK that advances SND.UNA is positive
        # evidence the neighbour is reachable; promote any
        # STALE / DELAY / PROBE entry directly to REACHABLE
        # without firing a unicast probe (ND for IPv6 peers,
        # ARP for IPv4). Linux's 'NEIGH_UPDATE_F_USE' is the
        # equivalent hook.
        session._confirm_neighbor_reachability()

        # Modular bytes-acked computation per RFC 9293 §3.4
        # so the §3.1 cwnd growth formula gets the correct
        # delta when the cum-ACK straddles the 32-bit wrap.
        bytes_acked = (packet_rx_md.tcp__ack - session._snd_seq.una) & 0xFFFF_FFFF
        session._snd_seq.una = packet_rx_md.tcp__ack
        # PLPMTUD adapter: notify of snd.una advance so any
        # in-flight probe whose seq is now <= new_snd_una
        # gets dispatched as an on_probe_ack event.
        # Linux 'tcp_mtu_probe_success' equivalent: a
        # successful probe ack grows the engine's
        # 'current_mtu'; sync 'self._win.snd_mss' to match
        # so future data segments use the newly-confirmed
        # larger MSS. Detect the growth by snapshotting the
        # engine's current_mtu around the dispatch — only
        # fires when on_probe_ack actually advanced it.
        plpmtud_current_before = session._plpmtud_adapter.current_mtu
        session._plpmtud_adapter.on_snd_una_advance(
            new_snd_una=session._snd_seq.una,
            now=time.monotonic(),
        )
        if session._plpmtud_adapter.current_mtu > plpmtud_current_before:
            engine_mss = session._plpmtud_adapter.current_mtu - session._ip_tcp_overhead
            if engine_mss > session._win.snd_mss:
                session._win.snd_mss = engine_mss
        # RFC 9406 §4.2 round-boundary detection: if SND.UNA
        # has reached or passed the round's window_end_seq,
        # rotate the per-round minRTT trackers. The first
        # round bootstrap-initialises window_end_seq from
        # SND.NXT; subsequent rotations also re-anchor
        # window_end_seq to the current SND.NXT so the next
        # round measures samples until the in-flight
        # high-water mark is acked. CSS_ROUNDS exhaustion
        # is signalled by 'css_rounds_remaining == 0' after
        # rotate_round; that triggers the §4.2 "set
        # ssthresh = cwnd" entry into congestion avoidance.
        if session._cc.cwnd < session._cc.ssthresh:
            if session._cc.hystart_state.window_end_seq == 0:
                # Bootstrap: first round of slow-start.
                session._cc.hystart_state.window_end_seq = session._snd_seq.nxt
            elif not lt32(session._snd_seq.una, session._cc.hystart_state.window_end_seq):
                rotate_round(session._cc.hystart_state, new_window_end_seq=session._snd_seq.nxt)
                if session._cc.hystart_state.in_css and session._cc.hystart_state.css_rounds_remaining == 0:
                    # CSS_ROUNDS exhausted -> ssthresh =
                    # cwnd, enter CA. Clear CSS state.
                    session._cc.ssthresh = session._cc.cwnd
                    resume_slow_start(session._cc.hystart_state)
                    __debug__ and log(
                        "tcp-ss",
                        f"[{session}] - RFC 9406 HyStart++ "
                        "CSS_ROUNDS exhausted; ssthresh = "
                        f"cwnd = {session._cc.cwnd}, entering CA",
                    )
        # RFC 6582 §3.2 step 4 marker decay: clear the
        # recover marker once SND.UNA has reached or passed
        # it. SND.UNA is the next-byte-expected from peer,
        # so 'SND.UNA == recover' means peer has acked the
        # last byte recorded into the marker (recover ==
        # snd_max-at-RTO == one past last data seq); 'ge32'
        # is the right comparison. Subsequent dup-ACK bursts
        # can then drive fast retransmit normally without
        # the post-RTO gate suppressing legitimate loss
        # recovery.
        if session._cc.recover_seq != 0 and ge32(session._snd_seq.una, session._cc.recover_seq):
            session._cc.recover_seq = 0
        # RFC 6937 §3.1 PRR: cumulative bytes ACK'd during
        # recovery feed 'prr_delivered'. Out-of-recovery
        # cum-ACKs do not - the accumulator is scoped to a
        # single recovery episode.
        if session._cc.recovery_point != 0:
            session._cc.prr_delivered += bytes_acked
        # Cwnd update on cum-ACK that advances SND.UNA.
        # Three branches gated on recovery state:
        #   - in recovery, partial cum-ACK (snd_una hasn't
        #     reached recovery_point): RFC 6937 §3.1 PRR
        #     proportional pacing - 'cwnd = pipe + sndcnt'
        #     where sndcnt is computed from the
        #     'prr_delivered * ssthresh / RecoverFS' ratio.
        #     Replaces the RFC 6582 NewReno step 3b
        #     deflation; PRR's per-ACK proportional pacing
        #     subsumes both the deflate-on-partial-ACK
        #     intent and RFC 5681 §3.2 step 4's per-dup-ACK
        #     inflation.
        #   - in recovery, full cum-ACK (snd_una reached
        #     recovery_point): RFC 5681 §3.2 step 6
        #     deflation (cwnd = ssthresh) - handled at the
        #     recovery-exit branch below.
        #   - not in recovery: RFC 5681 §3.1 slow-start vs
        #     congestion-avoidance growth.
        if session._cc.recovery_point != 0 and lt32(session._snd_seq.una, session._cc.recovery_point):
            current_pipe = pipe(
                scoreboard=session._sack_scoreboard,
                snd_una=session._snd_seq.una,
                snd_max=session._snd_seq.max,
            )
            if current_pipe > session._cc.ssthresh:
                # PRR proper: aim for ssthresh/RecoverFS
                # ratio. Integer CEIL via the standard
                # '-(-a // b)' trick to avoid float math.
                target = -(-session._cc.prr_delivered * session._cc.ssthresh // session._cc.recover_fs)
                sndcnt = target - session._cc.prr_out
            else:
                # PRR-CRB / PRR-SSRB: pipe has dropped at
                # or below ssthresh; allow conservative
                # send budget. SSRB (bilateral SACK + new
                # data this ACK) lets cwnd grow up to one
                # SMSS per ACK; CRB (no SACK or no new
                # data) caps at the unsent prr_delivered.
                if session._advertise.send_sack and bytes_acked > 0:
                    limit = max(session._cc.prr_delivered - session._cc.prr_out, bytes_acked) + session._win.snd_mss
                else:
                    limit = session._cc.prr_delivered - session._cc.prr_out
                sndcnt = min(session._cc.ssthresh - current_pipe, limit)
            session._cc.cwnd = current_pipe + max(0, sndcnt)
        else:
            # RFC 9438 §4.4 / §4.5: when '_cc_mode == CUBIC'
            # AND we are in CA (cwnd >= ssthresh), use the
            # cubic growth formula instead of the linear
            # Reno CA branch. Slow-start (cwnd < ssthresh)
            # is handled inside both helpers and yields the
            # same RFC 5681 §3.1 path either way.
            if session._cc.cc_mode is CcMode.CUBIC and session._cc.cwnd >= session._cc.ssthresh:
                session._cc.cubic_in_ca = True
                now_ms = stack.timer.now_ms
                cubic_cwnd = cubic_grow_per_ack(
                    cwnd=session._cc.cwnd,
                    ssthresh=session._cc.ssthresh,
                    w_max=session._cc.cubic_w_max,
                    K_ms=session._cc.cubic_K_ms,
                    epoch_start_ms=session._cc.cubic_epoch_start_ms,
                    now_ms=now_ms,
                    bytes_acked=bytes_acked,
                    smss=session._win.snd_mss,
                    srtt_ms=session._rto_state.srtt_ms or 0,
                )
                # RFC 9438 §4.3: track the Reno-equivalent
                # cwnd ('W_est') in parallel; if the cubic
                # formula yields a smaller cwnd than Reno
                # would, fall back to W_est so CUBIC never
                # under-performs Reno on small-BDP / short-
                # RTT paths. Lazy-initialise on first CA
                # entry from cwnd_epoch.
                if session._cc.cubic_w_est == 0:
                    session._cc.cubic_w_est = session._cc.cwnd
                session._cc.cubic_w_est = cubic_w_est(
                    w_est_prev=session._cc.cubic_w_est,
                    cwnd=session._cc.cwnd,
                    smss=session._win.snd_mss,
                    bytes_acked=bytes_acked,
                )
                session._cc.cwnd = max(cubic_cwnd, session._cc.cubic_w_est)
            else:
                # RFC 9406 §4.2 CSS phase override: when
                # HyStart++ has detected delay-increase and
                # we are in Conservative Slow Start, grow
                # cwnd at 1/CSS_GROWTH_DIVISOR the normal
                # rate. Outside CSS this is the normal
                # RFC 5681 / RFC 6928 slow-start or RFC
                # 5681 §3.1 congestion-avoidance growth via
                # 'cwnd_grow_per_ack'.
                if session._cc.cwnd < session._cc.ssthresh and session._cc.hystart_state.in_css:
                    session._cc.cwnd += css_growth_increment(bytes_acked, session._win.snd_mss)
                else:
                    session._cc.cwnd = cwnd_grow_per_ack(
                        session._cc.cwnd, session._cc.ssthresh, bytes_acked, session._win.snd_mss
                    )
        # RFC 9293 §3.8.4: the effective send window is
        # 'min(cwnd, snd_wnd)'. Recompute now so
        # '_transmit_data' sees the new value on the same
        # FSM tick.
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)
        # RFC 6298 §5.2 / §5.3: peer has acknowledged new
        # data, fresh evidence of liveness. Reset the R2
        # abort counter and manage the retransmit timer:
        # turn it off iff every in-flight byte is now
        # acked (§5.2), else restart it with the current
        # 'rto_ms' (§5.3) — see the cancel/arm below.
        session._retransmit_count = 0
        # RFC 8985 §7.4 TLP loss-detection on inbound ACK.
        # Apply BEFORE the cum-ACK drain hook so a Case-3
        # ('ack > tlp_end_seq') ACK that also drains the
        # tail can invoke the §7.4.2 CC response. Returns
        # the new '_tlp_end_seq' (None on outcome
        # determined; preserved otherwise) and a flag
        # indicating whether to halve cwnd / ssthresh.
        new_tlp_end_seq, invoke_cc = tlp_process_ack(
            tlp_end_seq=session._rack_tlp.tlp_end_seq,
            tlp_is_retrans=session._rack_tlp.tlp_is_retrans,
            ack_seq=packet_rx_md.tcp__ack,
            has_dsack_for_probe=(session._dsack_received > 0),
            has_sack_blocks=bool(session._sack_scoreboard.blocks()),
        )
        session._rack_tlp.tlp_end_seq = new_tlp_end_seq
        if invoke_cc:
            # RFC 8985 §7.4.2: probe repaired a single
            # tail loss; the network signalled a real
            # loss event so apply the conventional
            # cwnd halving (ssthresh = max(flight/2,
            # 2*SMSS); cwnd = ssthresh).
            flight_size = (session._snd_seq.max - session._snd_seq.una) & 0xFFFF_FFFF
            session._cc.ssthresh = compute_loss_event_ssthresh(flight_size, session._win.snd_mss)
            session._cc.cwnd = session._cc.ssthresh
            session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - RFC 8985 §7.4.2 TLP probe-repair "
                f"CC: ssthresh={session._cc.ssthresh} cwnd={session._cc.cwnd}",
            )
        if session._snd_seq.una == session._snd_seq.max:
            session._cancel_timer("retransmit")
            # RFC 8985 §7.2 TLP cancellation: when a
            # cum-ACK drains all in-flight bytes, there is
            # no tail to probe. Cancel the TLP timer so a
            # late expiry does not fire a stale probe.
            # Also clear the once-per-tail state so the
            # next tail can fire its own probe.
            session._cancel_timer("tlp")
            session._rack_tlp.cancel_tlp()
        else:
            session._arm_timer("retransmit", session._rto_state.rto_ms)
        self._phase2_frto_spurious_detect()

    def _phase2_frto_spurious_detect(self) -> None:
        """
        Phase 2 of the inbound-ACK pipeline. RFC 5682 §2.1 step 2
        / step 3 F-RTO spurious-RTO detection. Up to two post-RTO
        ACKs classify the RTO:

          step==1 (first post-RTO ACK):
            - SND.UNA covers all pre-RTO data (>= recover):
              single-ACK strong-spurious; restore and exit.
            - SND.UNA partially advances (still < recover):
              step 2b — defer decision to second ACK, set
              frto_step=2 and stay in F-RTO. PyTCP's existing
              _transmit_data flow naturally sends up to 2 new
              segments after this cum-ACK because cwnd was reset
              to 1 SMSS on RTO and slow-start grows it by 1 SMSS
              per ACK.
          step==2 (second post-RTO ACK):
            - SND.UNA advanced further: spurious declared per
              step 3b; restore and exit.
            - (dup-ACK paths are handled in the dup-ACK branch.)

        Caller MUST guard the invocation on cum-ACK advance
        (lt32(self._snd_seq.una, packet_rx_md.tcp__ack) was True at
        the top of phase 1) — F-RTO step transitions assume the
        ACK advances the window.

        Reference: RFC 5682 §2.1 step 2 (single-ACK strong-spurious).
        Reference: RFC 5682 §2.1 step 3b (two-ACK advancing path).
        Reference: RFC 9438 §4.9.1 (CUBIC F-RTO snapshot restore).
        """

        session = self._session
        if not session._cc.frto_active:
            return
        fully_covered = not lt32(session._snd_seq.una, session._cc.frto_pre_snd_max)
        if session._cc.frto_step == 1:
            if fully_covered:
                # Single-ACK strong-spurious — restore.
                session._cc.frto_step = 0
                session._cc.frto_active = False
                session._cc.restore_frto_snapshot(snd_wnd=session._win.snd_wnd)
                __debug__ and log(
                    "tcp-ss",
                    f"[{session}] - RFC 5682 F-RTO: spurious RTO "
                    f"detected, restored cwnd={session._cc.cwnd} "
                    f"ssthresh={session._cc.ssthresh}; "
                    f"RFC 9438 §4.9.1: restored cubic "
                    f"w_max={session._cc.cubic_w_max} "
                    f"K_ms={session._cc.cubic_K_ms}",
                )
            else:
                # Step 2b: partial advance, defer to step 3.
                session._cc.frto_step = 2
                __debug__ and log(
                    "tcp-ss",
                    f"[{session}] - RFC 5682 §2.1 step 2b: "
                    f"partial first post-RTO ACK "
                    f"(SND.UNA={session._snd_seq.una} < recover="
                    f"{session._cc.frto_pre_snd_max}); waiting "
                    "for second ACK to declare spurious",
                )
        elif session._cc.frto_step == 2:
            # Second ACK that advances the window declares the
            # timeout spurious per §2.1 step 3b. We landed here
            # because the caller's cum-ACK advance gate was True;
            # that's the §2.1 "acknowledgment advances the window"
            # condition.
            session._cc.frto_step = 0
            session._cc.frto_active = False
            session._cc.restore_frto_snapshot(snd_wnd=session._win.snd_wnd)
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - RFC 5682 F-RTO: spurious RTO "
                f"detected, restored cwnd={session._cc.cwnd} "
                f"ssthresh={session._cc.ssthresh}; "
                f"RFC 9438 §4.9.1: restored cubic "
                f"w_max={session._cc.cubic_w_max} "
                f"K_ms={session._cc.cubic_K_ms}",
            )

    def _phase3_harvest_rtt_samples(self, packet_rx_md: "TcpMetadata") -> None:
        """
        Phase 3 of the inbound-ACK pipeline. Harvest an RTT sample
        from the inbound ACK via either the RFC 7323 §4 TSecr path
        (preferred when bilateral TSopt is enabled — unambiguous
        even on retransmissions, obviating Karn's algorithm) or
        the RFC 6298 §4 sample-tracker path (Karn-gated). Either
        path also folds the observed RTT into HyStart++ state
        during slow-start so the per-round min-RTT trackers can
        drive the SS->CSS / CSS->SS transitions.

        Independent of cum-ACK advance: a dup-ACK that carries a
        new TSecr can still produce a valid RTT measurement.

        Reference: RFC 6298 §3 (Karn's algorithm).
        Reference: RFC 6298 §4 (RTO RTT-sample update).
        Reference: RFC 7323 §4 (TSecr-driven RTTM).
        Reference: RFC 9406 §4.2 (HyStart++ RTT fold).
        """

        session = self._session
        # RFC 7323 §4 TSecr-driven RTTM: peer's TSecr identifies
        # the specific transmission it acknowledges, so the RTT
        # measurement is unambiguous even on retransmitted
        # segments (RFC 7323 §4 obviates Karn's algorithm).
        # When bilateral TSopt is enabled and peer's ACK carries
        # a non-zero TSecr that echoes one of our previous
        # TSvals, fold 'now_ms - tsecr' into '_rto_state' via
        # 'update'. This SUPERSEDES the Phase-2 sample tracker,
        # which would otherwise skip the harvest on Karn-
        # tainted samples. Clear the tracker after to prevent
        # double-folding.
        if session._ts.send_ts and packet_rx_md.tcp__tsecr is not None and packet_rx_md.tcp__tsecr != 0:
            ts_rtt_ms = (stack.timer.now_ms - packet_rx_md.tcp__tsecr) & 0xFFFF_FFFF
            session._rto_state = update(session._rto_state, ts_rtt_ms)
            # RFC 9406 §4.2: fold the RTT sample into HyStart
            # state during slow-start (or CSS) so the per-round
            # min-RTT trackers can drive the SS->CSS / CSS->SS
            # transitions. Skipped after slow-start exits
            # (cwnd >= ssthresh AND not in_css) — HyStart++ is a
            # slow-start-only mechanism.
            if session._cc.cwnd < session._cc.ssthresh or session._cc.hystart_state.in_css:
                fold_rtt_sample(session._cc.hystart_state, ts_rtt_ms)
                session._hystart_check_phase_transition()
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - RFC 7323 §4 TSecr-driven RTTM: "
                f"rtt={ts_rtt_ms} ms via TSecr="
                f"{packet_rx_md.tcp__tsecr}; rto_state="
                f"{session._rto_state}",
            )
            session._rtt.clear()

        # RFC 6298 §4 sample harvest: peer's cumulative ACK has
        # advanced past the seq of our pending RTT sample. Fold
        # the observed RTT into '_rto_state' iff the sample was
        # not retransmitted (Karn's algorithm, RFC 6298 §3); in
        # either case clear the tracker so the next outbound
        # segment can start a fresh sample. Modular 'gt32' so the
        # harvest fires correctly when both seq and ack straddle
        # the 32-bit wrap.
        if session._rtt.seq is not None and gt32(packet_rx_md.tcp__ack, session._rtt.seq):
            if not session._rtt.retransmitted:
                assert session._rtt.send_time_ms is not None
                observed_rtt_ms = stack.timer.now_ms - session._rtt.send_time_ms
                session._rto_state = update(session._rto_state, observed_rtt_ms)
                # RFC 9406 §4.2: see TSecr-fold note above; same
                # HyStart++ feed in the Karn-tracker harvest path.
                if session._cc.cwnd < session._cc.ssthresh or session._cc.hystart_state.in_css:
                    fold_rtt_sample(session._cc.hystart_state, observed_rtt_ms)
                    session._hystart_check_phase_transition()
                __debug__ and log(
                    "tcp-ss",
                    f"[{session}] - RTT sample harvested: rtt={observed_rtt_ms} ms, " f"rto_state={session._rto_state}",
                )
            else:
                __debug__ and log(
                    "tcp-ss",
                    f"[{session}] - RTT sample tainted by retransmit (Karn); "
                    f"skipping update of {session._rto_state}",
                )
            session._rtt.clear()

    def _phase4_loss_detection_and_recovery_exit(self, packet_rx_md: "TcpMetadata") -> None:
        """
        Phase 4 of the inbound-ACK pipeline. Fold the inbound ACK
        + SACK info into the RACK reorder-window state, prune the
        per-segment dict for entries fully covered by SND.UNA,
        and exit recovery if SND.UNA has reached or passed the
        RecoveryPoint marker.

        Reference: RFC 5681 §3.2 step 6 (cwnd = ssthresh on recovery exit).
        Reference: RFC 6675 §5 (RecoveryPoint sentinel).
        Reference: RFC 6937 §3.1 (PRR per-recovery state reset).
        Reference: RFC 8985 §5.2 (RACK per-segment dict pruning).
        Reference: RFC 8985 §6.2 (RACK fold + reo_wnd_persist decay).
        Reference: RFC 9438 §4.9.2 (FR-CUBIC snapshot scope = one episode).
        """

        session = self._session
        # RFC 8985 §6.2 step 1-2 RACK fold + step 5 loss
        # detection. Run AFTER SACK ingest so the scoreboard
        # reflects the latest peer-reported state. Identical
        # invocation in '_retransmit_packet_request' for the
        # dup-ACK path.
        session._rack_process_ack(packet_rx_md)

        # RFC 8985 §5.2 RACK per-segment dict pruning. An entry's
        # 'end_seq' at or below SND.UNA is wholly covered by the
        # cumulative ACK - the segment has been delivered and is
        # no longer in flight. Modular 'le32' so the prune fires
        # correctly when both 'end_seq' and SND.UNA straddle the
        # 32-bit wrap. Phase 1 only ships the storage substrate;
        # Phase 2 onward consumes the dict for time-based loss
        # detection / RACK_sent_after / TLP probe selection. The
        # parallel '_rack_acked_seqs' set is pruned alongside so
        # a future segment that lands at the same seq (post-
        # wrap) is not falsely treated as already-acked.
        session._rack_tlp.prune_segments(snd_una=session._snd_seq.una)
        # Exit recovery once SND.UNA has advanced to or past the
        # RecoveryPoint marker (RFC 6675 §5). The loss event is
        # now fully recovered; subsequent dup-ACKs are eligible
        # to re-enter recovery via either trigger. RFC 5681 §3.2
        # step 6 mandates deflating cwnd back to ssthresh on
        # exit so the inflation from steps 3+4 is undone and
        # subsequent §3.1 growth resumes from the previously-
        # observed loss boundary.
        if session._cc.recovery_point != 0 and le32(session._cc.recovery_point, session._snd_seq.una):
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - Exiting recovery: SND.UNA={session._snd_seq.una} "
                f"reached RecoveryPoint={session._cc.recovery_point}",
            )
            session._cc.cwnd = session._cc.ssthresh
            session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)
            session._cc.recovery_point = 0
            # RFC 9438 §4.9.2 snapshot is scoped to a single
            # recovery episode; clear on exit so a stray DSACK
            # post-recovery does not roll back unrelated state.
            session._cc.clear_fr_cubic_snapshot()
            # RFC 6937 §3.1 PRR: per-recovery state is scoped
            # to a single recovery episode. Reset on exit so
            # the next loss event snapshots a fresh
            # 'RecoverFS' and re-accumulates from zero.
            session._cc.recover_fs = 0
            session._cc.prr_delivered = 0
            session._cc.prr_out = 0
            # RFC 8985 §6.2 step 4 reo_wnd_persist decay. Each
            # recovery exit decrements the persist counter; on
            # reaching zero, the multiplier and persist counter
            # reset to their defaults so the connection
            # eventually decays back to the canonical reordering
            # tolerance after a long stretch of recoveries
            # without DSACK.
            session._rack_tlp.decay_reo_wnd_persist()

    def _phase5_consume_segment_and_postprocess(self, packet_rx_md: "TcpMetadata") -> None:
        """
        Phase 5 of the inbound-ACK pipeline. Consume the inbound
        segment's data + window field, fire the delayed-ACK side-
        effects, purge stale TX-retransmit bookkeeping, and drain
        a queued out-of-order segment if 'rcv_nxt' has advanced
        across it. Last phase; reads everything settled by the
        earlier phases.

        Reference: RFC 9293 §3.4 (RCV.NXT advance protections).
        Reference: RFC 9293 §3.8.4 (snd_ewn = min(cwnd, snd_wnd)).
        Reference: RFC 9293 §3.8.6.1 (persist timer reset on reopen).
        Reference: RFC 9293 §3.10.7.4 (segment-arrives RCV.NXT update).
        Reference: RFC 1122 §4.2.3.2 (delayed-ACK every-other-segment).
        Reference: RFC 2883 §3 (DSACK detection / generation).
        Reference: RFC 5961 §5 (MAX.SND.WND running maximum).
        """

        session = self._session
        # Adjust local SEQ accordingly to what peer acked (needed after the
        # retransmit happens and peer is jumping to previously received SEQ).
        if lt32(session._snd_seq.nxt, session._snd_seq.una) and le32(session._snd_seq.una, session._snd_seq.max):
            session._snd_seq.nxt = session._snd_seq.una
        # Update the next-expected receive sequence number, with two
        # protections drawn from RFC 9293 §3.4 / §3.10.7.4:
        #   1. Use 'max(...)' so a stale-duplicate segment whose tail
        #      lies entirely BEFORE our current RCV.NXT cannot REWIND
        #      RCV.NXT backward and corrupt the connection's seq
        #      tracking.
        #   2. Compute the overlap prefix - the count of already-
        #      received bytes at the front of this segment - so the
        #      enqueue path below can slice them off and avoid
        #      double-delivering bytes the application has already
        #      seen on a previous segment.
        # Modular 'seg_end' computation per RFC 9293 §3.4: each
        # operand contributes one or more sequence numbers, and
        # the sum wraps modulo 2**32.
        seg_end = add32(
            packet_rx_md.tcp__seq,
            len(packet_rx_md.tcp__data),
            packet_rx_md.tcp__flag_syn,
            packet_rx_md.tcp__flag_fin,
        )
        # Modular overlap-prefix: how many bytes at the front of
        # this segment we have already received (RCV.NXT - seq,
        # in modular 32-bit space; clamped to 0 if the segment is
        # entirely new).
        if lt32(packet_rx_md.tcp__seq, session._rcv_seq.nxt):
            overlap_prefix = (session._rcv_seq.nxt - packet_rx_md.tcp__seq) & 0xFFFF_FFFF
        else:
            overlap_prefix = 0
        # RFC 2883 DSACK: stash the duplicate-prefix range so the
        # next outbound ACK reports it as the FIRST SACK block.
        # The range is '[seg_seq, seg_seq + overlap_prefix)' which
        # equals '[seg_seq, OLD RCV.NXT)' (RCV.NXT advances later).
        if session._advertise.send_sack and overlap_prefix > 0:
            session._pending_dsack = (
                packet_rx_md.tcp__seq,
                add32(packet_rx_md.tcp__seq, overlap_prefix),
            )
        # Modular 'max' on RCV.NXT: advance iff the segment's end
        # is ahead of our current RCV.NXT in modular order.
        if lt32(session._rcv_seq.nxt, seg_end):
            session._rcv_seq.nxt = seg_end
        # In case packet contains data enqueue it. RFC 1122 §4.2.3.2 governs
        # how we acknowledge it: count pending unacked segments since the
        # last ACK, force an inline ACK once two segments are pending
        # ("every other segment"), and otherwise arm the delayed-ACK
        # timer so the ACK fires within tcp__constants.TCP__DELAYED_ACK__DELAY_MS rather than
        # immediately. Arming the timer here (rather than only inside
        # '_transmit_packet') ensures the FIRST inbound data segment
        # after the handshake is properly delayed - without this, the
        # delayed-ACK timer would not yet be armed in '_timer_deadlines'
        # (the third-leg ACK was emitted from within SYN_SENT, which
        # does not arm the timer), so the held ACK would not be
        # deferred and an immediate ACK would slip out.
        if packet_rx_md.tcp__data and overlap_prefix < len(packet_rx_md.tcp__data):
            new_data = packet_rx_md.tcp__data[overlap_prefix:]
            session._enqueue_rx_buffer(new_data)
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - Enqueued {len(new_data)} bytes starting at "
                f"{add32(packet_rx_md.tcp__seq, overlap_prefix)} "
                f"(sliced {overlap_prefix} overlap byte(s))",
            )
            session._delayed_ack_segments_pending += 1
            if session._delayed_ack_segments_pending >= 2:
                # RFC 1122 §4.2.3.2: ACK every other segment in a stream
                # of full-sized segments. '_transmit_packet' will reset
                # the counter via the 'flag_ack' branch below.
                session._transmit_packet(flag_ack=True)
                __debug__ and log(
                    "tcp-ss",
                    f"[{session}] - Sent inline ACK (every-other-segment, {session._rcv_seq.nxt})",
                )
            else:
                # First pending segment: ensure the delayed-ACK timer is
                # armed so the timer-driven '_delayed_ack' will fire the
                # ACK after tcp__constants.TCP__DELAYED_ACK__DELAY_MS rather than immediately.
                session._arm_timer("delayed_ack", tcp__constants.TCP__DELAYED_ACK__DELAY_MS)
        # Purge acked data from TX buffer.
        with session._lock__tx_buffer:
            session._tx.drain(bytes_count=session._tx_buffer_una)
        __debug__ and log(
            "tcp-ss",
            f"[{session}] - Purged TX buffer up to SEQ {session._snd_seq.una}",
        )
        # Update remote window size.
        if session._win.snd_wnd != packet_rx_md.tcp__win << session._win.snd_wsc:
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - Updated sending window size {session._win.snd_wnd} -> "
                f"{packet_rx_md.tcp__win << session._win.snd_wsc}",
            )
            session._win.snd_wnd = packet_rx_md.tcp__win << session._win.snd_wsc
            # RFC 9293 §3.8.4: '_snd_ewn = min(cwnd, snd_wnd)'.
            # Recompute when peer's advertised window changes so
            # the wire-level transmit gate sees a coherent
            # min(cwnd, snd_wnd) regardless of which side just
            # moved.
            session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)
        # RFC 5961 §5 'MAX.SND.WND': running maximum of peer's
        # advertised window. Used as the lower-bound tolerance
        # for ACK acceptability ('SND.UNA - MAX.SND.WND <=
        # SEG.ACK <= SND.NXT').
        session._win.bump_max_window(snd_wnd=session._win.snd_wnd)
        # If peer has reopened their receive window, deactivate the
        # persist timer and reset the back-off interval so the next
        # zero-window event starts fresh at the initial RTO
        # (RFC 9293 §3.8.6.1).
        if session._win.snd_wnd > 0 and session._persist.active:
            __debug__ and log("tcp-ss", f"[{session}] - Persist: peer reopened window, deactivating timer")
            session._persist.deactivate(initial_timeout=tcp__constants.TCP__RTO__INITIAL_MS)
        __debug__ and log(
            "tcp-ss",
            f"[{session}] - cwnd={session._cc.cwnd} ssthresh={session._cc.ssthresh} snd_ewn={session._cc.snd_ewn}",
        )
        # Purge expired tx packet retransmit requests. Modular '<'
        # via 'lt32' so entries near the 32-bit wrap are dropped
        # correctly when SND.UNA advances past them.
        for seq in list(session._tx.retransmit_request_counter):
            if lt32(seq, packet_rx_md.tcp__ack):
                session._tx.retransmit_request_counter.pop(seq)
                __debug__ and log(
                    "tcp-ss",
                    f"[{session}] - Purged expired TX packet retransmit request counter for {seq}",
                )
        # Bring next packet from ooo_packet_queue if available.
        if ooo_packet := session._ooo_packet_queue.pop(session._rcv_seq.nxt, None):
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - <lg>Retrieving packet {session._rcv_seq.nxt} from Out of Order queue</>",
            )
            session.tcp_fsm(ooo_packet)
