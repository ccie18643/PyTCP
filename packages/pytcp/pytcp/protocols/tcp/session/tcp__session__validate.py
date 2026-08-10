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
This module contains the per-session TCP segment validator —
'TcpSegmentValidator' — which owns the read-mostly segment
acceptability + PAWS + RST-acceptability + ICMP-embedded-seq
acceptability checks and the RFC 6191 §3 4-tuple-reuse
re-initialisation helper. Phase 4 of the TcpSession god-class
decomposition.

Pure structural extraction — no behaviour change, no new lock.
The validator holds a back-reference to the session and
reads/writes every shared state dataclass via
'self._session.<state>', matching the idiom 'fsm/' and the
Phase-1/2/3 collaborators already use. The session keeps thin
delegators for every method moved here so 'fsm/' handlers
and ICMP RX handlers continue to call
'session.is_seq_in_window' /
'session._check_segment_acceptability' /
'session._check_paws_and_update_ts_recent' /
'session._check_rst_acceptability' /
'session._reinit_for_rfc6191_reuse' unchanged.

packages/pytcp/pytcp/protocols/tcp/session/tcp__session__validate.py

ver 3.0.10
"""

import time
from typing import TYPE_CHECKING

from net_proto.protocols.tcp.tcp__header import TCP__MIN_MSS
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.tcp import tcp__constants
from pytcp.protocols.tcp.tcp__iss import compute_iss
from pytcp.protocols.tcp.tcp__rto import initial_state
from pytcp.protocols.tcp.tcp__sack import SackScoreboard
from pytcp.protocols.tcp.tcp__seq import add32, gt32, in_range32, le32, lt32
from pytcp.runtime.socket.tcp__metadata import TcpMetadata

if TYPE_CHECKING:
    from pytcp.protocols.tcp.session import TcpSession


class TcpSegmentValidator:
    """
    Per-session TCP segment validator — owns the read-mostly
    inbound-segment acceptability checks + the RFC 6191 reuse
    re-initialisation helper.
    """

    def __init__(self, session: "TcpSession", /) -> None:
        """
        Initialize the segment validator with a back-reference
        to the owning session.
        """

        self._session: TcpSession = session

    # ------------------------------------------------------------------
    # Public surface — called via session delegators from fsm/ handlers
    # (synchronized-state acceptability + PAWS + RST acceptability +
    # RFC 6191 reuse) and from the ICMP RX handlers (is_seq_in_window).
    # ------------------------------------------------------------------

    def is_seq_in_window(self, seq: int) -> bool:
        """
        Return True when 'seq' falls in the SND.UNA..SND.NXT range —
        the RFC 5927 §4 acceptability check for an ICMP error
        targeting an embedded TCP segment. ICMP RX handlers call this
        before notifying the session so an off-path attacker cannot
        forge an error for an arbitrary 4-tuple.

        For unsynchronized states (no SND.NXT yet) the check accepts
        anything since no flight is outstanding to validate against.

        Reference: RFC 5927 §4 (ICMP attacks against TCP).
        """

        session = self._session
        if session._snd_seq.nxt == 0 and session._snd_seq.una == 0:
            return True

        # Modular comparison via Seq32 wrap-aware arithmetic.
        if session._snd_seq.una <= session._snd_seq.nxt:
            return session._snd_seq.una <= seq <= session._snd_seq.nxt
        return seq >= session._snd_seq.una or seq <= session._snd_seq.nxt

    def check_segment_acceptability(self, packet_rx_md: TcpMetadata) -> bool:
        """
        Apply the RFC 9293 §3.10.7.4 step 1 receive-window
        acceptability check to an inbound segment. Return True
        when the segment is acceptable (caller should continue
        processing); return False when the segment is
        unacceptable (caller MUST drop and return - this method
        has already emitted the mandated ACK reply).

        Acceptability table (RFC 9293 §3.10.7.4):

            SEG.LEN == 0:
              RCV.WND > 0  -> RCV.NXT <= SEG.SEQ <= RCV.NXT+RCV.WND
              RCV.WND == 0 -> SEG.SEQ == RCV.NXT
            SEG.LEN > 0:
              RCV.WND > 0  -> SEG.SEQ < RCV.NXT+RCV.WND AND
                              SEG.SEQ + SEG.LEN > RCV.NXT
              RCV.WND == 0 -> not acceptable

        SEG.LEN here counts data plus the SYN / FIN flag bytes
        that also consume sequence space. All comparisons are
        modular per RFC 9293 §3.4.

        On unacceptable segments the spec mandates an ACK reply
        carrying our current SND.NXT / RCV.NXT, EXCEPT when the
        segment carries RST (RFC 9293 §3.10.7.4 step 1 explicit
        RST clause: 'unless the RST bit is set, if so drop the
        segment and return' - replying with an ACK to a blind
        RST would amplify a possible attack).

        RFC 2883 DSACK case 1: when bilateral SACK is enabled
        and the unacceptable segment is a fully-duplicate data
        retransmit (entirely below RCV.NXT), stash the
        duplicated range as a pending DSACK so the next
        outbound ACK reports it as the FIRST SACK block.
        """

        session = self._session
        seg_len = len(packet_rx_md.tcp__data) + packet_rx_md.tcp__flag_syn + packet_rx_md.tcp__flag_fin
        seg_end = add32(packet_rx_md.tcp__seq, seg_len)
        if seg_len == 0:
            if session._rcv_wnd > 0:
                acceptable = in_range32(
                    packet_rx_md.tcp__seq, session._rcv_seq.nxt, add32(session._rcv_seq.nxt, session._rcv_wnd)
                )
            else:
                acceptable = packet_rx_md.tcp__seq == session._rcv_seq.nxt
        else:
            if session._rcv_wnd > 0:
                acceptable = lt32(packet_rx_md.tcp__seq, add32(session._rcv_seq.nxt, session._rcv_wnd)) and gt32(
                    seg_end, session._rcv_seq.nxt
                )
            else:
                acceptable = False

        if acceptable:
            return True

        __debug__ and log(
            "tcp-ss",
            f"[{session}] - Packet seq {packet_rx_md.tcp__seq} + "
            f"{seg_len} doesn't fit into receive window, dropping",
        )
        # RFC 9293 §3.10.7.4 step 1 RST exception: an
        # unacceptable RST is dropped silently to avoid an
        # ACK-amplification path against blind off-path
        # attackers.
        if packet_rx_md.tcp__flag_rst:
            return False
        # RFC 2883 DSACK case 1: stash the duplicate range so
        # the ACK below reports it as the FIRST SACK block.
        if (
            session._advertise.send_sack
            and len(packet_rx_md.tcp__data) > 0
            and lt32(packet_rx_md.tcp__seq, session._rcv_seq.nxt)
            and le32(seg_end, session._rcv_seq.nxt)
        ):
            session._pending_dsack = (packet_rx_md.tcp__seq, seg_end)
        # RFC 9293 §3.10.7.4 step 1: ACK the unacceptable
        # segment so peer's retransmit machinery sees fresh
        # activity and can stop retransmitting. Rate-limited
        # per RFC 5961 §3 so a burst of unacceptable segments
        # cannot amplify into an outbound ACK flood.
        session._emit_challenge_ack()
        return False

    def check_paws_and_update_ts_recent(self, packet_rx_md: TcpMetadata) -> bool:
        """
        RFC 7323 §5 PAWS + §4.3 '_ts_recent' refresh as a
        single helper invoked at every inbound dispatch
        boundary. Returns True when the segment passes PAWS
        (caller may continue normal processing) and False
        when the segment must be silently dropped per §5.4.

        Side effect: on a non-stale segment carrying TSopt,
        '_ts_recent' is refreshed to the segment's TSval.

        Bilateral-success-gated: returns True (and skips both
        the PAWS check and the '_ts_recent' update) when
        '_send_ts' is False or the inbound segment carries no
        TSopt. Legacy non-TSopt peers fall through unchanged.

        Modular comparison via 'lt32' so the check is correct
        across the 32-bit TSval clock wrap (24 days at 1 ms
        granularity).
        """

        session = self._session
        if not session._ts.send_ts:
            return True
        # RFC 7323 §3.2: "If a non-<RST> segment is received
        # without a TSopt, a TCP SHOULD silently drop the
        # segment." The SHOULD applies to in-stream segments;
        # SYN-bearing segments are exempt because they may
        # legitimately re-initiate (RFC 6191 §3 4-tuple reuse,
        # RFC 9293 §3.10.7.4 SYN-in-synchronized challenge-ACK
        # path) and the per-segment TSopt expectation has not
        # yet been re-established for the new incarnation.
        if packet_rx_md.tcp__tsval is None:
            if packet_rx_md.tcp__flag_syn:
                return True
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - PAWS: silently dropping segment "
                "missing TSopt on TS-negotiated session "
                "(RFC 7323 §3.2 SHOULD)",
            )
            return False
        # RFC 7323 §4.3 rule (2) Last.ACK.sent gate: TS.Recent
        # is only refreshed when SEG.SEQ <= Last.ACK.sent so an
        # OOO segment cannot inflate TS.Recent and corrupt the
        # TSecr echoed back to the peer's RTT estimator. Last.
        # ACK.sent equals RCV.NXT at the moment of our last
        # outbound ACK and is monotone non-decreasing; using
        # the current RCV.NXT as the upper bound is a tightening
        # safe approximation (it can only suppress refreshes
        # that the strict algorithm would also suppress, never
        # the reverse). SYN-bearing segments are exempt: they
        # establish (or, on RFC 6191 §3 reuse, re-establish)
        # the connection's TS.Recent and the §4.3 algorithm
        # assumes a stable seq-space relationship that has not
        # yet been negotiated for the new incarnation.
        ts_recent_refresh_gate_ok = packet_rx_md.tcp__flag_syn or le32(packet_rx_md.tcp__seq, session._rcv_seq.nxt)
        if lt32(packet_rx_md.tcp__tsval, session._ts.ts_recent):
            # RFC 7323 §5.5 outdated-timestamps mitigation:
            # if the connection has been idle longer than the
            # 24-day threshold, 'TS.Recent' MUST be treated as
            # invalidated and the segment accepted (rule R3
            # then refreshes TS.Recent with the segment's
            # TSval). Without this gate, a recovered idle
            # connection past the 24-day mark would freeze
            # because every subsequent segment's TSval would
            # appear stale until the peer's TS clock wrapped
            # its sign bit. The check requires a non-zero
            # last-update timestamp so freshly-handshaked
            # sessions (initialised to 0) cannot trigger
            # the mitigation spuriously.
            if (
                session._ts.ts_recent_updated_at_ms != 0
                and stack.timer.now_ms - session._ts.ts_recent_updated_at_ms
                > tcp__constants.TCP__TS_RECENT__OUTDATED_THRESHOLD_MS
            ):
                __debug__ and log(
                    "tcp-ss",
                    f"[{session}] - PAWS: TS.Recent outdated past "
                    f"{tcp__constants.TCP__TS_RECENT__OUTDATED_THRESHOLD_MS} ms idle threshold, "
                    "accepting segment per RFC 7323 §5.5 mitigation "
                    f"(tsval={packet_rx_md.tcp__tsval}, "
                    f"_ts_recent={session._ts.ts_recent})",
                )
                session._ts.update(tsval=packet_rx_md.tcp__tsval, now_ms=stack.timer.now_ms)
                return True
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - PAWS: dropping stale-TSval segment "
                f"(tsval={packet_rx_md.tcp__tsval} < _ts_recent="
                f"{session._ts.ts_recent})",
            )
            # RFC 7323 §5.3 R1: "Send an acknowledgment in
            # reply" on the PAWS-stale drop so the peer can
            # recover its sender state without waiting for its
            # own RTO. Reuses the rate-limited challenge-ACK
            # emit which is the canonical "ACK at SND.NXT,
            # RCV.NXT" wire shape.
            session._emit_challenge_ack()
            return False
        if ts_recent_refresh_gate_ok:
            session._ts.update(tsval=packet_rx_md.tcp__tsval, now_ms=stack.timer.now_ms)
        return True

    def check_rst_acceptability(self, packet_rx_md: TcpMetadata) -> bool:
        """
        RFC 9293 §3.10.7.4 / RFC 5961 §3.2 three-way RST handling
        for synchronized states. Returns True when the inbound
        RST is in-window AND its 'seq' exactly matches RCV.NXT
        (case 1: caller MUST reset the connection via state ->
        CLOSED). Returns False otherwise; if the segment was
        in-window but its seq did not match RCV.NXT (case 2),
        this method has already emitted a rate-limited challenge
        ACK so a legitimate peer can retransmit at the right
        seq, while a blind off-path attacker cannot leverage the
        silent drop. Out-of-window RSTs (case 3) fall through to
        silent drop with no reply.

        The 'ack' field is also validated against
        '[SND.UNA, SND.MAX]' for case 1 to preserve the
        defensive guard the per-state RST handlers carried
        previously; an RST whose ack value implausibly points
        at unsent data is treated like a case-3 out-of-window
        drop. RFC 9293 does not strictly require this guard but
        the conservative behaviour is harmless and matches the
        pre-helper code's invariant.
        """

        session = self._session
        seq = packet_rx_md.tcp__seq
        # The 'ack' field is only meaningful when the ACK flag is
        # set (RFC 9293 §3.1). A bare RST carries no ack value;
        # the in-range guard is skipped in that case so the
        # case-1 reset path remains reachable for peer TCPs that
        # send bare RST instead of the more common RST+ACK.
        ack_acceptable = (not packet_rx_md.tcp__flag_ack) or in_range32(
            packet_rx_md.tcp__ack, session._snd_seq.una, session._snd_seq.max
        )
        if seq == session._rcv_seq.nxt and ack_acceptable:
            return True
        if lt32(session._rcv_seq.nxt, seq) and lt32(seq, add32(session._rcv_seq.nxt, session._rcv_wnd)):
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - In-window mismatched RST (seq={seq}, RCV.NXT={session._rcv_seq.nxt}); challenge-ACK",
            )
            session._emit_challenge_ack()
        return False

    def reinit_for_rfc6191_reuse(self, packet_rx_md: TcpMetadata) -> None:
        """
        RFC 6191 §3 TIME-WAIT 4-tuple reuse: re-initialise
        this session's runtime state in place so a fresh
        three-way handshake can proceed against peer's new
        SYN. The 4-tuple is unchanged (RFC 6191 reuse
        applies on the same 4-tuple); the helper resets
        send-side seq state to a fresh ISS, refreshes
        peer-derived parameters (MSS / window / WSCALE /
        SACK / TSopt) from the inbound SYN, clears the
        previous-incarnation buffers and recovery state, and
        cancels every per-session timer the prior incarnation
        may have armed.

        After the helper returns, the caller transitions to
        SYN_RCVD and emits the SYN+ACK. The previously-
        registered 'TIME-WAIT' timer is dropped via the
        prefix-keyed unregister so any other per-session
        timers (delayed-ACK, retransmit, persist, keep-
        alive) are also cleared - they would otherwise fire
        against the stale state of the prior connection.
        """

        session = self._session
        # Cancel every per-session logical timer the prior
        # incarnation may have armed (TIME-WAIT, retransmit,
        # delayed-ACK, persist, keep-alive, challenge-ACK).
        session._cancel_all_timers()

        # Fresh ISS for the new incarnation. The 4-tuple is
        # unchanged but the time-driven 'M' clock advance in
        # 'compute_iss' guarantees a different ISS from the
        # previous incarnation, preserving RFC 6528's blind-
        # injection defence across the reuse boundary.
        new_iss = compute_iss(
            local_address=session._local_ip_address,
            local_port=session._local_port,
            remote_address=session._remote_ip_address,
            remote_port=session._remote_port,
            secret=stack.TCP__ISS_SECRET,
            clock_us=time.monotonic_ns() // 1000,
        )
        session._snd_seq.ini = new_iss
        session._snd_seq.una = new_iss
        session._snd_seq.nxt = new_iss
        session._snd_seq.max = new_iss
        session._snd_seq.sml = new_iss
        session._snd_seq.fin = 0
        session._snd_seq.fin_sent = False
        session._tx.seq_mod = new_iss

        # Adopt peer's new SYN parameters. MSS is clamped to the
        # RFC 879 / RFC 6691 bounds (via '_mss_ceiling()', which
        # honours the PLPMTUD cold-start base_mss ceiling when
        # 'tcp.mtu_probing' is enabled); an explicit floor at
        # TCP__MIN_MSS treats peer-advertised 0 (or any malformed
        # sub-floor value) as 'option absent'.
        session._win.snd_mss = max(
            TCP__MIN_MSS,
            min(packet_rx_md.tcp__mss, session._mss_ceiling()),
        )
        session._win.snd_wnd = packet_rx_md.tcp__win
        session._win.max_window = session._win.snd_wnd

        # Re-run the bilateral negotiation against peer's new SYN -
        # WSCALE / SACK / TSopt may all differ between incarnations.
        if session._advertise.wscale and packet_rx_md.tcp__wscale:
            session._win.snd_wsc = packet_rx_md.tcp__wscale
        else:
            session._win.rcv_wsc = 0
            session._win.snd_wsc = 0
        session._advertise.send_sack = session._advertise.sack and packet_rx_md.tcp__sackperm
        session._ts.send_ts = session._advertise.ts and packet_rx_md.tcp__tsval is not None
        # '_ts_recent' was already refreshed to peer's new TSval
        # by the PAWS helper in the FSM handler before this point.

        # RFC 5681 §3.1 + RFC 6928 §2: reset cwnd to the post-handshake
        # IW and ssthresh to the canonical large-constant default. The
        # actual IW assignment happens at the SYN_RCVD -> ESTABLISHED
        # transition; here we set the SYN-RCVD-phase value
        # (one SMSS) so the outbound SYN+ACK is emitted correctly.
        session._cc.cwnd = session._win.snd_mss
        session._cc.ssthresh = 0x7FFF_FFFF
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        # Receive-side state from the new SYN.
        session._rcv_seq.ini = packet_rx_md.tcp__seq
        session._rcv_seq.nxt = add32(
            packet_rx_md.tcp__seq,
            packet_rx_md.tcp__flag_syn,
            len(packet_rx_md.tcp__data),
        )
        session._rcv_seq.una = session._rcv_seq.nxt
        session._peer_contacted = True

        # Reset RFC 6298 RTO estimator + sample tracker so the new
        # incarnation re-establishes its own RTT measurements.
        session._rto_state = initial_state()
        session._retransmit_count = 0
        session._rtt.last_send_time_ms = None
        session._rtt.clear()

        # Clear SACK + DSACK + recovery state from the prior incarnation.
        session._sack_scoreboard = SackScoreboard()
        session._cc.recovery_point = 0
        session._cc.recover_fs = 0
        session._cc.prr_delivered = 0
        session._cc.prr_out = 0
        session._pending_dsack = None
        session._dsack_received = 0

        # Clear OOO queue + buffers (TIME-WAIT should already have
        # them empty, but be defensive against state that an earlier
        # bug or a spurious-FIN-retransmit path may have left).
        session._ooo_packet_queue.clear()
        session._tx.buffer.clear()
        session._rx_buffer.clear()

        # Queue any data the new SYN piggybacked (RFC 9293 §3.10.7.2
        # step 3 permits this; rare but legal).
        if packet_rx_md.tcp__data:
            session._enqueue_rx_buffer(packet_rx_md.tcp__data)
