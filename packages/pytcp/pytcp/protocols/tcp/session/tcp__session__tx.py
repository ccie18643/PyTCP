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
This module contains the per-session TCP TX engine —
'TcpTxEngine' — which owns the outbound-segment construction
pipeline: '_transmit_packet' + the six '_phase0..5' helpers,
'transmit_data' (the buffered-data dribbler that paces the
send pump), 'delayed_ack' (the §4.2.3.2 ACK-coalescing
emit), 'build_sack_blocks' (the RFC 2018 / 2883 SACK / DSACK
option builder), and 'emit_challenge_ack' (the RFC 5961
rate-limited challenge-ACK emit). Phase 2 of the TcpSession
god-class decomposition.

Pure structural extraction — no behaviour change, no new
lock. The engine holds a back-reference to the session and
reads/writes every shared state dataclass via
'self._session.<state>', matching the idiom 'fsm/' already
uses. The session keeps thin delegators so 'fsm/' handlers
and other callers continue to call 'session._transmit_packet'
unchanged.

packages/pytcp/pytcp/protocols/tcp/session/tcp__session__tx.py

ver 3.0.9
"""

import time
from typing import TYPE_CHECKING

from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.tcp import tcp__constants
from pytcp.protocols.tcp.tcp__cwnd import initial_window
from pytcp.protocols.tcp.tcp__enums import FsmState
from pytcp.protocols.tcp.tcp__rack import tlp_calc_pto
from pytcp.protocols.tcp.tcp__rto import initial_state
from pytcp.protocols.tcp.tcp__seq import add32, gt32, in_range32, lt32

if TYPE_CHECKING:
    from pytcp.protocols.tcp.session import TcpSession


class TcpTxEngine:
    """
    Per-session TCP TX engine — owns the outbound-segment
    construction pipeline and the buffered-data send pump.
    """

    def __init__(self, session: "TcpSession", /) -> None:
        """
        Initialize the TX engine with a back-reference to the
        owning session.
        """

        self._session: TcpSession = session

    # ------------------------------------------------------------------
    # Public surface — called via thin TcpSession delegators.
    # ------------------------------------------------------------------

    def transmit_packet(
        self,
        *,
        seq: int | None = None,
        flag_syn: bool = False,
        flag_ack: bool = False,
        flag_fin: bool = False,
        flag_rst: bool = False,
        flag_psh: bool = False,
        data: bytes = b"",
    ) -> None:
        """
        Send out the TCP packet.
        """

        session = self._session
        seq = seq if seq is not None else session._snd_seq.nxt
        ack = session._rcv_seq.nxt if flag_ack else 0

        self._phase0_pre_send_hygiene(seq=seq, flag_syn=flag_syn, flag_fin=flag_fin, data=data)

        # WSCALE shift on outbound 'win' field per RFC 7323 §2.3:
        # post-handshake segments use 'rcv_wnd >> rcv_wsc'; the
        # SYN segment itself uses an unshifted value (RFC 7323
        # §2.2's "WSopt is not used to scale the value in the
        # window field of the SYN segment itself"). The SYN+ACK
        # is also a "SYN segment" for this rule.
        if flag_syn:
            tcp__win = min(session._rcv_wnd, 0xFFFF)
        elif 0 < session._rcv_wnd < session._win.rcv_mss:
            # RFC 1122 §4.2.3.3 receiver SWS avoidance: when the
            # available receive-window is non-zero but smaller
            # than one MSS, advertise zero so peer's persist-
            # probe loop fires rather than peer sending a sub-
            # MSS segment that wastes per-byte header overhead.
            # The next window update fires once the application
            # has consumed at least one MSS of buffer space and
            # '_rcv_wnd >= _rcv_mss' again.
            tcp__win = 0
        else:
            tcp__win = session._rcv_wnd >> session._win.rcv_wsc

        # WSCALE option presence on outbound SYN / SYN+ACK is
        # gated on '_advertise_wscale' per RFC 7323 §2.2's
        # bilateral non-offer rule. The packet-handler TX path
        # treats 'tcp__wscale=0' as "no option" (falsy guard),
        # which is the bilateral-non-offer wire form.
        tcp__wscale: int | None
        if flag_syn and session._advertise.wscale:
            tcp__wscale = session._win.rcv_wsc
        elif flag_syn:
            tcp__wscale = 0
        else:
            tcp__wscale = None

        # SACK-Permitted option presence per RFC 2018 §2:
        # active-open SYN emits iff we advertise (peer's view is
        # not yet known); passive-open SYN+ACK emits iff the
        # bilateral negotiation succeeded ('_send_sack' is set
        # in '_tcp_fsm_listen' on peer's SYN). Non-SYN segments
        # never carry the option (RFC 2018 §2: "MUST NOT be sent
        # on non-SYN segments").
        if flag_syn and not flag_ack:
            tcp__sackperm = session._advertise.sack
        elif flag_syn and flag_ack:
            tcp__sackperm = session._advertise.send_sack
        else:
            tcp__sackperm = False

        # SACK option blocks per RFC 2018 §3-§4 / RFC 2883 §4:
        # emitted on non-SYN ACKs iff the bilateral negotiation
        # succeeded AND we have at least one block to report -
        # either an OOO-queue entry OR a pending DSACK report.
        # An empty SACK option is illegal per RFC 2018 §3
        # (length must cover at least one 8-byte block).
        tcp__sack_blocks: list[tuple[int, int]] | None
        if (
            not flag_syn
            and session._advertise.send_sack
            and (session._ooo_packet_queue or session._pending_dsack is not None)
        ):
            tcp__sack_blocks = self.build_sack_blocks()
        else:
            tcp__sack_blocks = None

        # RFC 7323 §3 Timestamps option:
        #   - Active-open SYN (flag_syn AND not flag_ack): emit
        #     iff '_advertise_ts'. tsval=now_ms, tsecr=0 (peer's
        #     TSval not yet known).
        #   - Passive-open SYN+ACK (flag_syn AND flag_ack): emit
        #     iff bilateral '_send_ts' set. tsval=now_ms,
        #     tsecr=_ts_recent (peer's TSval from its SYN).
        #   - Non-SYN segments: emit iff '_send_ts'. tsval=now_ms,
        #     tsecr=_ts_recent. (Phase 2 wires this; Phase 1 only
        #     handles handshake.)
        # RFC 7323 §5.4: TSval / TSecr are 4-byte unsigned integers
        # that wrap at 2**32. PyTCP's 'stack.timer.now_ms' is a
        # monotonic ms counter that exceeds UINT32_MAX after ~49.7
        # days of stack uptime; mask to 32 bits so the wire field
        # carries the wrapped value rather than overflowing the
        # TcpOptionTimestamps assertion.
        ts_clock = stack.timer.now_ms & 0xFFFF_FFFF
        tcp__tsval: int | None
        tcp__tsecr: int | None
        if flag_syn and not flag_ack:
            if session._advertise.ts:
                tcp__tsval = ts_clock
                tcp__tsecr = 0
            else:
                tcp__tsval = None
                tcp__tsecr = None
        elif flag_syn and flag_ack:
            if session._ts.send_ts:
                tcp__tsval = ts_clock
                tcp__tsecr = session._ts.ts_recent
            else:
                tcp__tsval = None
                tcp__tsecr = None
        else:
            if session._ts.send_ts:
                tcp__tsval = ts_clock
                tcp__tsecr = session._ts.ts_recent
            else:
                tcp__tsval = None
                tcp__tsecr = None

        flag_ece, flag_cwr, flag_ns = self._phase1_compose_ecn_flags(
            flag_syn=flag_syn,
            flag_ack=flag_ack,
            flag_rst=flag_rst,
            data=data,
        )

        tcp__fastopen_cookie = self._phase3_build_fastopen_cookie(flag_syn=flag_syn, flag_ack=flag_ack)

        tcp__accecn0_counters, tcp__accecn1_counters = self._phase2_build_accecn_counters(
            flag_syn=flag_syn,
            flag_ack=flag_ack,
            flag_rst=flag_rst,
        )

        # RFC 3168 §6.1.5: when bilateral ECN has been
        # negotiated, every outbound data segment MUST set
        # the IP ECN field to ECT(0) ('10' = 2) so routers
        # along the path can mark it on congestion via the
        # CE codepoint. §6.1.1 forbids ECT on SYNs and §6.1.6
        # advises against ECT on pure ACKs / FIN-only / RST,
        # so the marking is gated on the segment carrying a
        # TCP payload. §6.1.5 also mandates "ECN-capable TCP
        # implementations MUST NOT set either ECT codepoint
        # (ECT(0) or ECT(1)) in the IP header for
        # retransmitted data packets": a segment whose seq
        # is strictly below the current SND.MAX (the high-
        # water mark of seqs we've ever sent) is, by
        # definition, a retransmit since SND.NXT was rewound
        # to SND.UNA on the RTO/FR path. The 'lt32' modular
        # comparison handles the 32-bit seq wrap correctly.
        is_retransmit = bool(data) and lt32(seq, session._snd_seq.max)
        ip__ecn = 2 if (session._ecn.enabled and data and not is_retransmit) else 0
        stack.egress_packet_handler(session._remote_ip_address).send_tcp_packet(
            ip__local_address=session._local_ip_address,
            ip__remote_address=session._remote_ip_address,
            # Linux IP_TTL / IPV6_UNICAST_HOPS per-socket override
            # (H6 of socket_linux_parity_audit.md). 'None' lets the
            # IP TX handler apply the stack default; a positive int
            # threads through to the outbound IP header's TTL /
            # Hop-Limit field.
            ip__ttl=session._socket._effective_ip_ttl(session._remote_ip_address),
            ip__ecn=ip__ecn,
            # Linux IP_TOS / IPV6_TCLASS DSCP marking (M4 of
            # socket_linux_parity_audit.md): the high 6 bits of the
            # socket's TOS / Traffic-Class byte mark every outbound
            # segment. ECN (low 2 bits) stays RFC-3168 stack-driven
            # above; DSCP is orthogonal and applies to TCP too.
            ip__dscp=session._socket._effective_ip_dscp(),
            tcp__local_port=session._local_port,
            tcp__remote_port=session._remote_port,
            tcp__flag_syn=flag_syn,
            tcp__flag_ack=flag_ack,
            tcp__flag_fin=flag_fin,
            tcp__flag_rst=flag_rst,
            tcp__flag_psh=flag_psh,
            tcp__flag_ece=flag_ece,
            tcp__flag_cwr=flag_cwr,
            tcp__flag_ns=flag_ns,
            tcp__seq=seq,
            tcp__ack=ack,
            tcp__win=tcp__win,
            # RFC 9293 §3.7.5 / RFC 2675 §5: the MSS option wire
            # field is 16-bit, so '_rcv_mss > 65535' (e.g. on a
            # mis-configured super-jumbo MTU) would otherwise
            # overflow the assembler's uint16 assert. Cap at 65535
            # which RFC 2675 reserves as the "use path-MTU-derived
            # MSS" signal for jumbogram-capable IPv6 paths. The
            # Linux 'TCP_MAXSEG' per-connection override
            # (propagated as 'session._maxseg_override',
            # 0 = no clamp) takes precedence — clamp to the
            # user-supplied ceiling so the peer learns no
            # advertised MSS larger than the application
            # wants. M7 of 'socket_linux_parity_audit.md'.
            tcp__mss=(
                min(
                    session._win.rcv_mss,
                    0xFFFF,
                    session._maxseg_override if session._maxseg_override > 0 else 0xFFFF,
                )
                if flag_syn
                else None
            ),
            tcp__wscale=tcp__wscale,
            tcp__sackperm=tcp__sackperm,
            tcp__sack_blocks=tcp__sack_blocks,
            tcp__tsval=tcp__tsval,
            tcp__tsecr=tcp__tsecr,
            tcp__fastopen_cookie=tcp__fastopen_cookie,
            tcp__accecn0_counters=tcp__accecn0_counters,
            tcp__accecn1_counters=tcp__accecn1_counters,
            tcp__payload=data,
        )
        self._phase4_advance_send_state(
            seq=seq,
            flag_syn=flag_syn,
            flag_ack=flag_ack,
            flag_fin=flag_fin,
            data=data,
        )
        self._phase5_post_send_timers(flag_syn=flag_syn, flag_fin=flag_fin, data=data)

        __debug__ and log(
            "tcp-ss",
            f"[{session}] - Sent packet_rx_md: {'S' if flag_syn else ''}"
            f"{'F' if flag_fin else ''}{'R' if flag_rst else ''}"
            f"{'A' if flag_ack else ''}, seq {seq}, ack {ack}, "
            f"dlen {len(data)}",
        )

    def transmit_data(self) -> None:
        """
        Send out data segment from TX buffer using TCP
        sliding window mechanism.
        """

        session = self._session
        # RFC 9293 §3.8.6 / RFC 1122 §4.2.2.16: a sender MUST be
        # robust against peer window shrinking. When the peer ACKs
        # less data than is in flight while simultaneously
        # advertising a smaller window, the right edge
        # (SND.UNA + SND.EWN) can fall below SND.NXT and the
        # invariant 'SND.UNA <= SND.NXT <= SND.UNA + SND.EWN' is
        # legitimately violated. The RFC requires the sender to
        # absorb the shrink: refuse to push more data, wait for the
        # peer to reopen the window or for RTO to fire, and let
        # the normal retransmit machinery cover the unacknowledged
        # bytes within SND.UNA..SND.UNA+SND.WND.
        # Modular window-edge check (RFC 9293 §3.4): SND.NXT must
        # fall within the closed interval [SND.UNA, SND.UNA+SND.EWN]
        # in modular 32-bit space. Plain '<=' chained comparison
        # would wrongly reject a SND.NXT that has wrapped past
        # SND.UNA but is still in-window.
        right_edge = add32(session._snd_seq.una, session._cc.snd_ewn)
        if not in_range32(session._snd_seq.nxt, session._snd_seq.una, right_edge):
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - Peer-shrunk usable window: SND.NXT={session._snd_seq.nxt} "
                f"is outside [{session._snd_seq.una}, {right_edge}]; "
                "deferring further transmission until peer reopens or RTO fires",
            )
            return

        # Check if we need to (re)transmit initial SYN packet.
        if session._state is FsmState.SYN_SENT and session._snd_seq.nxt == session._snd_seq.ini:
            # RFC 7413 §3.1 SYN-with-data: when the active-open
            # SYN is the first transmit AND we have a cached
            # cookie for the peer AND the application has
            # pre-loaded data into '_tx_buffer', slice up to
            # one SMSS of pending bytes onto the SYN itself.
            # Server-side cookie validation (Phase 3) gates
            # whether the bytes are accepted; on rejection
            # the data is replayed via normal retransmit after
            # the third-leg ACK. The slice is gated on cached-
            # cookie presence so a cookie-request SYN (no
            # cached cookie) never carries data - the empty-
            # cookie request form is invalid for data
            # acceptance per §4.1.2.
            tfo_data: bytes = b""
            cached = stack.tcp_stack.fastopen_cookie(session._remote_ip_address)
            if cached and session._advertise.fastopen and session._tx.buffer:
                with session._lock__tx_buffer:
                    slice_len = min(session._win.snd_mss, len(session._tx.buffer))
                    tfo_data = bytes(session._tx.buffer[:slice_len])
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - Transmitting initial SYN packet_rx_md: seq {session._snd_seq.nxt}"
                + (f", carrying {len(tfo_data)} bytes of TFO SYN-data" if tfo_data else ""),
            )
            self.transmit_packet(flag_syn=True, data=tfo_data)
            return

        # Check if we need to (re)transmit initial SYN + ACK packet.
        if session._state is FsmState.SYN_RCVD and session._snd_seq.nxt == session._snd_seq.ini:
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - Transmitting initial SYN + ACK packet_rx_md: seq {session._snd_seq.nxt}",
            )
            self.transmit_packet(flag_syn=True, flag_ack=True)
            return

        # Make sure we in the state that allows sending data out.
        if session._state in {FsmState.ESTABLISHED, FsmState.CLOSE_WAIT}:
            # During fast-retransmit recovery, advance SND.NXT past
            # any peer-SACKed range so the next transmit does not
            # re-send bytes peer already received. RFC 6675 §5
            # multi-gap recovery semantics: with the scoreboard
            # tracking SACKed regions, the sender can skip them
            # entirely and only retransmit genuine gaps. Outside
            # recovery this is a no-op (the high-water-mark
            # invariant 'SND.NXT == SND.MAX' holds, and
            # 'is_sacked(SND.MAX)' is always False since peer
            # cannot SACK bytes we never sent).
            session._advance_snd_nxt_past_sacked()
            remaining_data_len = len(session._tx.buffer) - session._tx_buffer_nxt
            usable_window = session._cc.snd_ewn - session._tx_buffer_nxt
            # RFC 6691 §2 Req B: "the sender MUST reduce the
            # TCP data length to account for any IP or TCP
            # options that it is including in the packets that
            # it sends." TSopt = 12 bytes (10 + 2 NOP padding)
            # on every post-handshake segment when bilaterally
            # negotiated. SACK option = 2 (header) + 8*N (block
            # count) bytes, padded to a 4-byte boundary; the
            # block count is bounded by the §3 4-block cap (or
            # 3 with TSopt). AccECN option = 2 + N bytes
            # depending on the abbreviation length. Estimate
            # the upper-bound option overhead conservatively
            # so the data-segment + option-block + fixed
            # headers stay within MTU.
            options_overhead = 0
            if session._ts.send_ts:
                options_overhead += 12  # TSopt 10 bytes + 2 NOPs
            if session._advertise.send_sack and (session._ooo_packet_queue or session._pending_dsack is not None):
                # Worst-case SACK option size when we'd emit
                # blocks on a non-SYN segment. With TSopt the
                # cap is 3 blocks (= 2 + 24 = 26, padded to 28);
                # without TSopt it's 4 blocks (= 2 + 32 = 34,
                # padded to 36).
                sack_blocks_cap = 3 if session._ts.send_ts else 4
                options_overhead += ((2 + 8 * sack_blocks_cap + 3) // 4) * 4
            if session._accecn.enabled:
                # AccECN Length 11 (the largest variant)
                # plus 1 NOP for alignment = 12 bytes worst
                # case.
                options_overhead += 12
            mss_for_data = max(session._win.snd_mss - options_overhead, 1)
            transmit_data_len = min(mss_for_data, usable_window, remaining_data_len)

            # RFC 4821 §5 / §7.5 PLPMTUD probe-segment emit
            # (Phase 3c). When the engine has a candidate probe
            # size and there is enough application data to fill
            # 'probe_payload' bytes, override the segment size
            # so this segment goes out as a probe instead of a
            # regular MSS-sized data segment. Probes are
            # standard TCP data segments — the peer ACKs them
            # like any other data. The IP packet ends up at
            # 'candidate_mtu' bytes; if the path supports it
            # the probe is acked and PLPMTUD advances
            # search_low; otherwise the probe is lost and the
            # engine narrows search_high.
            #
            # Phase 3d will add cwnd-exempt accounting (RFC
            # 4821 §7.4) so probes don't consume the
            # congestion window, and probe-only RTO (RFC 4821
            # §7.5) so data-RTO doesn't feed probe-loss. For
            # now probes share the data cwnd / RTO machinery.
            probe_size_to_record: int | None = None
            candidate_mtu = session._plpmtud_adapter.candidate_mtu
            if session._plpmtud_probing_enabled and candidate_mtu is not None:
                probe_payload = candidate_mtu - session._ip_tcp_overhead - options_overhead
                if (
                    probe_payload > session._win.snd_mss
                    and probe_payload <= usable_window
                    and probe_payload <= remaining_data_len
                ):
                    # Feasibility check passed; commit the
                    # probe. 'maybe_probe' returns None when a
                    # previous probe is still in flight
                    # (engine's PROBE_TIMER not yet expired),
                    # so this also serves as the
                    # one-probe-at-a-time gate.
                    reserved = session._plpmtud_adapter.maybe_probe(now=time.monotonic())
                    if reserved is not None:
                        probe_size_to_record = reserved
                        transmit_data_len = probe_payload

            if remaining_data_len:
                __debug__ and log(
                    "tcp-ss",
                    f"[{session}] - Sliding window <y>[{session._snd_seq.una}|"
                    f"{session._snd_seq.nxt}|{add32(session._snd_seq.una, session._cc.snd_ewn)}]</>",
                )
                __debug__ and log(
                    "tcp-ss",
                    f"[{session}] - {usable_window} left in window, "
                    f"{remaining_data_len} left in buffer, "
                    f"{transmit_data_len} to be sent",
                )
                if transmit_data_len > 0:
                    # Nagle's algorithm with the Minshall modification
                    # (RFC 1122 §4.2.3.4). Defer a partial (sub-MSS)
                    # segment when a previous partial segment is still
                    # unacknowledged - this avoids generating tinygrams
                    # for a series of small writes while still allowing
                    # the trailing fragment of a single large write to
                    # fire immediately. We track the post-end seq of
                    # the most recent partial in '_snd_sml'; if it is
                    # still ahead of 'SND.UNA', a previous partial is
                    # in flight and we defer until either it gets ACK'd
                    # or the buffered amount reaches a full MSS.
                    #
                    # Nagle applies to FRESH transmits only - RFC 1122
                    # §4.2.3.4 governs application-driven small-write
                    # generation, not the RTO retransmit machinery
                    # (RFC 6298 §2 retransmits the earliest unacked
                    # segment unconditionally). We detect "we are
                    # retransmitting" via 'SND.NXT < SND.MAX
                    # modularly': '_retransmit_packet_timeout' rewinds
                    # SND.NXT to SND.UNA while leaving SND.MAX at the
                    # high-water mark, so this inequality is True iff
                    # the next segment to send covers ground we have
                    # already transmitted. Without this exemption a
                    # sub-MSS partial that is dropped on the wire
                    # would loop in the Nagle gate forever - the
                    # retransmit counter only increments inside
                    # '_transmit_packet', so deferring here also
                    # disables R2-based connection-abort progression,
                    # silently hanging the connection.
                    is_retransmit = lt32(session._snd_seq.nxt, session._snd_seq.max)
                    is_partial = transmit_data_len < session._win.snd_mss
                    prev_partial_in_flight = gt32(session._snd_seq.sml, session._snd_seq.una)
                    # RFC 1122 §4.2.3.4: TCP_NODELAY disables
                    # Nagle for latency-sensitive applications;
                    # when set, partial segments fire even with
                    # a previous partial still unacked.
                    if is_partial and prev_partial_in_flight and not is_retransmit and not session._tcp_nodelay:
                        __debug__ and log(
                            "tcp-ss",
                            f"[{session}] - Nagle: deferring {transmit_data_len}-byte "
                            f"partial segment - previous partial at seq {session._snd_seq.sml} "
                            f"still unacked (SND.UNA={session._snd_seq.una})",
                        )
                        return
                    with session._lock__tx_buffer:
                        transmit_data = session._tx.buffer[
                            session._tx_buffer_nxt : session._tx_buffer_nxt + transmit_data_len
                        ]
                    # RFC 1122 §4.2.2.2: PSH MUST be set on the last
                    # segment of a write. The current segment drains
                    # the buffer iff 'transmit_data_len ==
                    # remaining_data_len'; that is the marker for "this
                    # is the last segment of the buffered write".
                    is_last_segment_of_write = transmit_data_len == remaining_data_len
                    probe_emit_seq = session._snd_seq.nxt
                    __debug__ and log(
                        "tcp-ss",
                        f"[{session}] - Transmitting data segment: seq {session._snd_seq.nxt} len {len(transmit_data)}",
                    )
                    self.transmit_packet(
                        flag_ack=True,
                        flag_psh=is_last_segment_of_write,
                        data=bytes(transmit_data),
                    )
                    if probe_size_to_record is not None:
                        # Record the just-emitted probe so the
                        # adapter's snd.una hook can detect the
                        # ACK when it arrives. The "end seq" of
                        # the probe is the post-emit snd.nxt
                        # (probe_emit_seq + transmit_data_len);
                        # 'on_snd_una_advance' acks when snd.una
                        # passes the probe's recorded seq.
                        probe_terminal_seq = (probe_emit_seq + transmit_data_len) & 0xFFFFFFFF
                        session._plpmtud_adapter.record_emitted_probe(
                            seq=probe_terminal_seq,
                            size=probe_size_to_record,
                        )
                    # If we just sent a partial, record its post-end
                    # seq so the Minshall check can defer subsequent
                    # partials until this one is ACK'd.
                    if is_partial:
                        session._snd_seq.sml = session._snd_seq.nxt
                else:
                    # Zero-window state: peer has buffered no receive
                    # space but we have data ready to send. Manage the
                    # persist timer per RFC 9293 §3.8.6.1: arm the timer
                    # on first entry into the state, then on each
                    # expiry emit a 1-byte probe at SND.UNA and re-arm
                    # with double the timeout (capped at
                    # tcp__constants.TCP__PERSIST__TIMEOUT_MAX_MS). RFC 1122 §4.2.2.17 makes
                    # probing mandatory because without it the
                    # connection would stall indefinitely whenever the
                    # peer temporarily closed its window.
                    if not session._persist.active:
                        session._persist.active = True
                        session._persist.timeout = tcp__constants.TCP__RTO__INITIAL_MS
                        session._arm_timer("persist", session._persist.timeout)
                        __debug__ and log(
                            "tcp-ss",
                            f"[{session}] - Persist: zero-window, armed timer "
                            f"with timeout {session._persist.timeout} ms",
                        )
                    elif session._timer_expired("persist"):
                        with session._lock__tx_buffer:
                            probe_data = bytes(session._tx.buffer[session._tx_buffer_nxt : session._tx_buffer_nxt + 1])
                        __debug__ and log(
                            "tcp-ss",
                            f"[{session}] - Persist: emitting 1-byte probe at seq {session._snd_seq.nxt}",
                        )
                        self.transmit_packet(flag_ack=True, data=probe_data)
                        # The probe is by definition a partial; track
                        # it for Nagle so subsequent partials defer.
                        session._snd_seq.sml = session._snd_seq.nxt
                        session._persist.timeout = min(
                            session._persist.timeout * 2,
                            tcp__constants.TCP__PERSIST__TIMEOUT_MAX_MS,
                        )
                        session._arm_timer("persist", session._persist.timeout)
                return

        # Check if we need to (re)transmit final FIN packet.
        if session._state in {FsmState.FIN_WAIT_1, FsmState.LAST_ACK} and session._snd_seq.nxt != session._snd_seq.fin:
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - Transmitting final FIN packet_rx_md: seq {session._snd_seq.nxt}",
            )
            self.transmit_packet(flag_fin=True, flag_ack=True)
            return

    def delayed_ack(self) -> None:
        """
        Run Delayed ACK mechanism.
        """

        session = self._session
        # NB: "not armed" (never started OR already fired), NOT
        # "_timer_expired" — the §5.5 audit row for this site was
        # wrong: the unarmed-flush behaviour is load-bearing. A
        # CLOSE_WAIT/ESTABLISHED tick with no delayed-ACK window
        # in progress must flush the held ACK immediately.
        if not session._timer_armed("delayed_ack"):
            if gt32(session._rcv_seq.nxt, session._rcv_seq.una):
                self.transmit_packet(flag_ack=True)
                __debug__ and log(
                    "tcp-ss",
                    f"[{session}] - Sent out delayed ACK ({session._rcv_seq.nxt})",
                )
            session._arm_timer("delayed_ack", tcp__constants.TCP__DELAYED_ACK__DELAY_MS)

    def build_sack_blocks(self) -> list[tuple[int, int]]:
        """
        Compute the SACK option block list for the next outbound
        ACK. Layout per RFC 2018 §4 / RFC 2883 §4: when a DSACK
        report is pending it MUST appear as the FIRST block (the
        signal the sender uses to recognise this as a DSACK-
        bearing option), followed by the OOO-queue ranges in
        insertion order. The returned list is capped at RFC 2018
        §3's maximum of 4 blocks per option. The pending DSACK
        is consumed (cleared) by this call so it appears on
        exactly one outbound ACK.
        """

        session = self._session
        # RFC 2018 §3 block-cap: at most 4 blocks per SACK
        # option (40-byte options window divided by the 8-byte-
        # per-block + 2-byte SACK header). When TSopt is also
        # being emitted (10 bytes consumed), the cap drops to 3
        # blocks because 10 + 2 + 4*8 = 44 > 40 byte options
        # cap. The §3 examples explicitly enumerate the 3-block
        # cap as the TSopt-coexistence form.
        block_cap = 3 if session._ts.send_ts else 4
        blocks: list[tuple[int, int]] = []
        if session._pending_dsack is not None:
            blocks.append(session._pending_dsack)
            session._pending_dsack = None
        # RFC 2018 §4 first-block ordering: the most recent OOO
        # arrival should be the first block (after any DSACK).
        # PyTCP's '_ooo_packet_queue' is an insertion-ordered
        # dict where the newest entry is the LAST item; reverse
        # the iteration so the newest comes first. The remaining
        # blocks follow in newest-first order, satisfying the
        # §4 "first block reflects triggering segment" intent
        # without an extra triggering-segment tracker.
        for seq, packet_rx_md in reversed(session._ooo_packet_queue.items()):
            if len(blocks) >= block_cap:
                break
            blocks.append((seq, add32(seq, len(packet_rx_md.tcp__data))))
        return blocks

    def emit_challenge_ack(self) -> None:
        """
        RFC 5961 §3 / §4 rate-limited challenge-ACK emission.
        Fires 'transmit_packet(flag_ack=True)' at most once per
        sliding 1-second window so a burst of inbound segments
        (unacceptable seq, unacceptable ack, blind SYN-in-
        synchronized-state, etc.) cannot amplify into an outbound
        ACK flood. Subsequent calls within the window are
        suppressed; the caller's intended observable behaviour
        ('an ACK was emitted in response to this segment') is
        sacrificed in favour of the global rate-limit invariant
        which RFC 5961 mandates as a SHOULD-level requirement.

        Implementation: a per-session 'challenge_ack' logical
        timer acts as the sliding-window gate. While it is armed
        and unfired we are inside the rate-limit window and
        suppress; otherwise we emit and (re-)arm it.
        """

        session = self._session
        if session._timer_armed("challenge_ack"):
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - Challenge ACK suppressed by RFC 5961 §3 rate limit",
            )
            return
        self.transmit_packet(flag_ack=True)
        session._arm_timer("challenge_ack", tcp__constants.TCP__CHALLENGE_ACK__RATE_LIMIT_MS)

    # ------------------------------------------------------------------
    # Private engine helpers — phases of 'transmit_packet'.
    # ------------------------------------------------------------------

    def _phase0_pre_send_hygiene(self, *, seq: int, flag_syn: bool, flag_fin: bool, data: bytes) -> None:
        """
        Phase 0 of the outbound-send pipeline. Pre-send hygiene
        applied to every segment that consumes sequence space:

          - RFC 6298 §5.7 restart-after-idle: when the session
            has been silent for longer than the in-flight
            'rto_ms' the smoothed RTT estimator may be stale.
            Reset to 'initial_state()' so the next sample re-
            establishes it from scratch.
          - RFC 5681 §4.1 Restart Window: paired with the §5.7
            idle trigger on data segments — reduce cwnd to
            RW = min(IW, cwnd) so a stale high-cwnd estimate
            does not blast a line-rate burst into a network
            whose live capacity may have decayed.
          - RFC 6298 §4 RTT-sample tracker init: stash (seq,
            now_ms, retransmit-flag) for the eventual covering-
            ACK harvest in phase 3 of the inbound pipeline.
          - RFC 6298 §5.7 idle-baseline refresh: update
            '_last_send_time_ms' so the next call's §5.7 idle
            check has an accurate baseline.

        Reference: RFC 5681 §4.1 (Restart Window cwnd reduction).
        Reference: RFC 6298 §4 (RTT sample collection).
        Reference: RFC 6298 §5.7 (restart-after-idle baseline).
        """

        session = self._session
        # RFC 6298 §5.7 restart-after-idle: when a session has
        # been silent for longer than the in-flight 'rto_ms' the
        # smoothed RTT estimator may be stale (the network
        # conditions that produced the current SRTT/RTTVAR may
        # no longer hold). Reset to 'initial_state()' so the
        # next sample re-establishes the estimator from scratch
        # and avoids spurious retransmits with a now-too-short
        # RTO. The '_last_send_time_ms is not None' guard
        # ensures the reset never fires on a fresh session
        # before any send has occurred.
        if (
            (data or flag_syn or flag_fin)
            and session._rtt.last_send_time_ms is not None
            and stack.timer.now_ms - session._rtt.last_send_time_ms > session._rto_state.rto_ms
        ):
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - RFC 6298 §5.7 idle-reset: now="
                f"{stack.timer.now_ms} last_send="
                f"{session._rtt.last_send_time_ms} rto_ms="
                f"{session._rto_state.rto_ms}; resetting estimator",
            )
            session._rto_state = initial_state()
            # RFC 5681 §4.1 Restart Window: same idle trigger,
            # reduce cwnd to RW = min(IW, cwnd) so a stale
            # high-cwnd estimate from a prior high-bandwidth
            # period doesn't blast a line-rate burst into a
            # network whose live capacity may have decayed.
            # Skipped on flag_syn (handshake path; cwnd is
            # already the post-handshake IW) and on FIN-only
            # (no data to pace).
            if data:
                rw = min(initial_window(session._win.snd_mss), session._cc.cwnd)
                if rw < session._cc.cwnd:
                    __debug__ and log(
                        "tcp-ss",
                        f"[{session}] - RFC 5681 §4.1 Restart Window: "
                        f"cwnd {session._cc.cwnd} -> {rw} (IW="
                        f"{initial_window(session._win.snd_mss)})",
                    )
                    session._cc.cwnd = rw
                    session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        # RFC 6298 §4 sample collection: record one in-flight RTT
        # sample at a time. The covering ACK harvest hook in
        # '_process_ack_packet' folds the observed RTT into
        # '_rto_state' via 'tcp__rto.update' (skipping the fold
        # iff Karn's flag is set per RFC 6298 §3). The
        # '_rtt_sample_seq is None' gate enforces single-sample-
        # per-RTT cadence: subsequent in-flight segments do not
        # overwrite the pending sample, and a retransmit of the
        # sampled segment lands here with '_rtt_sample_seq' set
        # so no fresh sample is recorded - the original
        # send-time stays paired with the original seq, with the
        # taint flag controlling whether the eventual ACK
        # produces an estimator update.
        if (data or flag_syn or flag_fin) and session._rtt.seq is None:
            session._rtt.record(seq=seq, send_time_ms=stack.timer.now_ms)

        # RFC 6298 §5.7 idle-baseline tracking: refresh the
        # last-send timestamp on every outbound segment that
        # consumes sequence space, so the §5.7 idle-check above
        # has an accurate baseline for the next send.
        if data or flag_syn or flag_fin:
            session._rtt.last_send_time_ms = stack.timer.now_ms

    def _phase1_compose_ecn_flags(
        self,
        *,
        flag_syn: bool,
        flag_ack: bool,
        flag_rst: bool,
        data: bytes,
    ) -> tuple[bool, bool, bool]:
        """
        Phase 1 of the outbound-send pipeline. Compose the
        (ECE, CWR, NS/AE) flag triple for the outbound segment.
        Mutates '_ecn_send_cwr' (cleared on CWR emission) and
        '_accecn_handshake_ack_pending' (consumed on the third-
        leg ACK).

        The branch ladder dispatches by segment kind and ECN
        capability:

          - Active-open SYN with AccECN advertised: AE+CWR+ECE
            (RFC 9768 §3.1.1 Table 1).
          - Active-open SYN with classic ECN advertised: ECE+CWR
            (RFC 3168 §6.1.1).
          - Passive-open SYN+ACK with AccECN enabled: encode the
            IP-ECN codepoint of the received SYN per §3.1.1
            Table 2.
          - Passive-open SYN+ACK with classic ECN enabled: ECE
            only.
          - Non-SYN with AccECN enabled (not RST): encode the
            'r.cep & 7' counter as ACE bits (§3.2.2.1), or the
            Table-3 handshake form on the third-leg ACK.
          - Non-SYN with classic ECN enabled (not RST): set ECE
            while '_send_ece' is True (§6.1.2 / §6.1.3 echo).

        Then unconditionally apply the §6.1.2 sender-side CWR
        confirmation: on the first outbound data segment after
        responding to an ECE, set CWR and clear '_ecn_send_cwr'
        so subsequent segments stay unmarked.

        Reference: RFC 3168 §6.1.1 (ECN-setup SYN flags).
        Reference: RFC 3168 §6.1.2 (sender CWR confirmation).
        Reference: RFC 3168 §6.1.3 (receiver CE-echo continuation).
        Reference: RFC 9768 §3.1.1 (AccECN handshake codepoint).
        Reference: RFC 9768 §3.2.2.1 (ACE field encoding non-SYN).
        """

        session = self._session
        flag_ece = False
        flag_cwr = False
        flag_ns = False
        # RFC 9768 §3.1.1 active-open AccECN-setup SYN. When
        # we advertise AccECN, the SYN carries AE+CWR+ECE -
        # the AE bit (NS position) is the wire signal that
        # distinguishes us from an RFC-3168-only client. A
        # peer that recognises AccECN responds with one of
        # four AE/CWR/ECE codepoints; one that does not
        # responds with the RFC 3168 ECE-only form, and we
        # fall back gracefully in the SYN_SENT handler.
        if flag_syn and not flag_ack and session._advertise.accecn:
            flag_ns = True
            flag_cwr = True
            flag_ece = True
        elif flag_syn and not flag_ack and session._advertise.ecn:
            flag_ece = True
            flag_cwr = True
        # RFC 9768 §3.1.1 passive-side AccECN SYN+ACK. When
        # the listener has accepted an AccECN-setup SYN, the
        # SYN+ACK carries one of four codepoints encoding the
        # IP-ECN of the received SYN:
        #   Not-ECT (00) -> AE=0, CWR=1, ECE=0
        #   ECT(1)  (01) -> AE=0, CWR=1, ECE=1
        #   ECT(0)  (10) -> AE=1, CWR=0, ECE=0
        #   CE      (11) -> AE=1, CWR=1, ECE=1
        # The encoding has AE = bit1 of the IP-ECN codepoint;
        # CWR = (NOT bit1) OR bit0 (i.e. set unless ECT(0));
        # ECE = bit0 of the codepoint XOR'd with bit1 (i.e.
        # set when codepoint is ECT(1) or CE).
        elif flag_syn and flag_ack and session._accecn.enabled:
            cp = session._accecn.synack_codepoint
            flag_ns = bool(cp & 0b10)
            flag_cwr = (cp & 0b10) == 0 or (cp & 0b01) != 0
            flag_ece = bool(cp & 0b01)
        elif flag_syn and flag_ack and session._ecn.enabled:
            flag_ece = True
        # RFC 9768 §3.2.2.1 ACE field encoding on non-SYN
        # segments of an AccECN-capable connection. The 3-bit
        # 'r.cep modulo 8' counter is encoded into the
        # AE+CWR+ECE flags as: bit2 -> AE (NS bit position),
        # bit1 -> CWR, bit0 -> ECE. RST segments stay
        # unmarked per the §3.2 advisory.
        #
        # On the active-open client's third-leg ACK the
        # encoding is the §3.2.2.1 Table-3 handshake form
        # instead of 'r.cep & 7' - the SYN_SENT handler
        # populated '_accecn_handshake_ack_pending' with the
        # Table-3 value derived from the inbound SYN+ACK's
        # IP-ECN codepoint. The pending field is consumed
        # (cleared to None) by this branch so subsequent
        # post-handshake segments fall back to the regular
        # encoding.
        elif session._accecn.enabled and not flag_rst:
            ace = session._accecn.next_ace_field()
            flag_ns = bool(ace & 0b100)
            flag_cwr = bool(ace & 0b010)
            flag_ece = bool(ace & 0b001)
        # RFC 3168 §6.1.2 / §6.1.3 receiver-side CE echo. On
        # non-SYN segments of an ECN-capable connection, set
        # ECE while the receiver's CE-echo flag is True. The
        # flag was set when an inbound CE-marked segment was
        # observed and is cleared once the sender confirms
        # cwnd reduction by setting CWR on a subsequent
        # segment.
        elif session._ecn.enabled and session._ecn.send_ece and not flag_rst:
            flag_ece = True
        # RFC 3168 §6.1.2 sender-side CWR confirmation. After
        # responding to an inbound ECE with cwnd reduction,
        # the first outbound data segment carries CWR as the
        # wire confirmation. The flag clears on emission so
        # subsequent segments stay unmarked unless a new ECN
        # response is triggered.
        if session._ecn.enabled and data and session._ecn.consume_cwr():
            flag_cwr = True
        return flag_ece, flag_cwr, flag_ns

    def _phase2_build_accecn_counters(
        self,
        *,
        flag_syn: bool,
        flag_ack: bool,
        flag_rst: bool,
    ) -> tuple[
        tuple[int | None, int | None, int | None] | None,
        tuple[int | None, int | None, int | None] | None,
    ]:
        """
        Phase 2 of the outbound-send pipeline. Build the RFC 9768
        §3.2.3 receiver-side AccECN option counter tuples for the
        outbound segment.

        On every outbound non-SYN segment of an AccECN-enabled
        connection, attach an AccECN option with the cumulative
        byte counters so the sender can compute precise per-
        codepoint feedback deltas across ACKs. Skipped on SYN-
        only segments (where the codepoint encoding in
        AE/CWR/ECE handles negotiation) and RST.

        Order choice between AccECN0 (Kind 172, ECT(0) first)
        and AccECN1 (Kind 174, ECT(1) first) per §3.2.3 'whichever
        order is more efficient': pick AccECN1 when r.ECT(1)
        advanced since the last emission and r.ECT(0) did not
        (the L4S-style workload pattern — putting the changed
        counter first minimises bytes under the abbreviation
        rule). Otherwise pick AccECN0 (the classic-ECN default
        and most common case).

        Length choice per §3.2.3 / §3.2.3.3 abbreviation rule:
        include any counter that changed since the last
        emission; once a counter is included, the ordering rule
        forces all preceding (less-trailing) counters in the
        natural order to also be included. Lengths 11/8/5/2
        correspond to including 3/2/1/0 counters respectively.

        Trackers initialise to -1 (outside the uint24 range) so
        the first emission always picks Length 11 — seeding the
        peer with the full §3.2.1 initial state on the third-leg
        ACK.

        Returns (accecn0_counters, accecn1_counters); exactly one
        is populated when AccECN is enabled and the segment is
        eligible, both are None otherwise.

        Reference: RFC 9768 §3.2.1 (initial counter state).
        Reference: RFC 9768 §3.2.3 (AccECN option emission + ordering).
        Reference: RFC 9768 §3.2.3.3 (abbreviation rule / wire lengths).
        """

        session = self._session
        if not session._accecn.enabled or flag_rst or (flag_syn and not flag_ack):
            return None, None
        return session._accecn.next_emit_counters()

    def _phase3_build_fastopen_cookie(self, *, flag_syn: bool, flag_ack: bool) -> bytes | None:
        """
        Phase 3 of the outbound-send pipeline. Build the RFC 7413
        TFO cookie value to attach to the outbound segment, with
        the §4.1.3.1 negative-cache and §4.4 SYN-retransmit-
        without-TFO bypass paths.

        Returns:
          - 'self._fastopen.cookie_to_emit' on a passive-open
            SYN+ACK (cookie generated by the LISTEN handler when
            peer's SYN carried the TFO option).
          - None on an active-open SYN if the peer is in the
            negative cache OR this is a SYN retransmit (§4.1.3.1
            / §4.4 bypass — fall back to plain 3WHS).
          - 'b""' (empty cookie-request) on an active-open SYN
            with no cached cookie.
          - The cached cookie on an active-open SYN with one
            available.
          - None for any segment that does not carry the TFO
            option (non-SYN, RST, etc.).

        Reference: RFC 7413 §3.1 (cookie request / cookie response).
        Reference: RFC 7413 §4.1.3.1 (negative-cache bypass).
        Reference: RFC 7413 §4.4 (SYN-retransmit-without-TFO bypass).
        """

        session = self._session
        if flag_syn and flag_ack and session._fastopen.cookie_to_emit is not None:
            return session._fastopen.cookie_to_emit
        if flag_syn and not flag_ack and session._advertise.fastopen:
            # RFC 7413 §4.1.3.1 negative-response cache
            # bypass: if this peer has previously failed TFO,
            # do NOT include the TFO option on the active-open
            # SYN — fall back to a plain 3WHS so the known-bad
            # path is not exercised. RFC 7413 §4.4 SYN-
            # retransmit-without-TFO bypass: if this is a
            # retransmit of an earlier SYN, drop the TFO option
            # so the second attempt is plain 3WHS. Otherwise
            # emit TFO with the cached cookie if known, else
            # the empty cookie-request form.
            if stack.tcp_stack.is_fastopen_negative(session._remote_ip_address) or session._fastopen.syn_retransmitted:
                return None
            return stack.tcp_stack.fastopen_cookie(session._remote_ip_address) or b""
        return None

    def _phase4_advance_send_state(
        self,
        *,
        seq: int,
        flag_syn: bool,
        flag_ack: bool,
        flag_fin: bool,
        data: bytes,
    ) -> None:
        """
        Phase 4 of the outbound-send pipeline. Advance per-session
        send-side state to reflect the segment that was just
        dispatched:

          - Insert a RACK per-segment record for the segment.
          - Reset RCV.UNA = RCV.NXT (the piggybacked ACK field
            covers everything up to RCV.NXT, so the delayed-ACK
            gate is now disarmed).
          - Advance SND.NXT modularly past the consumed seq
            range (RFC 9293 §3.4).
          - Bump SND.MAX iff SND.NXT is now ahead of it (modular
            max).
          - Bump '_tx_buffer_seq_mod' modularly for any consumed
            SYN / FIN seq (data bytes are accounted for via the
            TX-buffer drain in the inbound-ACK path).
          - Stash SND.NXT and set '_fin_sent' on FIN emission.
          - Accumulate 'prr_out' during a recovery episode for
            the per-ACK PRR send-pacing computation.
          - Reset the every-other-segment delayed-ACK counter
            when the outbound segment carries an ACK.

        Reference: RFC 6937 §3.1 (PRR per-recovery prr_out).
        Reference: RFC 8985 §5.2 (RACK per-segment record).
        Reference: RFC 8985 §6.1 (RACK retransmit-tag).
        Reference: RFC 9293 §3.4 (modular SND.NXT / SND.MAX).
        """

        session = self._session
        # RFC 8985 §5.2 / §6.1 RACK per-segment record: insert a
        # 'RackSegment' for every outbound segment that consumes
        # sequence space (data / SYN / FIN). Keyed by the
        # segment's starting seq. If the seq is already in the
        # dict the segment is a retransmit (re-entered
        # '_transmit_packet' with the same '_snd_nxt' after a
        # walkback) - record xmit_ts of the latest transmission
        # AND set 'retransmitted' so RACK §6.2 step 2 can
        # disambiguate samples per Karn's algorithm. Phase 1
        # only ships the storage; Phase 2 onward consumes it.
        if data or flag_syn or flag_fin:
            session._rack_tlp.record_segment(
                seq=seq,
                end_seq=add32(seq, len(data), flag_syn, flag_fin),
                xmit_ts=stack.timer.now_ms,
            )
        # Mark RCV.UNA = RCV.NXT: the segment we just emitted
        # acknowledged everything up to RCV.NXT (via the piggybacked
        # 'ack' field if 'flag_ack' is set, or trivially otherwise),
        # so there is no longer any pending RX byte the peer is
        # unaware we received. '_delayed_ack' uses the
        # 'RCV.UNA != RCV.NXT' inequality as the gate for firing the
        # next delayed ACK; resetting them to equal here disarms
        # that gate until the next inbound data segment.
        session._rcv_seq.una = session._rcv_seq.nxt
        # RFC 9293 §3.4: modular SND.NXT advance + SND.MAX bump.
        session._snd_seq.advance_nxt(seq=seq, data_len=len(data), flag_syn=flag_syn, flag_fin=flag_fin)
        session._snd_seq.bump_max_to_nxt()
        # Modular '+=' on '_tx_buffer_seq_mod' (a Seq32 anchor):
        # raw '+=' would let the value escape the 32-bit range
        # past the wrap; 'add32' clamps to UINT32__MAX.
        session._tx.bump_seq_mod_for_flags(flag_syn=flag_syn, flag_fin=flag_fin)

        # RFC 9293 §3.10.7.4: stamp the FIN seq + idempotent gate.
        if flag_fin:
            session._snd_seq.record_fin()

        # RFC 6937 §3.1 PRR: track 'prr_out' across every
        # outbound segment that consumes sequence space while
        # we are in a recovery episode. The accumulator feeds
        # the per-ACK 'sndcnt' computation
        # ('CEIL(prr_delivered * ssthresh / RecoverFS) -
        # prr_out') so PRR's send-pacing decision sees the
        # actual recovery-episode send rate. The retransmit
        # that fires from the recovery-entry path consumes one
        # SMSS of 'prr_out'; subsequent retransmits or new
        # data sent during recovery accumulate here too.
        if session._cc.recovery_point != 0 and (data or flag_syn or flag_fin):
            session._cc.prr_out += len(data) + flag_syn + flag_fin

        # Whenever we send an ACK-bearing segment (which may also carry
        # data) the peer's pending sequence space is implicitly
        # acknowledged via the piggybacked ACK field, so the
        # every-other-segment counter resets to zero.
        if flag_ack:
            session._delayed_ack_segments_pending = 0

    def _phase5_post_send_timers(self, *, flag_syn: bool, flag_fin: bool, data: bytes) -> None:
        """
        Phase 5 of the outbound-send pipeline. Arm the per-send
        timers and reset the keep-alive idle counter:

          - Keep-alive idle reset on every outbound segment
            (RFC 1122 §4.2.3.6).
          - Delayed-ACK timer arm on ESTABLISHED so the next
            inbound data segment cannot fire an immediate ACK
            via the every-other-segment branch in
            '_phase5_consume_segment_and_postprocess'.
          - Retransmit timer 'if not running, start it' on every
            sequence-consuming segment (RFC 6298 §5.1).
          - TLP timer arm on data segments outside recovery,
            using the §7.2 PTO formula clamped against the
            RTO expiration (RFC 8985 §7.2).

        Reference: RFC 1122 §4.2.3.6 (keep-alive activity reset).
        Reference: RFC 6298 §5.1 (retransmit-timer arm).
        Reference: RFC 8985 §7.2 (TLP scheduling + PTO clamp).
        """

        session = self._session
        # RFC 1122 §4.2.3.6: any outbound segment counts as
        # "activity" for keep-alive purposes - reset the idle
        # timer. No-op when keep-alive is disabled. The keep-alive
        # PROBE itself bypasses this method (it goes through
        # 'stack.packet_handler.send_tcp_packet' directly), so a
        # probe emission does not spuriously reset its own timer.
        session._keepalive_arm_idle()

        # If in ESTABLISHED state then reset ACK delay timer.
        if session._state is FsmState.ESTABLISHED:
            session._arm_timer("delayed_ack", tcp__constants.TCP__DELAYED_ACK__DELAY_MS)

        # RFC 6298 §5.1: every packet containing data (including a
        # retransmission) starts the retransmit timer if it is not
        # already running. '_timer_armed' is False both when the
        # timer was never armed AND after it has fired, so this
        # branch correctly arms a fresh timer post-§5.2-shutdown
        # without spuriously re-arming a still-running one.
        # Re-arming on every send would diverge from
        # §5.1's "if not running, start it" wording; the §5.3
        # restart-on-cum-ACK fires from '_process_ack_packet'
        # instead, and the timeout-driven re-arm fires from
        # '_retransmit_packet_timeout' after 'back_off'.
        if (data or flag_syn or flag_fin) and not session._timer_armed("retransmit"):
            session._arm_timer("retransmit", session._rto_state.rto_ms)

        # RFC 8985 §7.2 Tail Loss Probe scheduling. Arm the
        # 'f"{self}-tlp"' timer on every outbound data segment
        # so the §7.3 probe-emission path can elicit an ACK if
        # the segment was the last byte of the application's
        # write and peer's ACK is delayed. Skipped while in
        # any recovery (recovery_point != 0 OR _frto_active)
        # because a probe during recovery would race the
        # ongoing retransmit machinery. Only fires for data
        # segments, not SYN / FIN / pure-ACK probes.
        # RFC 8985 §7.2 TLP arming. Gated on:
        #   - data segment fired (not SYN / FIN / pure-ACK),
        #   - no recovery in progress (recovery_point == 0
        #     and not frto_active),
        #   - SRTT measurement available. The RFC permits a
        #     1000 ms fallback when SRTT is unavailable, but
        #     in that regime PTO equals the initial RTO so
        #     TLP and RTO would race; PyTCP defers to the
        #     RTO-only path until the first RTT sample arrives,
        #     then enables TLP for tail-loss probing.
        # Arm TLP only when SRTT is available and non-zero
        # (i.e. a measurable RTT sample exists). The RFC
        # permits a 1000 ms fallback when SRTT is unavailable,
        # but in that regime PTO equals the initial RTO and
        # would race the RTO timer; PyTCP defers to the
        # RTO-only path until a real RTT sample arrives.
        if (
            data
            and session._cc.recovery_point == 0
            and not session._cc.frto_active
            and (session._rto_state.srtt_ms or 0) > 0
        ):
            flight_size = (session._snd_seq.max - session._snd_seq.una) & 0xFFFF_FFFF
            # Use the IN-FLIGHT RTO timer's actual remaining
            # time (when accessible) so the §7.2 'do not
            # outlast RTO' clamp respects the real expiration.
            # Fall back to None when the timer subsystem does
            # not expose internal state (e.g. unit-test stubs).
            rto_remaining_ms = getattr(stack.timer, "_timers", {}).get(f"{session}-retransmit")
            rto_expiration_ms = (stack.timer.now_ms + rto_remaining_ms) if rto_remaining_ms else None
            pto_ms = tlp_calc_pto(
                srtt_ms=session._rto_state.srtt_ms,
                flight_size=flight_size,
                smss=session._win.snd_mss,
                max_ack_delay_ms=session._rack_tlp.tlp_max_ack_delay_ms,
                rto_expiration_ms=rto_expiration_ms,
                now_ms=stack.timer.now_ms,
            )
            if pto_ms > 0:
                session._arm_timer("tlp", pto_ms)
                session._rack_tlp.tlp_armed = True
