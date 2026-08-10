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
This module contains the TCP FSM SYN_SENT state handler.

pytcp/protocols/tcp/fsm/tcp__fsm__syn_sent.py

ver 3.0.10
"""

from dataclasses import replace
from typing import TYPE_CHECKING

from net_proto.protocols.tcp.tcp__header import TCP__MIN_MSS
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.tcp.tcp__cwnd import initial_window
from pytcp.protocols.tcp.tcp__enums import ConnError, FsmState, SysCall
from pytcp.protocols.tcp.tcp__icmp_metadata import IcmpMetadata
from pytcp.protocols.tcp.tcp__seq import add32, le32, lt32
from pytcp.runtime.socket.tcp__metadata import TcpMetadata

if TYPE_CHECKING:
    from pytcp.protocols.tcp.session import TcpSession


# RFC 5927 §5.2 hard-error code set: ICMPv4 Type 3 codes
# 2 (Protocol Unreachable) / 3 (Port Unreachable), and ICMPv6
# Type 1 codes 1 (admin prohibited) / 4 (Port Unreachable).
# Code 4 (Frag Needed) is excluded — PMTUD treats it as soft and
# routes via the PMTU category instead.
_SYN_SENT__HARD_DEST_UNREACHABLE_CODES: frozenset[tuple[int, int]] = frozenset(
    {
        (3, 2),  # ICMPv4 Protocol Unreachable
        (3, 3),  # ICMPv4 Port Unreachable
        (1, 1),  # ICMPv6 Communication with destination admin prohibited
        (1, 4),  # ICMPv6 Port Unreachable
    }
)

# RFC 1122 §4.2.3.9 / RFC 5927 §6 soft-host-unreachable codes:
# ICMPv4 Type 3 Code 1 (Host Unreachable) and ICMPv6 Type 1 Code
# 3 (Address Unreachable). RFC 5927 §6 classes these as
# hint-not-proof advisory errors.
_SYN_SENT__SOFT_HOST_CODES: frozenset[tuple[int, int]] = frozenset(
    {
        (3, 1),  # ICMPv4 Host Unreachable
        (1, 3),  # ICMPv6 Address Unreachable
    }
)

# RFC 1122 §4.2.3.9 / RFC 5927 §6 soft-net-unreachable codes:
# ICMPv4 Type 3 Code 0 (Net Unreachable) and ICMPv6 Type 1 Code
# 0 (No Route to Destination).
_SYN_SENT__SOFT_NET_CODES: frozenset[tuple[int, int]] = frozenset(
    {
        (3, 0),  # ICMPv4 Net Unreachable
        (1, 0),  # ICMPv6 No Route to Destination
    }
)


def fsm__syn_sent__icmp(session: TcpSession, metadata: IcmpMetadata) -> None:
    """
    TCP FSM SYN_SENT state ICMP-error handler.

    SYN_SENT is the only state where TCP applies the RFC 1122 §4.2.3.9
    'SHOULD abort on hard error' rule (RFC 5927 §5.2 narrows it to
    pre-synchronized state). Hard codes -> ConnError.REFUSED + CLOSED;
    Net/Host Unreachable record the diagnostic and release the blocked
    CONNECT but do not abort; everything else is purely advisory.
    """

    # Avoid runtime import of IcmpCategory by referring to its enum
    # values via an isolated import — the dispatch table guarantees
    # 'metadata.category' is one of the four canonical values.
    from pytcp.protocols.tcp.tcp__icmp_metadata import IcmpCategory

    if metadata.category is IcmpCategory.DEST_UNREACHABLE:
        type_code = (metadata.icmp_type, metadata.icmp_code)
        if type_code in _SYN_SENT__HARD_DEST_UNREACHABLE_CODES:
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - <ly>[{session._state}]</> - got ICMP "
                f"hard error type={metadata.icmp_type} "
                f"code={metadata.icmp_code}, refusing",
            )
            session._connection_error = ConnError.REFUSED
            session._event__rx_buffer.set()
            session._event__connect.release()
            session._change_state(FsmState.CLOSED)
            return
        if type_code in _SYN_SENT__SOFT_HOST_CODES:
            session._connection_error = ConnError.HOST_UNREACHABLE
            session._event__rx_buffer.set()
            session._event__connect.release()
            return
        if type_code in _SYN_SENT__SOFT_NET_CODES:
            session._connection_error = ConnError.NET_UNREACHABLE
            session._event__rx_buffer.set()
            session._event__connect.release()
            return
        return

    if metadata.category is IcmpCategory.PMTU:
        assert metadata.next_hop_mtu is not None, "IcmpMetadata.next_hop_mtu must be set for PMTU events."
        session._apply_pmtu_update(
            next_hop_mtu=metadata.next_hop_mtu,
            ip_version=metadata.ip_version,
        )
        return

    # TIME_EXCEEDED / PARAM_PROBLEM are soft per RFC 5927 §6 — log only.
    __debug__ and log(
        "tcp-ss",
        f"[{session}] - <ly>[{session._state}]</> - got ICMP "
        f"category={metadata.category.name} type={metadata.icmp_type} "
        f"code={metadata.icmp_code} (soft, advisory only)",
    )


def fsm__syn_sent__timer(session: TcpSession) -> None:
    """
    TCP FSM SYN_SENT state timer handler.

    Resend the SYN if its retransmit timer expired and drain
    any TFO-piggybacked TX buffer.
    """

    session._retransmit_packet_timeout()
    session._transmit_data()


def fsm__syn_sent__syscall(session: TcpSession, syscall: SysCall) -> None:
    """
    TCP FSM SYN_SENT state syscall handler.

    Got CLOSE syscall -> Change state to CLOSED. Also signal
    any blocked CONNECT caller (typical for a multi-threaded
    app with one thread blocked on 'connect()' and another
    calling 'close()') with 'ConnError.CANCELED' so they
    unblock with 'TcpSessionError("Connection canceled")'
    rather than hanging on the dead session forever.
    """

    if syscall is SysCall.CLOSE:
        session._connection_error = ConnError.CANCELED
        session._event__connect.release()
        session._change_state(FsmState.CLOSED)


def fsm__syn_sent__packet(session: TcpSession, packet_rx_md: TcpMetadata) -> None:
    """
    TCP FSM SYN_SENT state packet handler.
    """

    # RFC 9293 §3.10.7.3 step 1: ACK acceptability check.
    # Any incoming segment with ACK set whose SEG.ACK falls outside
    # (SND.UNA, SND.MAX] must elicit '<SEQ=SEG.ACK><CTL=RST>' and the
    # segment itself must be discarded; the RST emit is suppressed if
    # the offending segment also carries the RST bit, to avoid RST/RST
    # loops. This check applies regardless of the SYN / FIN / RST
    # combination on the segment - it must precede the per-flag
    # branches below, matching the order RFC 9293 §3.10.7.3
    # prescribes (step 1 ACK, step 2 RST, step 3 security, step 4 SYN).
    # We bypass '_transmit_packet' for this RST because that helper
    # rewrites '_snd_nxt' from its 'seq' argument, which would corrupt
    # our state by latching the offending peer's ACK number into our
    # send sequence space; the RST itself consumes no sequence space
    # and must leave session bookkeeping untouched.
    # Modular '(SND.UNA, SND.MAX]' check per RFC 9293 §3.4.
    # The chained Python '<' / '<=' fails across the 32-bit
    # wrap when the SYN consumed seq 0xFFFF_FFFF and SND.MAX
    # has wrapped to 0; the modular helpers fire the
    # acceptability test correctly regardless of where in
    # the seq space the ISS happens to fall.
    if packet_rx_md.tcp__flag_ack and not (
        lt32(session._snd_seq.una, packet_rx_md.tcp__ack) and le32(packet_rx_md.tcp__ack, session._snd_seq.max)
    ):
        if not packet_rx_md.tcp__flag_rst:
            stack.egress_packet_handler(session._remote_ip_address).send_tcp_packet(
                ip__local_address=session._local_ip_address,
                ip__remote_address=session._remote_ip_address,
                ip__dscp=session._socket._effective_ip_dscp(),
                tcp__local_port=session._local_port,
                tcp__remote_port=session._remote_port,
                tcp__flag_rst=True,
                tcp__seq=packet_rx_md.tcp__ack,
                tcp__ack=0,
                tcp__win=session._rcv_wnd,
            )
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - SYN_SENT: rejected segment with unacceptable "
                f"ACK={packet_rx_md.tcp__ack}, sent RST (RFC 9293 §3.10.7.3)",
            )
        return

    # Got SYN + ACK packet -> Send ACK / change state to ESTABLISHED.
    if all({packet_rx_md.tcp__flag_syn, packet_rx_md.tcp__flag_ack}) and not any(
        {packet_rx_md.tcp__flag_fin, packet_rx_md.tcp__flag_rst}
    ):
        # Packet sanity check. RFC 9293 §3.10.7.3 step 4 ("If
        # there are other controls or text in the segment, then
        # continue processing at the sixth step under Section
        # 3.10.7.4 ...") explicitly permits piggybacked data on
        # the SYN+ACK; the data is NOT gated here, it is
        # enqueued into '_rx_buffer' below.
        #
        # ACK acceptability per RFC 9293 §3.10.7.3 step 1 is
        # modular '(SND.UNA, SND.MAX]': any ack that advances
        # SND.UNA past at least the SYN (peer_iss + 1) is
        # acceptable. The '== SND.NXT' strict-equality check
        # this replaces was correct for non-TFO sessions where
        # SND.NXT only ever advances on the SYN's one byte,
        # but for RFC 7413 §4.2 TFO partial-acks (server
        # rejects SYN-data; SYN+ACK acks only the SYN, ack <
        # SND.NXT) the equality check would refuse the
        # SYN+ACK and the handshake would stall.
        if lt32(session._snd_seq.una, packet_rx_md.tcp__ack) and le32(packet_rx_md.tcp__ack, session._snd_seq.nxt):
            # Clamp the effective send-MSS to RFC 879 / RFC 6691
            # bounds: at most '_mss_ceiling()' (the egress
            # interface MTU minus IP+TCP overhead, or the smaller
            # PLPMTUD cold-start ceiling when 'tcp.mtu_probing' is
            # enabled), at least 'TCP__MIN_MSS = 536' (the SMSS
            # floor that 'option absent' would yield - any smaller
            # peer-advertised value, including the malformed 0,
            # is treated as 'option absent').
            session._win.snd_mss = max(
                TCP__MIN_MSS,
                min(packet_rx_md.tcp__mss, session._mss_ceiling()),
            )
            # Initial '_snd_wnd' = peer's literal SYN+ACK win
            # (unshifted per RFC 7323 §2.2 - "WSopt is not used
            # to scale the value in the window field of the SYN
            # segment itself"). Subsequent post-handshake
            # segments will be shifted by '_snd_wsc' inside
            # '_process_ack_packet'.
            session._win.snd_wnd = packet_rx_md.tcp__win
            session._rcv_seq.ini = packet_rx_md.tcp__seq
            # Bootstrap RCV.NXT from peer's ISN before
            # '_process_ack_packet' runs - the modular 'max'
            # inside that helper cannot bootstrap from
            # uninitialized 'rcv_nxt = 0' to a peer ISN near
            # the 32-bit wrap (modular distance 0 -> high seq
            # goes the "wrong way"). Mirror the passive-open
            # path's explicit assignment.
            session._rcv_seq.nxt = add32(
                packet_rx_md.tcp__seq,
                packet_rx_md.tcp__flag_syn,
                len(packet_rx_md.tcp__data),
            )
            # Mark peer as contacted so the R2-abort RST
            # gate in '_retransmit_packet_timeout' fires
            # the RST even when 'RCV.NXT' happens to equal
            # 0 (peer's ISN was 0xFFFF_FFFF, modular wrap).
            session._peer_contacted = True
            session._cc.cwnd = session._win.snd_mss
            session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)
            # Enqueue any piggybacked SYN+ACK data per RFC 9293
            # §3.10.7.4 step 7 BEFORE '_process_ack_packet'
            # runs: the helper's overlap-prefix calculation
            # would otherwise classify all data bytes as
            # already-received (since RCV.NXT was pre-advanced
            # past them above) and silently drop them. Mirrors
            # the LISTEN-side handling for SYN-with-data in
            # '_tcp_fsm_listen'.
            if packet_rx_md.tcp__data:
                session._enqueue_rx_buffer(packet_rx_md.tcp__data)
            # Process ACK packet (uses '_snd_wsc=0' still, so
            # the SYN+ACK's win is preserved unshifted).
            session._process_ack_packet(packet_rx_md)
            # RFC 7413 §4.2 TFO partial-ack handling: when
            # the server rejected our SYN-data
            # (ack < SND.NXT after _process_ack_packet
            # advanced SND.UNA only past the SYN), rewind
            # SND.NXT to SND.UNA so the data still in
            # '_tx_buffer' is re-emitted by '_transmit_data'
            # on the next tick (post-ESTABLISHED). Without
            # the rewind the data would sit unacked until
            # the RTO retransmit timer fires - a one-RTO
            # latency penalty for every TFO failure.
            if lt32(session._snd_seq.una, session._snd_seq.nxt):
                session._snd_seq.nxt = session._snd_seq.una
            # RFC 6928 §2 Initial Window: post-handshake cwnd
            # = min(10*MSS, max(2*MSS, 14600)). Set after
            # '_process_ack_packet' has fired §3.1 growth on
            # the SYN+ACK ack-advance so the IW value is the
            # exact post-handshake cwnd, not IW + 1.
            session._cc.cwnd = initial_window(session._win.snd_mss)
            session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)
            # RFC 6298 §5.7 second clause: when the SYN was
            # retransmitted at least once before the handshake
            # completed, RTO MUST be re-initialized to >= 3 s
            # when data transmission begins. The floor protects
            # against pathologically aggressive RTOs in
            # environments where the SYN's RTT clamp
            # (MIN_RTO_MS = 1000 ms) is optimistic relative to
            # the path's actual RTT. A clean handshake
            # ('_syn_retransmit_count == 0') skips the floor
            # and uses the canonical estimator output. The
            # dedicated counter survives '_process_ack_packet's
            # reset of the general-purpose '_retransmit_count'
            # so the check is order-independent.
            if session._syn_retransmit_count > 0 and session._rto_state.rto_ms < 3000:
                session._rto_state = replace(session._rto_state, rto_ms=3000)
            # WSCALE bilateral negotiation per RFC 7323 §2.2:
            # store peer's wscale only if WE offered our own.
            # The check 'packet_rx_md.tcp__wscale != 0' is the
            # parser's way of signalling the option was present
            # on the wire (the parser substitutes 0 when the
            # option is absent via 'TcpOptions.wscale or 0').
            # Set '_snd_wsc' AFTER '_process_ack_packet' so the
            # SYN+ACK's literal 'win' value is used unshifted
            # per scenario #6's invariant.
            if session._advertise.wscale and packet_rx_md.tcp__wscale:
                session._win.snd_wsc = packet_rx_md.tcp__wscale
            else:
                # Bilateral non-offer: no scaling on either side.
                session._win.rcv_wsc = 0
                session._win.snd_wsc = 0
            # SACK bilateral negotiation per RFC 2018 §2:
            # active-open mirrors peer's offer. SACK is
            # enabled iff WE advertised on the SYN we sent
            # AND peer echoed SACK-Permitted on the SYN+ACK.
            session._advertise.send_sack = session._advertise.sack and packet_rx_md.tcp__sackperm
            # RFC 7323 §3 bilateral negotiation: enable post-
            # handshake TSopt iff WE advertised on our SYN AND
            # peer's SYN+ACK carried TSopt. Cache peer's TSval
            # as '_ts_recent' so the third-leg ACK and all
            # subsequent segments echo it via TSecr.
            if session._advertise.ts and packet_rx_md.tcp__tsval is not None:
                session._ts.send_ts = True
                session._ts.ts_recent = packet_rx_md.tcp__tsval
                # RFC 7323 §5.5 outdated-timestamps mitigation:
                # seed the last-update clock at handshake.
                session._ts.ts_recent_updated_at_ms = stack.timer.now_ms
            # RFC 9768 §3.1.1 / §3.1.2 active-side bilateral
            # ECN/AccECN confirmation. The peer's SYN+ACK
            # codepoint disambiguates which protocol it
            # supports. AccECN-capable (AE=1 OR CWR=1) takes
            # precedence; RFC 3168-only (AE=0, CWR=0, ECE=1)
            # is the graceful fallback. Mutual exclusivity is
            # enforced by the order of these branches: at
            # most one of '_accecn_enabled' / '_ecn_enabled'
            # is set.
            # RFC 9768 §3.1.2 fourth-block 'Broken' guard: some
            # older TCP servers incorrectly reflect the SYN's
            # AE+CWR+ECE flags into the SYN/ACK. The client
            # cannot distinguish the reflected (1,1,1) SYN/ACK
            # from a genuine AccECN top-block CE-on-SYN
            # response, so the spec mandates falling back to
            # Not ECN whenever (1,1,1) appears - both halves
            # of the connection skip ECN/AccECN entirely.
            is_broken_reflection = (
                packet_rx_md.tcp__flag_ns and packet_rx_md.tcp__flag_cwr and packet_rx_md.tcp__flag_ece
            )
            if is_broken_reflection:
                pass  # neither _accecn_enabled nor _ecn_enabled set
            elif session._advertise.accecn and (packet_rx_md.tcp__flag_ns or packet_rx_md.tcp__flag_cwr):
                session._accecn.enabled = True
                # RFC 9768 §3.2.2.1: derive the Table-3 ACE value
                # from the inbound SYN+ACK's IP-ECN codepoint so
                # the third-leg ACK encodes it for the server's
                # mangling-detection check. Mapping:
                #   0 (Not-ECT) -> 0b010
                #   1 (ECT(1))  -> 0b011
                #   2 (ECT(0))  -> 0b100
                #   3 (CE)      -> 0b110
                _table3 = {0: 0b010, 1: 0b011, 2: 0b100, 3: 0b110}
                session._accecn.handshake_ack_pending = _table3[packet_rx_md.ip__ecn]
                # RFC 9768 §3.2.2.2: a CE-marked SYN+ACK MUST
                # increment r.cep (one-shot from 5 to 6) so the
                # marking is reliably delivered via the ACE
                # field on subsequent post-handshake segments.
                if packet_rx_md.ip__ecn == 3:
                    session._accecn.r_cep = 6
                # RFC 9768 §3.2.2.3 IP-ECN mangling test
                # (client side). The SYN/ACK's AE+ECE flag
                # pair encodes the IP-ECN codepoint peer
                # observed on the SYN we sent (Table 2):
                # codepoint = (AE << 1) | ECE. PyTCP always
                # transmits Not-ECT (0) on SYNs per RFC 3168
                # §6.1.1, so any peer-observed codepoint
                # other than Not-ECT is an invalid transition
                # of the IP-ECN field along the path - the
                # 'mangling' the §3.2.2.3 procedure detects.
                # The (1,1,1) broken-reflection case is
                # handled by the outer 'is_broken_reflection'
                # branch above and never reaches this point.
                observed_ipecn = (int(packet_rx_md.tcp__flag_ns) << 1) | int(packet_rx_md.tcp__flag_ece)
                if observed_ipecn != 0:
                    session._accecn.mangling_detected = True
            elif session._advertise.ecn and packet_rx_md.tcp__flag_ece and not packet_rx_md.tcp__flag_cwr:
                session._ecn.enabled = True
            # RFC 7413 §3.1 client-side cookie cache update:
            # when peer's SYN+ACK carries a non-empty TFO
            # cookie, cache it against the peer IP via the
            # 'cache_cookie' helper so the cache stays
            # bounded by 'TCP__FASTOPEN_CACHE_MAX_SIZE'
            # (FIFO eviction). Subsequent active-open to
            # the same server can replay the cached cookie
            # until eviction times out the entry.
            if packet_rx_md.tcp__fastopen_cookie:
                from pytcp.protocols.tcp.tcp__fastopen import cache_cookie

                cache_cookie(
                    peer_address=session._remote_ip_address,
                    cookie=bytes(packet_rx_md.tcp__fastopen_cookie),
                )
            # Send initial ACK packet.
            session._transmit_packet(flag_ack=True)
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - Sent initial ACK ({session._rcv_seq.una}) packet",
            )
            # Change state to ESTABLISHED.
            session._change_state(FsmState.ESTABLISHED)
            # Inform connect syscall that connection related event happened.
            session._event__connect.release()
            return

    # Got SYN packet -> Send SYN + ACK packet / change state to SYN_RCVD.
    # Simultaneous-open path per RFC 9293 §3.5.1: peer's bare SYN
    # crossed our outbound SYN before either side saw the other's
    # SYN. Bootstrap peer-side state from peer's SYN options -
    # mirroring the listener-fork pattern in '_tcp_fsm_listen' -
    # then emit a SYN+ACK that reuses our original SYN's seq
    # with peer's ACK piggybacked. The bootstrap is mandatory:
    # without it the SYN+ACK we emit would carry 'ack=0' (the
    # uninitialised '_rcv_nxt' default) and peer's TCP would
    # reject it as not acknowledging their SYN, leaving both
    # ends stuck until R2 fires.
    if all({packet_rx_md.tcp__flag_syn}) and not any(
        {
            packet_rx_md.tcp__flag_ack,
            packet_rx_md.tcp__flag_fin,
            packet_rx_md.tcp__flag_rst,
        }
    ):
        # Packet sanity check.
        if packet_rx_md.tcp__ack == 0 and not packet_rx_md.tcp__data:
            # Clamp the effective send-MSS to RFC 879 / RFC 6691
            # bounds: at most '_mss_ceiling()' (the egress
            # interface MTU minus IP+TCP overhead, or the smaller
            # PLPMTUD cold-start ceiling when 'tcp.mtu_probing' is
            # enabled), at least 'TCP__MIN_MSS = 536'.
            session._win.snd_mss = max(
                TCP__MIN_MSS,
                min(packet_rx_md.tcp__mss, session._mss_ceiling()),
            )
            session._win.snd_wnd = packet_rx_md.tcp__win
            # WSCALE bilateral negotiation per RFC 7323 §2.2.
            if session._advertise.wscale and packet_rx_md.tcp__wscale:
                session._win.snd_wsc = packet_rx_md.tcp__wscale
            else:
                session._win.rcv_wsc = 0
                session._win.snd_wsc = 0
            # SACK bilateral negotiation per RFC 2018 §2.
            session._advertise.send_sack = session._advertise.sack and packet_rx_md.tcp__sackperm
            # RFC 7323 §3 bilateral negotiation (simultaneous-
            # open path): same shape as the SYN+ACK case above.
            if session._advertise.ts and packet_rx_md.tcp__tsval is not None:
                session._ts.send_ts = True
                session._ts.ts_recent = packet_rx_md.tcp__tsval
                # RFC 7323 §5.5 outdated-timestamps mitigation:
                # seed the last-update clock at handshake.
                session._ts.ts_recent_updated_at_ms = stack.timer.now_ms
            # Receive sequence space: advance past peer's SYN.
            session._rcv_seq.ini = packet_rx_md.tcp__seq
            session._rcv_seq.nxt = add32(packet_rx_md.tcp__seq, packet_rx_md.tcp__flag_syn)
            # Mark peer as contacted so the R2-abort RST gate
            # fires correctly across the seq wrap (commit
            # 'e5e12dc' rationale).
            session._peer_contacted = True
            # Reset slow-start to one MSS now that we know peer's
            # MSS for real.
            session._cc.cwnd = session._win.snd_mss
            session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)
            # Send SYN + ACK at our original SYN's seq so peer
            # accepts it as the simultaneous-open response. RFC
            # 9293 §3.5.1 figure 8: the simultaneous-open SYN+ACK
            # is functionally a retransmit of our SYN with peer's
            # ACK piggybacked.
            session._transmit_packet(flag_syn=True, flag_ack=True, seq=session._snd_seq.ini)
            # Change state to SYN_RCVD.
            session._change_state(FsmState.SYN_RCVD)
            return

    # Got RST + ACK packet -> Change state to CLOSED.
    if all({packet_rx_md.tcp__flag_rst, packet_rx_md.tcp__flag_ack}) and not any(
        {packet_rx_md.tcp__flag_fin, packet_rx_md.tcp__flag_syn}
    ):
        # Packet sanity check.
        if packet_rx_md.tcp__seq == 0 and packet_rx_md.tcp__ack == session._snd_seq.nxt:
            # Change state to CLOSED.
            session._change_state(FsmState.CLOSED)
            # Inform connect syscall that connection related event happened.
            session._connection_error = ConnError.REFUSED
            session._event__connect.release()
