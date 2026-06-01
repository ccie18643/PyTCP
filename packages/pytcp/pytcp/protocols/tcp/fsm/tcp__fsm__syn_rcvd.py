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
This module contains the TCP FSM SYN_RCVD state handler.

pytcp/protocols/tcp/fsm/tcp__fsm__syn_rcvd.py

ver 3.0.8
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from pytcp.lib.logger import log
from pytcp.protocols.tcp.tcp__cwnd import initial_window
from pytcp.protocols.tcp.tcp__enums import ConnError, FsmState, SysCall

if TYPE_CHECKING:
    from pytcp.protocols.tcp.session import TcpSession
    from pytcp.socket.tcp__metadata import TcpMetadata


def fsm__syn_rcvd__timer(session: TcpSession) -> None:
    """
    TCP FSM SYN_RCVD state timer handler.

    Resend the SYN+ACK if its retransmit timer expired and
    drain the TX buffer.
    """

    session._retransmit_packet_timeout()
    session._transmit_data()


def fsm__syn_rcvd__syscall(session: TcpSession, syscall: SysCall) -> None:
    """
    TCP FSM SYN_RCVD state syscall handler.

    Got CLOSE syscall in SYN_RCVD -> change state to
    FIN_WAIT_1; the FIN packet is emitted from that state
    on the next timer tick. The pre-handshake-completion
    close is legal per RFC 9293 §3.10.4 (CLOSE in
    SYN-RECEIVED). Also signal any blocked CONNECT caller
    (active-open simultaneous-open path) with
    'ConnError.CANCELED' so they unblock with
    'TcpSessionError("Connection canceled")' rather than
    hanging through the entire FIN-exchange lifecycle.
    """

    if syscall is SysCall.CLOSE:
        session._connection_error = ConnError.CANCELED
        session._event__connect.release()
        session._change_state(FsmState.FIN_WAIT_1)


def fsm__syn_rcvd__packet(session: TcpSession, packet_rx_md: TcpMetadata) -> None:
    """
    TCP FSM SYN_RCVD state packet handler.
    """

    # Got SYN-bearing segment without RST in SYN_RCVD -> Send a challenge
    # ACK per RFC 9293 §3.10.7.4 step 1 / step 4 (folding RFC 5961 §4).
    # SYN_RECEIVED is a synchronized state per RFC 9293; the peer's
    # original SYN's sequence space has already been consumed
    # ('RCV.NXT = peer.ISN + 1'), so any SYN arriving here has SEG.SEQ
    # one byte before our window and is therefore "unacceptable" per
    # step 1 - the spec form of that response is the same challenge ACK
    # step 4 prescribes for SYN-on-synchronized:
    #   <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
    # The branch matches SYN-bearing segments that do NOT also carry RST
    # so the existing RST+ACK and RST branches below still take priority
    # for tear-down semantics. This is the symmetric analog of the
    # SYN-on-established branch in '_tcp_fsm_established'.
    if packet_rx_md.tcp__flag_syn and not packet_rx_md.tcp__flag_rst:
        session._emit_challenge_ack()
        __debug__ and log(
            "tcp-ss",
            f"[{session}] - Sent challenge ACK for SYN-in-syn_rcvd (RFC 9293 §3.10.7.4)",
        )
        return

    # Got ACK packet -> Change state to ESTABLISHED.
    if all({packet_rx_md.tcp__flag_ack}) and not any(
        {
            packet_rx_md.tcp__flag_syn,
            packet_rx_md.tcp__flag_fin,
            packet_rx_md.tcp__flag_rst,
        }
    ):
        # Packet sanity check. RFC 9293 §3.10.7.4 step 7 ("Once
        # in the ESTABLISHED state, it is possible to deliver
        # segment text to user RECEIVE buffers") explicitly
        # permits piggybacked data on the third-leg ACK; the
        # data is NOT gated here, '_process_ack_packet' below
        # enqueues it via its overlap-prefix logic (RCV.NXT is
        # still at 'peer_ISS + 1' here, so the overlap prefix
        # is 0 and the full payload is enqueued).
        if packet_rx_md.tcp__seq == session._rcv_seq.nxt and packet_rx_md.tcp__ack == session._snd_seq.nxt:
            # RFC 9768 §3.2.2.1 Table 4: when an AccECN
            # server's first inbound ACK arrives in
            # SYN-RCVD as a pure ACK with no SACK blocks,
            # decode the AE+CWR+ECE flags as the §3.2.2.1
            # handshake-encoded ACE field and infer the
            # IP-ECN codepoint of the SYN/ACK as observed
            # by the client. Update s.cep accordingly:
            #   ACE=000 -> s.disabled = True (§3.2.2.1
            #             Note 1 - server MUST NOT set ECT
            #             on outgoing packets and MUST NOT
            #             respond to AccECN feedback)
            #   ACE=110 -> s.cep = 6 (CE on SYN/ACK)
            #   any other ACE -> s.cep = 5
            # The decode runs only when AccECN is enabled
            # for this session and the inbound ACK has no
            # SACK blocks (the §3.2.2.1 gating condition
            # for the handshake encoding); a SACK-bearing
            # ACK falls through to the regular post-
            # handshake processing.
            if session._accecn.enabled and not packet_rx_md.tcp__sack_blocks:
                ace = (
                    (int(packet_rx_md.tcp__flag_ns) << 2)
                    | (int(packet_rx_md.tcp__flag_cwr) << 1)
                    | int(packet_rx_md.tcp__flag_ece)
                )
                if ace == 0b000:
                    session._accecn.s_disabled = True
                elif ace == 0b110:
                    session._accecn.s_cep = 6
                else:
                    session._accecn.s_cep = 5
                # RFC 9768 §3.2.2.3 IP-ECN mangling test
                # (server side). Each Table-4 ACE value
                # encodes the IP-ECN codepoint client
                # observed on the SYN/ACK we sent. PyTCP
                # always transmits Not-ECT (0) on SYN/ACK
                # per RFC 3168 §6.1.1, so any client-observed
                # codepoint other than Not-ECT is an invalid
                # transition - the 'mangling' the §3.2.2.3
                # procedure detects. ACE=000 is the §3.2.2.1
                # Note 1 protocol-non-compliance signal
                # already handled above (sets s.disabled);
                # ACE=001 / 0b101 / 0b111 are the §3.2.2.1
                # Note 2 'currently unused' codepoints,
                # forward-compat default to 's.cep = 5' with
                # no mangling claim. The remaining four
                # canonical ACE values map to non-Not-ECT
                # codepoints and trigger the flag.
                if ace in (0b011, 0b100, 0b110):  # ECT(1), ECT(0), CE
                    session._accecn.mangling_detected = True
            session._process_ack_packet(packet_rx_md)
            # RFC 6928 §2 Initial Window: post-handshake cwnd
            # = min(10*MSS, max(2*MSS, 14600)). Set after
            # '_process_ack_packet' has fired §3.1 growth on
            # the third-leg ack-advance so the IW value is
            # the exact post-handshake cwnd. Covers both the
            # passive-open path (peer's SYN -> our SYN+ACK ->
            # peer's third-leg ACK) and the simultaneous-open
            # path (both sides SYN, both SYN+ACK, third-leg
            # ACK).
            session._cc.cwnd = initial_window(session._win.snd_mss)
            session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)
            # RFC 6298 §5.7 second clause (passive- and
            # simultaneous-open shape): if our SYN+ACK was
            # retransmitted at least once before peer's
            # third-leg ACK arrived, RTO MUST be re-
            # initialized to >= 3 s when data transmission
            # begins. The dedicated '_syn_retransmit_count'
            # field survives '_process_ack_packet's reset of
            # '_retransmit_count' so the check is order-
            # independent.
            if session._syn_retransmit_count > 0 and session._rto_state.rto_ms < 3000:
                session._rto_state = replace(session._rto_state, rto_ms=3000)
            # Inline ACK if peer piggybacked data so peer's
            # retransmit machinery sees the data acknowledged
            # without waiting for delayed-ACK to fire (matches
            # the same idiom used for FIN+ACK with data in
            # '_tcp_fsm_established' and the data-bearing ACK
            # branches in the half-close states).
            if packet_rx_md.tcp__data:
                session._transmit_packet(flag_ack=True)
            # Change state to ESTABLISHED.
            session._change_state(FsmState.ESTABLISHED)
            # Passive-open path: inform the listening socket so
            # accept() can pick up the child. Simultaneous-open
            # path (active-open with peer's SYN crossing ours)
            # has no parent socket - the session itself is the
            # application-visible one; only the connect-event
            # release matters there. The 'is not None' gate
            # handles both paths uniformly without an assert
            # that would crash the active-open simultaneous-open
            # handshake.
            parent_socket = session._socket._parent_socket  # pylint: disable=protected-access
            if parent_socket is not None:
                parent_socket._tcp_accept.append(session._socket)  # pylint: disable=protected-access
                parent_socket._event__tcp_session_established.release()  # pylint: disable=protected-access
                # Selector readability: a 'selectors.DefaultSelector'
                # waiting on the listening socket's fileno() must
                # wake when a child lands on the accept queue.
                parent_socket._signal_readable()  # pylint: disable=protected-access
            # Inform connect syscall that connection related
            # event happened. Required for the active-open
            # simultaneous-open path (where the application
            # thread is blocked on '_event__connect.acquire()');
            # harmless on the passive-open path because no
            # caller is blocked on that semaphore there
            # ('Semaphore.release()' just increments the count).
            session._event__connect.release()
            return

    # Got RST packet (bare RST or RST+ACK) -> Process per RFC
    # 9293 §3.10.7.4 three-way classification via the shared
    # helper. Mirrors CLOSE_WAIT's predicate shape (commit
    # '991931e'); the helper skips the 'ack' in-range guard
    # for bare RST so both forms reach the case-1 reset path.
    # On case-1 reset the connect-event semaphore is released
    # with 'ConnError.REFUSED' so any active-open caller
    # blocked on '_event__connect.acquire()' (typical for the
    # simultaneous-open path that reaches SYN_RCVD via peer's
    # bare SYN crossing our outbound SYN) unblocks with the
    # canonical "connection refused" signal. The release on
    # an already-non-blocked semaphore is harmless
    # ('Semaphore.release()' just increments the counter), so
    # the same path applies uniformly to passive-open
    # listener-fork children where no caller is blocked.
    if packet_rx_md.tcp__flag_rst and not any(
        {
            packet_rx_md.tcp__flag_fin,
            packet_rx_md.tcp__flag_syn,
        }
    ):
        if session._check_rst_acceptability(packet_rx_md):
            session._connection_error = ConnError.REFUSED
            session._event__connect.release()
            session._change_state(FsmState.CLOSED)
