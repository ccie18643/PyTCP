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
This module contains the TCP FSM LISTEN state handler.

pytcp/protocols/tcp/fsm/tcp__fsm__listen.py

ver 3.0.8
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from net_addr import IpVersion
from net_proto.protocols.tcp.tcp__header import TCP__MIN_MSS
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
from pytcp.protocols.tcp.tcp__seq import add32

if TYPE_CHECKING:
    from pytcp.protocols.tcp.session import TcpSession
    from pytcp.protocols.tcp.tcp__icmp_metadata import IcmpMetadata
    from pytcp.socket.tcp__metadata import TcpMetadata


def fsm__listen__icmp(session: TcpSession, metadata: IcmpMetadata) -> None:
    """
    TCP FSM LISTEN state ICMP-error handler.

    A passive listener has no per-flow flight to abort and no blocked
    CONNECT to wake on; ICMP errors received against a LISTEN session
    are purely informational. Log only.
    """

    __debug__ and log(
        "tcp-ss",
        f"[{session}] - <ly>[{session._state}]</> - got ICMP "
        f"category={metadata.category.name} type={metadata.icmp_type} "
        f"code={metadata.icmp_code} (LISTEN no-op)",
    )


def fsm__listen__syscall(session: TcpSession, syscall: SysCall) -> None:
    """
    TCP FSM LISTEN state syscall handler.

    Got CLOSE syscall -> Change state to CLOSED.
    """

    if syscall is SysCall.CLOSE:
        session._change_state(FsmState.CLOSED)


def fsm__listen__packet(session: TcpSession, packet_rx_md: TcpMetadata) -> None:
    """
    TCP FSM LISTEN state packet handler.
    """

    from pytcp.protocols.tcp.session import TcpSession
    from pytcp.socket import AddressFamily
    from pytcp.socket.tcp__socket import TcpSocket

    # Got SYN packet -> Send SYN + ACK packet / change state to SYN_RCVD.
    if all({packet_rx_md.tcp__flag_syn}) and not any(
        {
            packet_rx_md.tcp__flag_ack,
            packet_rx_md.tcp__flag_fin,
            packet_rx_md.tcp__flag_rst,
        }
    ):
        # Packet sanity check. RFC 9293 §3.10.7.2 step 3 explicitly
        # permits piggybacked data on the initial SYN ("any other
        # incoming control or data (combined with SYN) will be
        # processed in the SYN-RECEIVED state"), so the data field
        # is intentionally NOT gated here; it is queued into the
        # child session's receive buffer below.
        if packet_rx_md.tcp__ack == 0:
            # Accept-queue admission gate (POSIX 'listen(backlog)'
            # semantics). When the parent listening socket's
            # accept queue is at capacity, drop the SYN silently.
            # The peer's TCP will retransmit the SYN per its
            # standard retry cycle; if the application has
            # drained a slot via 'accept()' by the time the
            # retransmit lands, the handshake completes
            # normally. Linux and BSD both default to silent
            # drop on overflow (POSIX leaves the choice
            # implementation-defined). The cap protects the
            # listening process from accept-queue exhaustion -
            # one of the oldest TCP-stack DoS classes -
            # without requiring application changes.
            # pylint: disable=protected-access
            accept_q_len = len(session._socket._tcp_accept)
            accept_q_cap = session._socket._backlog
            if accept_q_len >= accept_q_cap:
                __debug__ and log(
                    "tcp-ss",
                    f"[{session}] - Accept queue full " f"({accept_q_len}/{accept_q_cap}); " "dropping SYN silently",
                )
                return
            # pylint: enable=protected-access
            # Listener fork pattern (RFC 9293 §3.10.7.2). The
            # current 'session' object is the LISTEN-state session.
            # On peer's SYN we mutate it IN PLACE into the new
            # connection's child session (rebinding its 4-tuple
            # to the peer below) and create a FRESH session that
            # takes over the listening role on the original
            # socket. The result: one peer-specific child session
            # transitioning to SYN_RCVD, plus an unchanged
            # listening session ready to accept the next SYN.
            # The pivot relies on TcpSocket / TcpSession holding
            # mutable references to each other - callers that
            # cached 'listen_socket._tcp_session' BEFORE the SYN
            # arrived must re-resolve it after the drive.
            # Capture the listening parent socket reference BEFORE
            # the in-place pivot below clobbers 'session._socket'.
            # Both the fresh listening session and the new child
            # socket inherit RFC 1122 §4.2.3.6 SO_KEEPALIVE from
            # this parent.
            listen_socket = session._socket
            tcp_session = TcpSession(
                local_ip_address=session._local_ip_address,
                local_port=session._local_port,
                remote_ip_address=session._remote_ip_address,
                remote_port=session._remote_port,
                socket=listen_socket,
            )
            tcp_session.listen()
            # Inherit SO_KEEPALIVE on the fresh listening session
            # so each subsequent accept fork carries the flag too.
            tcp_session._keepalive.enabled = listen_socket._so_keepalive
            # Inherit per-connection keep-alive overrides too.
            tcp_session._keepalive.idle_override = listen_socket._tcp_keepidle
            tcp_session._keepalive.interval_override = listen_socket._tcp_keepintvl
            tcp_session._keepalive.max_count_override = listen_socket._tcp_keepcnt
            # RFC 9438 §1: inherit the CC algorithm selector
            # from the listening socket.
            tcp_session._cc.cc_mode = listen_socket._cc_mode
            # RFC 1122 §4.2.3.4: inherit the Nagle disable
            # flag.
            tcp_session._tcp_nodelay = listen_socket._tcp_nodelay
            session._socket._tcp_session = tcp_session  # pylint: disable=protected-access
            # Re-bind 'session' to the peer's 4-tuple and create a
            # new TcpSocket that exposes this child session to
            # the application's eventual 'accept()' caller.
            session._local_ip_address = packet_rx_md.ip__local_address
            session._local_port = packet_rx_md.tcp__local_port
            session._remote_ip_address = packet_rx_md.ip__remote_address
            session._remote_port = packet_rx_md.tcp__remote_port
            session._socket = TcpSocket(  # pyright: ignore[reportAttributeAccessIssue]
                family=(
                    AddressFamily.INET6 if session._local_ip_address.version == IpVersion.IP6 else AddressFamily.INET4
                ),
                tcp_session=session,
            )
            # H3 Phase 3c — dual-stack presentation flag. When the
            # listening parent is AF_INET6 with 'IPV6_V6ONLY = 0'
            # AND the accepted peer is IPv4 (the inbound metadata
            # is IPv4), mark the child so the application-facing
            # accessors ('local_ip_address' / 'remote_ip_address' /
            # 'family' / 'getsockname' / 'getpeername' / accept()
            # return tuple) surface the IPv4 addresses as their
            # IPv4-mapped IPv6 form. The wire attributes stay
            # AF_INET4 so the RX-path active-socket lookup keeps
            # matching the inbound IPv4 packets.
            if (
                listen_socket._address_family is AddressFamily.INET6
                and not listen_socket._ipv6_v6only
                and session._local_ip_address.version is IpVersion.IP4
            ):
                session._socket._dual_stack = True
            # POSIX accept(2) inherits the listener's O_NONBLOCK
            # onto the accepted child. Propagate the listener's
            # 'setblocking()' flag onto the freshly-constructed
            # child socket; the eventual 'accept()' caller re-
            # applies it in case the listener has flipped after
            # the listener-fork (covers both timing windows).
            session._socket._blocking = listen_socket._blocking
            # Propagate SO_KEEPALIVE from the listening parent
            # onto the new child socket so a future
            # 'getsockopt(SO_KEEPALIVE)' on the accept()'d child
            # round-trips correctly. The per-connection overrides
            # follow the same path so 'getsockopt(TCP_KEEPIDLE)'
            # etc. also round-trip.
            session._socket._so_keepalive = listen_socket._so_keepalive
            session._socket._tcp_keepidle = listen_socket._tcp_keepidle
            session._socket._tcp_keepintvl = listen_socket._tcp_keepintvl
            session._socket._tcp_keepcnt = listen_socket._tcp_keepcnt
            # RFC 9438 §1: child socket and its session inherit
            # the CC mode from the listening parent.
            session._socket._cc_mode = listen_socket._cc_mode
            session._cc.cc_mode = listen_socket._cc_mode
            # RFC 1122 §4.2.3.4: child socket / session inherit
            # the Nagle disable flag.
            session._socket._tcp_nodelay = listen_socket._tcp_nodelay
            session._tcp_nodelay = listen_socket._tcp_nodelay
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
            session._win.snd_wnd = packet_rx_md.tcp__win
            # WSCALE bilateral negotiation per RFC 7323 §2.2:
            # passive-open mirrors peer's offer. If peer's SYN
            # carries WSCALE AND we are configured to advertise,
            # store peer's wscale as '_snd_wsc' (we WILL emit
            # WSCALE on the SYN+ACK we send next). Otherwise,
            # both directions clear to 0 - peer's non-offer
            # forces us to non-offer too.
            if session._advertise.wscale and packet_rx_md.tcp__wscale:
                session._win.snd_wsc = packet_rx_md.tcp__wscale
            else:
                session._win.rcv_wsc = 0
                session._win.snd_wsc = 0
            # SACK bilateral negotiation per RFC 2018 §2:
            # passive-open mirrors peer's offer. SACK is
            # enabled iff we are configured to advertise AND
            # peer's SYN carried SACK-Permitted. The flag
            # gates both the SYN+ACK we emit next (which
            # carries SACK-Permitted iff '_send_sack') and
            # subsequent SACK-option emission on outbound
            # ACKs over an OOO-buffered queue.
            session._advertise.send_sack = session._advertise.sack and packet_rx_md.tcp__sackperm
            # RFC 7323 §3 bilateral negotiation: enable TSopt
            # on our SYN+ACK and all subsequent segments iff we
            # advertise AND peer's SYN carried TSopt. Cache
            # peer's TSval as '_ts_recent' so the SYN+ACK we
            # emit next echoes it via TSecr.
            if session._advertise.ts and packet_rx_md.tcp__tsval is not None:
                session._ts.send_ts = True
                session._ts.ts_recent = packet_rx_md.tcp__tsval
                # RFC 7323 §5.5 outdated-timestamps mitigation:
                # stamp the local clock at every TS.Recent
                # update so the helper can detect 24-day idle
                # later. Initial seed at handshake bootstrap.
                session._ts.ts_recent_updated_at_ms = stack.timer.now_ms
            # RFC 9768 §3.1.1 / §3.1.3 / RFC 3168 §6.1.1
            # bilateral ECN/AccECN negotiation. The canonical
            # AccECN-setup SYN carries (AE,CWR,ECE)=(1,1,1);
            # classic RFC 3168 SYN carries (0,1,1). Per
            # §3.1.3 forward-compatibility, ANY other
            # combination of AE/CWR/ECE on the SYN MUST be
            # treated as AccECN-setup so installed servers
            # stay forward-compatible with future TCP
            # extensions. The three combinations explicitly
            # excluded from the AccECN bucket are:
            #   (0,0,0): No ECN
            #   (0,1,1): Classic ECN
            #   (1,1,1): canonical AccECN (handled below)
            # Mutually exclusive: at most one of
            # '_accecn_enabled' / '_ecn_enabled' is set.
            ns = packet_rx_md.tcp__flag_ns
            cwr = packet_rx_md.tcp__flag_cwr
            ece = packet_rx_md.tcp__flag_ece
            is_classic_ecn_syn = (not ns) and cwr and ece
            any_ecn_bit = ns or cwr or ece
            if session._advertise.accecn and any_ecn_bit and not is_classic_ecn_syn:
                session._accecn.enabled = True
                session._accecn.synack_codepoint = packet_rx_md.ip__ecn
            elif session._advertise.ecn and is_classic_ecn_syn:
                session._ecn.enabled = True
            # RFC 7413 §3.1 Fast Open server-side cookie
            # issuance + validation, gated on the listening
            # socket's '_tcp_fastopen_qlen > 0' (the
            # application opt-in via 'setsockopt(IPPROTO_TCP,
            # TCP_FASTOPEN, qlen)'). When the listening
            # socket has not opted in, the inbound TFO option
            # is silently ignored - cookie is not issued,
            # cookie validation does not run, SYN-data is
            # subject to the RFC 9293 §3.10.7.2 default. This
            # matches Linux's TFO-disabled-by-default
            # semantics and gives the application a clear
            # opt-in switch.
            #
            # Two outcomes when peer's SYN carries the TFO
            # option AND the listener has opted in:
            #   - Always issue a fresh cookie back in the
            #     SYN+ACK so peer can cache and replay it on
            #     a subsequent connection.
            #   - Validate the inbound cookie; if it matches
            #     the HMAC we would issue for this peer's IP,
            #     accept any SYN-piggybacked data; otherwise
            #     discard it (the §4.1.2 amplification-attack
            #     defence).
            # RFC 7413 §4.2 PendingFastOpenRequests gate: when
            # the in-flight TFO-accepted SYN-RCVD count meets
            # or exceeds the configured 'fastopen_qlen' limit,
            # disable TFO acceptance for this incoming SYN so
            # the client falls back to plain 3WHS. The counter
            # is incremented below on TFO acceptance and
            # decremented from '_change_state' on transition
            # out of SYN_RCVD.
            tfo_enabled = (
                listen_socket._tcp_fastopen_qlen > 0
                and stack.tcp_stack.fastopen_pending() < listen_socket._tcp_fastopen_qlen
            )
            tfo_cookie_valid = False
            if tfo_enabled and packet_rx_md.tcp__fastopen_cookie is not None:
                from pytcp.protocols.tcp.tcp__fastopen import generate_cookie, validate_cookie

                if packet_rx_md.tcp__fastopen_cookie:
                    tfo_cookie_valid = validate_cookie(
                        peer_address=packet_rx_md.ip__remote_address,
                        secret=stack.TCP__FASTOPEN_SECRET,
                        cookie=bytes(packet_rx_md.tcp__fastopen_cookie),
                    )
                session._fastopen.cookie_to_emit = generate_cookie(
                    peer_address=packet_rx_md.ip__remote_address,
                    secret=stack.TCP__FASTOPEN_SECRET,
                )
            # SYN-data acceptance gate: per RFC 7413 §3.1, if
            # the TFO option is present-but-invalid (or empty
            # cookie-request form) the data MUST be discarded;
            # the receiver falls back to standard 3WHS. When
            # the option is absent altogether, the RFC 9293
            # §3.10.7.2 default applies (data is processed).
            # When TFO is disabled at the listener, the
            # 'tfo_enabled' check below treats the option as
            # absent and falls back to the RFC 9293 default.
            tfo_option_relevant = tfo_enabled and packet_rx_md.tcp__fastopen_cookie is not None
            accept_syn_data = (not tfo_option_relevant) or tfo_cookie_valid
            syn_data = packet_rx_md.tcp__data if accept_syn_data else memoryview(b"")
            session._rcv_seq.ini = packet_rx_md.tcp__seq
            session._cc.cwnd = session._win.snd_mss
            session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)
            # Make note of the remote SEQ number, advancing past the
            # SYN's one byte AND every byte of any piggybacked payload
            # so the SYN+ACK we emit acknowledges the data and the
            # peer does not have to retransmit it (RFC 9293 §3.10.7.2
            # step 3).
            session._rcv_seq.nxt = add32(
                packet_rx_md.tcp__seq,
                packet_rx_md.tcp__flag_syn,
                len(syn_data),
            )
            # Mark peer as contacted so the R2-abort RST
            # gate in '_retransmit_packet_timeout' fires
            # the RST even when 'RCV.NXT' happens to equal
            # 0 (peer's ISN was 0xFFFF_FFFF, modular wrap).
            session._peer_contacted = True
            if syn_data:
                session._enqueue_rx_buffer(syn_data)
                __debug__ and log(
                    "tcp-ss",
                    f"[{session}] - Queued {len(syn_data)} bytes "
                    "of SYN-piggybacked data for delivery after ESTABLISHED",
                )
            # RFC 7413 §4.2: increment the PendingFastOpenRequests
            # count when this SYN is accepted via the TFO fast
            # path (cookie validated). The count is decremented
            # in '_change_state' on transition out of SYN_RCVD.
            if tfo_cookie_valid:
                stack.tcp_stack.incr_fastopen_pending()
                session._fastopen.pending_counted = True
            # Change state to SYN_RCVD; the actual SYN+ACK packet
            # is emitted from that state on the next timer tick by
            # '_transmit_data', which detects 'SND.NXT == SND.INI'
            # in SYN_RCVD and fires the SYN+ACK.
            session._change_state(FsmState.SYN_RCVD)
