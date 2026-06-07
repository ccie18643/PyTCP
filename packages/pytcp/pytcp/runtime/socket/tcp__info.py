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


"""
This module packs a Linux-shaped 'struct tcp_info' from a
'TcpSession' snapshot for the 'getsockopt(IPPROTO_TCP,
TCP_INFO)' surface (M5 of 'socket_linux_parity_audit.md').
PyTCP also exposes the same data through 'TcpSocket.status()'
returning a 'TcpStatus' dataclass; TCP_INFO is the Linux-shaped
wire surface bolted on top so applications written against the
stdlib socket pattern (`tcp_info = struct.unpack(...,
sock.getsockopt(IPPROTO_TCP, TCP_INFO))`) see the bytes they
expect.

Field layout matches Linux include/uapi/linux/tcp.h as of
kernel 5.5 (240 bytes; without the 5.7+ tcpi_total_rto*
fields). The two bit-packed bytes — 'snd_wscale:4 |
rcv_wscale:4' and 'delivery_rate_app_limited:1 |
fastopen_client_fail:2' — are emitted as a single u8 each;
consumers extract via bit operations.

Byte order is little-endian ('<' prefix). Linux returns the
struct in CPU-native byte order; PyTCP runs on its host CPU so
the format is fixed-LE for predictability across the PyTCP
deployment surface (the dominant x86_64 / arm64 targets are
LE). Document the deviation here so a hypothetical big-endian
consumer knows to byte-swap.

pytcp/runtime/socket/tcp__info.py

ver 3.0.8
"""

import struct
from enum import IntEnum, IntFlag

from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__enums import FsmState


class TcpInfoState(IntEnum):
    """
    Linux 'include/uapi/linux/tcp.h' tcpi_state values.
    """

    # Member ordering mirrors 'enum {...}' in the kernel header
    # verbatim so a diagnostic tool consuming the byte recognises
    # the value.
    ESTABLISHED = 1
    SYN_SENT = 2
    SYN_RECV = 3
    FIN_WAIT1 = 4
    FIN_WAIT2 = 5
    TIME_WAIT = 6
    CLOSE = 7
    CLOSE_WAIT = 8
    LAST_ACK = 9
    LISTEN = 10
    CLOSING = 11


class TcpInfoOption(IntFlag):
    """
    Linux 'include/uapi/linux/tcp.h' tcpi_options bit flags.
    """

    # The values are stable kernel ABI; consumers test individual
    # bits.
    TIMESTAMPS = 1
    SACK = 2
    WSCALE = 4
    ECN = 8  # ECN negotiated at session init (RFC 3168).
    ECN_SEEN = 16  # At least one ECT segment received.
    SYN_DATA = 32  # SYN-ACK acked SYN-data (RFC 7413).


# PyTCP FsmState -> Linux tcpi_state. Every PyTCP FsmState has a
# direct Linux counterpart so the mapping is total.
_FSM_TO_TCP_INFO_STATE: dict[FsmState, TcpInfoState] = {
    FsmState.CLOSED: TcpInfoState.CLOSE,
    FsmState.LISTEN: TcpInfoState.LISTEN,
    FsmState.SYN_SENT: TcpInfoState.SYN_SENT,
    FsmState.SYN_RCVD: TcpInfoState.SYN_RECV,
    FsmState.ESTABLISHED: TcpInfoState.ESTABLISHED,
    FsmState.FIN_WAIT_1: TcpInfoState.FIN_WAIT1,
    FsmState.FIN_WAIT_2: TcpInfoState.FIN_WAIT2,
    FsmState.CLOSING: TcpInfoState.CLOSING,
    FsmState.CLOSE_WAIT: TcpInfoState.CLOSE_WAIT,
    FsmState.LAST_ACK: TcpInfoState.LAST_ACK,
    FsmState.TIME_WAIT: TcpInfoState.TIME_WAIT,
}


# Linux include/uapi/linux/tcp.h struct tcp_info layout, kernel
# 5.5 (240 bytes). Without the 5.7+ tcpi_total_rto* tail.
#
# struct tcp_info {
#     __u8    tcpi_state;
#     __u8    tcpi_ca_state;
#     __u8    tcpi_retransmits;
#     __u8    tcpi_probes;
#     __u8    tcpi_backoff;
#     __u8    tcpi_options;
#     __u8    tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;
#     __u8    tcpi_delivery_rate_app_limited:1, tcpi_fastopen_client_fail:2;
#
#     __u32   tcpi_rto;
#     __u32   tcpi_ato;
#     __u32   tcpi_snd_mss;
#     __u32   tcpi_rcv_mss;
#
#     __u32   tcpi_unacked;
#     __u32   tcpi_sacked;
#     __u32   tcpi_lost;
#     __u32   tcpi_retrans;
#     __u32   tcpi_fackets;
#
#     __u32   tcpi_last_data_sent;
#     __u32   tcpi_last_ack_sent;
#     __u32   tcpi_last_data_recv;
#     __u32   tcpi_last_ack_recv;
#
#     __u32   tcpi_pmtu;
#     __u32   tcpi_rcv_ssthresh;
#     __u32   tcpi_rtt;
#     __u32   tcpi_rttvar;
#     __u32   tcpi_snd_ssthresh;
#     __u32   tcpi_snd_cwnd;
#     __u32   tcpi_advmss;
#     __u32   tcpi_reordering;
#
#     __u32   tcpi_rcv_rtt;
#     __u32   tcpi_rcv_space;
#
#     __u32   tcpi_total_retrans;
#
#     __u64   tcpi_pacing_rate;
#     __u64   tcpi_max_pacing_rate;
#     __u64   tcpi_bytes_acked;
#     __u64   tcpi_bytes_received;
#     __u32   tcpi_segs_out;
#     __u32   tcpi_segs_in;
#
#     __u32   tcpi_notsent_bytes;
#     __u32   tcpi_min_rtt;
#     __u32   tcpi_data_segs_in;
#     __u32   tcpi_data_segs_out;
#
#     __u64   tcpi_delivery_rate;
#
#     __u64   tcpi_busy_time;
#     __u64   tcpi_rwnd_limited;
#     __u64   tcpi_sndbuf_limited;
#
#     __u32   tcpi_delivered;
#     __u32   tcpi_delivered_ce;
#
#     __u64   tcpi_bytes_sent;
#     __u64   tcpi_bytes_retrans;
#     __u32   tcpi_dsack_dups;
#     __u32   tcpi_reord_seen;
#
#     __u32   tcpi_rcv_ooopack;
#
#     __u32   tcpi_snd_wnd;
#     __u32   tcpi_rcv_wnd;
#
#     __u32   tcpi_rehash;
# };
TCP_INFO__STRUCT: str = (
    "<"  # Little-endian, no alignment padding.
    "B B B B B B B B "  # 8 u8 — state, ca_state, retransmits, probes,
    # backoff, options, wscale-packed, delivery-rate-app-limited-packed
    "I I I I "  # rto, ato, snd_mss, rcv_mss
    "I I I I I "  # unacked, sacked, lost, retrans, fackets
    "I I I I "  # last_data_sent, last_ack_sent, last_data_recv, last_ack_recv
    "I I I I I I I I "  # pmtu, rcv_ssthresh, rtt, rttvar,
    # snd_ssthresh, snd_cwnd, advmss, reordering
    "I I "  # rcv_rtt, rcv_space
    "I "  # total_retrans
    "Q Q Q Q "  # pacing_rate, max_pacing_rate, bytes_acked, bytes_received
    "I I "  # segs_out, segs_in
    "I I I I "  # notsent_bytes, min_rtt, data_segs_in, data_segs_out
    "Q "  # delivery_rate
    "Q Q Q "  # busy_time, rwnd_limited, sndbuf_limited
    "I I "  # delivered, delivered_ce
    "Q Q "  # bytes_sent, bytes_retrans
    "I I "  # dsack_dups, reord_seen
    "I "  # rcv_ooopack
    "I I "  # snd_wnd, rcv_wnd
    "I"  # rehash
)


def pack_tcp_info(session: TcpSession | None, /) -> bytes:
    """
    Pack a Linux-shaped 'struct tcp_info' snapshot from
    'session'. Returns the canonical 240-byte struct.

    When 'session' is None (a fresh socket with no associated
    TCP session) every field is zero except 'tcpi_state' which
    is set to TCP_CLOSE — matches Linux's behaviour on a
    never-connected socket.
    """

    if session is None:
        # 56 struct fields total; first is the state byte.
        return struct.pack(
            TCP_INFO__STRUCT,
            TcpInfoState.CLOSE,  # tcpi_state
            *([0] * 55),  # Every remaining field zero-padded.
        )

    info = session.tcp_info()
    state_byte = _FSM_TO_TCP_INFO_STATE[info.state]
    # 8 fixed u8 fields. Most are zero-filled — PyTCP does not
    # track these counters per-session today.
    ca_state = 0  # PyTCP exposes CcMode (CUBIC / NewReno) not
    #              the Linux open/disorder/CWR/recovery/loss
    #              CA-state machine. Zero-fill until added.
    retransmits = min(info.retransmit_count, 255)  # u8 ceiling.
    probes = 0  # Linux's keep-alive probe counter; PyTCP has
    #              a keep-alive state but the field isn't yet
    #              snapshot-exposed here.
    backoff = 0  # PyTCP's RTO backoff counter — not yet tracked
    #              as an int.

    # tcpi_options bit field (RFC 7323 / RFC 2018 / RFC 3168
    # negotiated state).
    options = TcpInfoOption(0)
    if info.send_ts:  # RFC 7323 §2 TS bilaterally negotiated.
        options |= TcpInfoOption.TIMESTAMPS
    if info.send_sack:  # RFC 2018 §2 SACK bilateral.
        options |= TcpInfoOption.SACK
    if info.snd_wsc or info.rcv_wsc:
        # WSCALE negotiated when either side's wscale is non-zero.
        options |= TcpInfoOption.WSCALE
    if info.ecn_enabled or info.accecn_enabled:
        # RFC 3168 classic ECN OR RFC 9768 AccECN negotiated.
        options |= TcpInfoOption.ECN

    # Pack snd_wscale (low nibble) + rcv_wscale (high nibble).
    wscale_byte = (info.snd_wsc & 0x0F) | ((info.rcv_wsc & 0x0F) << 4)
    # delivery_rate_app_limited:1 + fastopen_client_fail:2 +
    # reserved padding. PyTCP doesn't track either; zero-fill.
    delivery_byte = 0

    rto = info.rto_ms * 1000  # Linux uses μs.
    # tcpi_ato — delayed-ACK timeout (μs). Use the live sysctl
    # value so a runtime tune of 'tcp.delayed_ack.delay_ms' is
    # visible here without a session restart.
    from pytcp.protocols.tcp import tcp__constants

    ato = tcp__constants.TCP__DELAYED_ACK__DELAY_MS * 1000
    snd_mss = info.snd_mss
    rcv_mss = info.rcv_mss

    # Inflight / loss accounting. PyTCP tracks bytes (not
    # segments) for SND.UNA..SND.NXT; convert via snd_mss for
    # a Linux-shaped segment count.
    in_flight_bytes = max(0, info.snd_nxt - info.snd_una)
    unacked = (in_flight_bytes // snd_mss) if snd_mss > 0 else 0
    sacked = 0  # SACK scoreboard segment count — not yet
    #              snapshot-exposed.
    lost = 0
    retrans = 0
    fackets = 0  # Deprecated in Linux too; always 0.

    # 'last_*' timing scalars are Linux Δt (jiffies-ish) values
    # since the last event. PyTCP doesn't snapshot them today.
    last_data_sent = 0
    last_ack_sent = 0
    last_data_recv = 0
    last_ack_recv = 0

    # PMTU — from the engine's current MTU if active; else 0
    # (consumer-side fallback is to use IP_MTU / IPV6_MTU
    # which PyTCP already exposes).
    pmtu = info.pmtu

    rcv_ssthresh = 0
    rtt = (info.srtt_ms or 0) * 1000  # μs.
    rttvar = (info.rttvar_ms or 0) * 1000  # μs.
    # Linux 'tcpi_snd_cwnd' / 'tcpi_snd_ssthresh' are in
    # SEGMENTS (MSS-units) per the kernel ABI; PyTCP's
    # 'CcState.cwnd' / '.ssthresh' carry BYTES. Divide so the
    # struct matches Linux units exactly.
    snd_ssthresh = (info.ssthresh // snd_mss) if snd_mss > 0 else 0
    snd_cwnd = (info.cwnd // snd_mss) if snd_mss > 0 else 0
    advmss = info.rcv_mss  # Linux uses RX-side MSS here.
    reordering = 3  # Linux's TCP_FASTRETRANS_THRESH default.

    rcv_rtt = 0
    rcv_space = info.rcv_mss

    total_retrans = 0  # Cumulative — not tracked per-session.

    # Pacing / bytes counters — PyTCP doesn't track these. The
    # delivery-rate / busy / sndbuf counters land at 0 for the
    # same reason.
    pacing_rate = 0
    max_pacing_rate = 0
    bytes_acked = 0
    bytes_received = 0
    segs_out = 0
    segs_in = 0

    # 'notsent_bytes' — bytes in the application buffer not yet
    # transmitted. Approximated as the tx buffer length minus
    # the amount already in flight; clamp at 0.
    notsent_bytes = max(0, info.tx_buffer_len - in_flight_bytes)
    min_rtt = rtt  # No min-tracker; current RTT as proxy.
    data_segs_in = 0
    data_segs_out = 0

    delivery_rate = 0
    busy_time = 0
    rwnd_limited = 0
    sndbuf_limited = 0

    delivered = 0
    delivered_ce = 0

    bytes_sent = 0
    bytes_retrans = 0
    dsack_dups = info.dsack_received
    reord_seen = 0

    rcv_ooopack = 0

    snd_wnd = info.snd_wnd
    rcv_wnd = info.rcv_wnd_max  # The receive-window ceiling.

    rehash = 0

    return struct.pack(
        TCP_INFO__STRUCT,
        # 8 u8.
        state_byte,
        ca_state,
        retransmits,
        probes,
        backoff,
        options,
        wscale_byte,
        delivery_byte,
        # 4 u32.
        rto,
        ato,
        snd_mss,
        rcv_mss,
        # 5 u32.
        unacked,
        sacked,
        lost,
        retrans,
        fackets,
        # 4 u32 'last_*'.
        last_data_sent,
        last_ack_sent,
        last_data_recv,
        last_ack_recv,
        # 8 u32 metrics.
        pmtu,
        rcv_ssthresh,
        rtt,
        rttvar,
        snd_ssthresh,
        snd_cwnd,
        advmss,
        reordering,
        # 2 u32.
        rcv_rtt,
        rcv_space,
        # 1 u32.
        total_retrans,
        # 4 u64.
        pacing_rate,
        max_pacing_rate,
        bytes_acked,
        bytes_received,
        # 2 u32.
        segs_out,
        segs_in,
        # 4 u32.
        notsent_bytes,
        min_rtt,
        data_segs_in,
        data_segs_out,
        # 1 u64.
        delivery_rate,
        # 3 u64.
        busy_time,
        rwnd_limited,
        sndbuf_limited,
        # 2 u32.
        delivered,
        delivered_ce,
        # 2 u64.
        bytes_sent,
        bytes_retrans,
        # 2 u32.
        dsack_dups,
        reord_seen,
        # 1 u32.
        rcv_ooopack,
        # 2 u32.
        snd_wnd,
        rcv_wnd,
        # 1 u32.
        rehash,
    )
