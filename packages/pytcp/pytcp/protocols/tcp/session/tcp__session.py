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
This module contains the class supporting TCP finite state machine.

pytcp/protocols/tcp/session/tcp__session.py

ver 3.0.8
"""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, override

from net_addr import Ip4Address, Ip6Address
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.tcp import tcp__constants
from pytcp.protocols.tcp.fsm import dispatch_icmp as tcp_fsm_dispatch_icmp
from pytcp.protocols.tcp.fsm import dispatch_packet as tcp_fsm_dispatch_packet
from pytcp.protocols.tcp.fsm import dispatch_syscall as tcp_fsm_dispatch_syscall
from pytcp.protocols.tcp.fsm import dispatch_timer as tcp_fsm_dispatch_timer
from pytcp.protocols.tcp.session.tcp__session__ack import TcpAckProcessor
from pytcp.protocols.tcp.session.tcp__session__retransmit import TcpRetransmitter
from pytcp.protocols.tcp.session.tcp__session__timers import TcpTimerService
from pytcp.protocols.tcp.session.tcp__session__tx import TcpTxEngine
from pytcp.protocols.tcp.session.tcp__session__validate import TcpSegmentValidator
from pytcp.protocols.tcp.state.tcp__state__accecn import AccEcnState
from pytcp.protocols.tcp.state.tcp__state__advertise import AdvertiseState
from pytcp.protocols.tcp.state.tcp__state__cc import CcState
from pytcp.protocols.tcp.state.tcp__state__ecn_classic import ClassicEcnState
from pytcp.protocols.tcp.state.tcp__state__fastopen import FastOpenState
from pytcp.protocols.tcp.state.tcp__state__keepalive import KeepaliveState
from pytcp.protocols.tcp.state.tcp__state__persist import PersistState
from pytcp.protocols.tcp.state.tcp__state__rack_tlp import RackTlpState
from pytcp.protocols.tcp.state.tcp__state__recv_seq import RecvSeqState
from pytcp.protocols.tcp.state.tcp__state__rtt_sample import RttSampleState
from pytcp.protocols.tcp.state.tcp__state__send_seq import SendSeqState
from pytcp.protocols.tcp.state.tcp__state__shutdown import ShutdownState
from pytcp.protocols.tcp.state.tcp__state__timestamps import TimestampsState
from pytcp.protocols.tcp.state.tcp__state__tx_buffer import TxBufferState
from pytcp.protocols.tcp.state.tcp__state__window import WindowState
from pytcp.protocols.tcp.tcp__cwnd import compute_ecn_event_ssthresh
from pytcp.protocols.tcp.tcp__enums import (
    CcMode,
    ConnError,
    FsmState,
    SysCall,
)
from pytcp.protocols.tcp.tcp__errors import TcpSessionError
from pytcp.protocols.tcp.tcp__hystart import (
    enter_css,
    resume_slow_start,
    should_exit_slow_start_to_css,
    should_resume_slow_start_from_css,
)
from pytcp.protocols.tcp.tcp__icmp_metadata import IcmpMetadata
from pytcp.protocols.tcp.tcp__iss import compute_iss
from pytcp.protocols.tcp.tcp__plpmtud_adapter import TcpPlpmtudAdapter
from pytcp.protocols.tcp.tcp__rack import RackSegment
from pytcp.protocols.tcp.tcp__rto import RtoState, initial_state
from pytcp.protocols.tcp.tcp__sack import SackScoreboard
from pytcp.protocols.tcp.tcp__seq import Seq32, le32, lt32, sub32
from pytcp.stack import sysctl_iface

if TYPE_CHECKING:
    from threading import Event, Lock, RLock, Semaphore

    from pytcp.runtime.socket.tcp__metadata import TcpMetadata
    from pytcp.runtime.socket.tcp__socket import TcpSocket


# Name of the per-session 'tx_pump' FSM-pump logical timer
# (§5.6/§5.7). The §4.3 scope matrix mapping FSM-state to the
# set of logical timers that may wake the session lives on the
# service module 'session/tcp__session__timers.py' alongside
# the '_reschedule_locked' helper that consumes it.
_PUMP: str = "tx_pump"


class TcpSession:
    """
    The TCP session.
    """

    def __init__(
        self,
        *,
        local_ip_address: Ip6Address | Ip4Address,
        local_port: int,
        remote_ip_address: Ip6Address | Ip4Address,
        remote_port: int,
        socket: TcpSocket,
    ) -> None:
        """
        Initialize the TCP session.
        """

        ###
        # Parameters derived from the socket.
        ###

        self._local_ip_address: Ip6Address | Ip4Address = local_ip_address
        self._local_port: int = local_port
        self._remote_ip_address: Ip6Address | Ip4Address = remote_ip_address
        self._remote_port: int = remote_port

        # Keeps track of the socket that owns this session for
        # the session -> socket communication purposes.
        self._socket: TcpSocket = socket

        ###
        # Buffers.
        ###

        # Keeps data received from peer and not received by application yet.
        self._rx_buffer: bytearray = bytearray()

        # TX-side buffer state (raw byte buffer, seq-anchor for
        # buffer-index ↔ sequence-number mapping, fast-retransmit
        # dup-ACK request counter). See 'state/tcp__state__tx_buffer.py'.
        self._tx: TxBufferState = TxBufferState()

        # RFC 9293 §3.4 receive-side seq state (IRS / RCV.NXT /
        # RCV.UNA). Anchored at handshake time via
        # 'self._rcv_seq.reset_to(irs=peer_isn)' once peer's SYN
        # is observed. See 'state/tcp__state__recv_seq.py'.
        self._rcv_seq: RecvSeqState = RecvSeqState()

        # IP+TCP header overhead for MSS calculation. RFC 8200's
        # IPv6 fixed header is 40 bytes (vs IPv4's 20); the TCP
        # header is 20 bytes regardless. The MSS is the largest
        # TCP segment that fits in 'interface_mtu' once both
        # headers are subtracted.
        self._ip_tcp_overhead: int = (40 if isinstance(local_ip_address, Ip6Address) else 20) + 20

        # RFC 9293 §3.7.1 / RFC 7323 §2.3 / RFC 9293 §3.8.4 /
        # RFC 5961 §5 window state container (snd_mss, snd_wnd,
        # snd_wsc, max_window, rcv_mss, rcv_wsc, rcv_wnd_max).
        # See 'state/tcp__state__window.py'.
        self._win: WindowState = WindowState()
        self._win.rcv_mss = self._egress_interface_mtu() - self._ip_tcp_overhead

        # RFC 4821 / RFC 8899 per-session PLPMTUD adapter.
        # Wraps a PmtuSearch engine bound to the remote
        # address's family floor and tracks in-flight probe
        # segments for ACK / loss detection. Lazily mirrors
        # into 'stack.pmtu_state' on first classical PMTU
        # signal (via '_apply_pmtu_update') so per-destination
        # state is shared across sessions to the same peer.
        self._plpmtud_adapter: TcpPlpmtudAdapter = TcpPlpmtudAdapter(
            remote_ip_address=remote_ip_address,
            interface_mtu=self._egress_interface_mtu(),
        )
        # Linux 'net.ipv4.tcp_mtu_probing' tristate sysctl —
        # the operator-facing enable for active PLPMTUD probing
        # ('tcp.mtu_probing' = 0 off / 2 always-on; mode 1
        # deferred per the close-out plan §2). The flag is
        # consulted by the probe-emit hook in
        # 'session/tcp__session__tx.py' AND by '_mss_ceiling'
        # below so the handshake clamp keeps 'snd_mss' under
        # 'base_mss - overhead' instead of rising to
        # 'interface_mtu - overhead' — the gap that the
        # cold-start path closes.
        _probing_mode = sysctl_iface.get_for_iface(
            "tcp.mtu_probing",
            self._egress_interface_name(),
        )
        self._plpmtud_probing_enabled: bool = _probing_mode != 0
        # Linux 'net.ipv4.tcp_base_mss' cold-start seed. With
        # probing enabled, prime 'snd_mss' below
        # 'interface_mtu - overhead' so the engine's
        # 'candidate_mtu > snd_mss' probe-emit gate trips
        # on the first data send. Without this seed
        # 'snd_mss' would saturate at 'interface_mtu -
        # overhead' (the engine's '_max_mtu' ceiling) and
        # the gate would never fire — RFC 4821 §3 'Probing
        # without ICMP' unreachable. The handshake clamp
        # sites (FSM listen / syn_sent / syn_sent-reuse /
        # validate-rfc6191-reuse) consult '_mss_ceiling()'
        # so peer-advertised MSS does NOT raise 'snd_mss'
        # back above the seed.
        if self._plpmtud_probing_enabled:
            self._win.snd_mss = self._mss_ceiling()

        # Whether to advertise WSCALE on this session's outbound
        # SYN / SYN+ACK. Defaults True (the modern, throughput-
        # friendly behaviour); test code or constrained-buffer
        # profiles can opt out by setting False before CONNECT
        # / LISTEN. When False, the bilateral-non-offer rule
        # forces '_rcv_wsc = 0' on handshake completion so the
        # post-handshake outbound 'win' is not shifted either.
        # Per-session option-advertise + SACK-active state.
        # Defaults: all 'advertise_*' flags True (modern,
        # throughput-friendly), 'send_sack' False until
        # handshake bilaterally negotiates SACK-Permitted. See
        # 'state/tcp__state__advertise.py' for per-field rationale.
        self._advertise: AdvertiseState = AdvertiseState()
        # RFC 7323 §2 / §4.3 / §5.5 Timestamps state (send_ts
        # bilateral-success flag, ts_recent peer-TSval tracker,
        # ts_recent_updated_at_ms staleness clock). See
        # 'state/tcp__state__timestamps.py'.
        self._ts: TimestampsState = TimestampsState()

        # RFC 9293 §3.8.4 / RFC 1122 §4.2.3.6 keep-alive state
        # (enabled flag, unanswered-probe counter, three
        # setsockopt-equivalent override knobs, lazy-arm gate).
        # See 'state/tcp__state__keepalive.py' for the full
        # per-field rationale. Defaults to disabled per the
        # RFC's MUST.
        self._keepalive: KeepaliveState = KeepaliveState()

        # SACK scoreboard tracking peer-SACKed-but-not-yet-
        # cumulatively-acked send-side ranges per RFC 2018 §3 /
        # RFC 6675 §3. Updated by '_ingest_sack_info' on every
        # ACK that carries a SACK option (gated on
        # '_send_sack'); pruned by '_prune_sack_scoreboard'
        # when SND.UNA advances. Phase 5 will consult it via
        # 'pytcp.protocols.tcp.tcp__loss_recovery' for NextSeg / IsLost /
        # Pipe.
        self._sack_scoreboard: SackScoreboard = SackScoreboard()

        # Per-session congestion-control variables (cwnd, ssthresh,
        # snd_ewn, recovery_point, recover_seq, PRR counters, F-RTO
        # snapshot, CUBIC curve, HyStart++ state). Lives as one
        # coherent object on 'tcp__state__cc.py'. Primary CC fields
        # (cwnd / snd_ewn) are initialised below once 'snd_mss' is
        # known; everything else uses the dataclass's RFC-anchored
        # defaults.
        self._cc: CcState = CcState()

        # RFC 7413 per-session TFO state (cookie pending emission,
        # PendingFastOpenRequests counter flag, SYN-retransmit
        # bypass sentinel). Stack-wide TFO state lives on
        # 'pytcp.stack.tcp_stack' (TcpStack). See
        # 'state/tcp__state__fastopen.py'.
        self._fastopen: FastOpenState = FastOpenState()

        # RFC 7413 §3.1 Fast Open client-side opt-out flag.
        # The fastopen, ecn, accecn advertise flags live on
        # self._advertise (AdvertiseState) above.

        # RFC 3168 classic ECN per-session state (enabled flag,
        # send_ece receiver-echo, send_cwr sender-confirmation,
        # recovery_point one-shot gate). Mutually exclusive with
        # 'self._accecn.enabled' per RFC 9768 §3.1.1. See
        # 'state/tcp__state__ecn_classic.py' for per-field rationale.
        self._ecn: ClassicEcnState = ClassicEcnState()

        # RFC 9768 AccECN per-session state (negotiation flag,
        # codepoint capture, receiver/sender byte counters, ACE
        # encoding state, last-emit tracker, mangling sentinel).
        # Defaults are RFC-anchored on the dataclass — see
        # 'tcp__state__accecn.py' for the full per-field rationale.
        self._accecn: AccEcnState = AccEcnState()

        # F-RTO state, CUBIC F-RTO snapshot, and the FR-CUBIC
        # snapshot all live on 'self._cc' (CcState).
        # Defaults are RFC-anchored on the dataclass; no per-field
        # init needed here.

        # Classic ECN sender + receiver state moved to
        # 'self._ecn' (ClassicEcnState) above.

        # RFC 2883 DSACK: when peer retransmits data we already
        # received (fully-duplicate segment OR overlap prefix of
        # a partially-duplicate segment) we record the duplicate
        # range here so the next outbound ACK's SACK option
        # carries it as the FIRST block. 'None' means no DSACK
        # is pending. 'Build' clears it after consumption.
        self._pending_dsack: tuple[Seq32, Seq32] | None = None

        # Counter of inbound DSACK occurrences detected by the
        # sender side. Incremented in '_ingest_sack_info' when
        # the first SACK block looks like a DSACK marker (right
        # edge below SND.UNA OR contained within a later block).
        # Useful for spurious-retransmit observability; phase 7
        # does not yet wire it into RTO / cwnd.
        self._dsack_received: int = 0

        # RFC 8985 RACK + TLP per-session state (per-segment
        # scoreboard, RACK scalars, fold-tracker set, reorder-
        # window state, DSACK round marker, TLP arming state).
        # Defaults are RFC-anchored on the dataclass — see
        # 'tcp__state__rack_tlp.py' for the full per-field
        # rationale.
        self._rack_tlp: RackTlpState = RackTlpState()

        # RFC 6298 §2 RTO estimator state plus the single-pending-
        # sample tracker that drives '_rto_state' updates per
        # §4 ("one sample per RTT"). The hooks live in
        # '_transmit_packet' (record fresh sample), in
        # '_process_ack_packet' (harvest on covering ACK and run
        # 'update' iff Karn's flag is False), and in
        # '_retransmit_packet_timeout' (set Karn's flag per §3 on
        # the in-flight sample). 'rto_ms' drives the session-level
        # 'f"{self}-retransmit"' timer; on each timeout fire,
        # '_retransmit_packet_timeout' applies 'back_off' (§5.5)
        # and re-arms with the new value. The R2 abort counter
        # ('_retransmit_count') tracks consecutive timeouts since
        # the last cum-ACK that advanced SND.UNA; cleared on
        # progress in '_process_ack_packet'.
        self._rto_state: RtoState = initial_state()
        # RFC 6298 §4 single-pending RTT-sample tracker plus the
        # §5.7 idle-baseline 'last_send_time_ms'. See
        # 'state/tcp__state__rtt_sample.py'.
        self._rtt: RttSampleState = RttSampleState()
        self._retransmit_count: int = 0
        # RFC 6298 §5.7 second-clause SYN-retransmit counter.
        # Decoupled from '_retransmit_count' (which
        # '_process_ack_packet' resets on cum-ACK progress per
        # §5.2 / §5.3) so the post-handshake §5.7 floor check
        # is order-independent: the count survives the
        # SND.UNA-advancing handshake-completing ACK and is
        # observable from the ESTABLISHED-transition sites in
        # both '_tcp_fsm_syn_sent' (active open) and
        # '_tcp_fsm_syn_rcvd' (passive / simultaneous open).
        # Incremented in '_retransmit_packet_timeout' iff the
        # session is currently in {SYN_SENT, SYN_RCVD}.
        self._syn_retransmit_count: int = 0
        # 'last_send_time_ms' moved onto self._rtt above.

        ###
        # Sending window parameters.
        ###

        # Initial sequence number per RFC 6528 §3: hash of the
        # 4-tuple plus a stack-wide secret, plus a monotonically
        # advancing 'M' clock. Defends against blind sequence-
        # number injection by binding the ISN to the 4-tuple so
        # an attacker who learns one ISN cannot infer ISNs for
        # other connections; the time-driven M component prevents
        # replay of stale ISNs against fresh connections.
        # RFC 9293 §3.4 send-side seq state (ISS / SND.UNA /
        # SND.NXT / SND.MAX) plus RFC 9293 §3.10.7.4 FIN seq +
        # 'fin_sent' gate plus the RFC 1122 §4.2.3.4 Nagle/Minshall
        # partial-segment seq. Anchored to the freshly-computed
        # ISS via 'reset_to'; see 'state/tcp__state__send_seq.py'
        # for the full per-field rationale.
        iss = compute_iss(
            local_address=local_ip_address,
            local_port=local_port,
            remote_address=remote_ip_address,
            remote_port=remote_port,
            secret=stack.TCP__ISS_SECRET,
            clock_us=time.monotonic_ns() // 1000,
        )
        self._snd_seq: SendSeqState = SendSeqState()
        self._snd_seq.reset_to(iss=iss)

        # 'True' once any segment has been processed from peer
        # (peer's SYN in the passive-open path, peer's SYN+ACK
        # in the active-open path). Gates the R2-abort RST
        # emission so an aborting session that DID hear from
        # peer signals the abort even when 'RCV.NXT' happens to
        # equal 0 (which it does when peer's ISN was exactly
        # 0xFFFF_FFFF and 'add32(peer_isn, 1)' wraps). Without
        # the explicit flag, the previous 'self._rcv_seq.nxt > 0'
        # gate would suppress the RST whenever peer's ISN hit
        # the wrap-point sentinel - probability 2**-32 but a
        # real correctness gap.
        self._peer_contacted: bool = False

        # Conservative-start defaults for snd_wnd / max_window:
        # one SMSS (not 0, not 65535) so the first segment can
        # fire before peer's ACK reveals the real window size.
        # Updated by '_process_ack_packet' on every accepted ACK.
        self._win.snd_wnd = self._win.snd_mss
        self._win.max_window = self._win.snd_mss

        # Initialise the RFC 5681 cwnd and 'snd_ewn' from
        # 'win.snd_mss' now that the MSS is known. 'ssthresh'
        # keeps the dataclass default. See 'state/tcp__state__cc.py'.
        self._cc.cwnd = self._win.snd_mss
        self._cc.snd_ewn = self._win.snd_mss

        # CUBIC curve state ('cubic_w_max', 'cubic_K_ms', etc.) and
        # 'cc_mode' live on 'self._cc'. Override the algorithm per
        # connection via 'setsockopt(IPPROTO_TCP, TCP_CONGESTION,
        # CcMode.RENO.value)'; the dataclass default mirrors
        # Linux's CUBIC-since-2.6.18.

        # 'snd_wsc' lives on self._win and defaults to 0 there
        # (the canonical "initial SYN / SYN+ACK don't use WSCALE"
        # value). Set to peer's WSCALE value at handshake by
        # the FSM SYN_SENT / SYN_RCVD entries.

        # Nagle/Minshall partial-segment seq lives on the SendSeqState
        # dataclass; reset_to(iss=...) above already anchored it.

        # RFC 1122 §4.2.3.4 Nagle disable. When True, the
        # Nagle defer in '_transmit_data' is skipped and
        # partial segments fire immediately. Settable via the
        # BSD socket API:
        # 'setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)'. Default
        # False (Nagle enabled per RFC 1122 SHOULD).
        self._tcp_nodelay: bool = False

        # Linux 'TCP_USER_TIMEOUT' per-connection R2-abort
        # override (ms). 0 means "no override — use the
        # 'tcp.retransmit.max_count' system-default budget".
        # When > 0 the retransmit-timeout site converts the ms
        # budget to a count via 'budget = max(1,
        # _user_timeout_ms // current_rto_ms)' so the abort
        # fires after the user's wall-time budget elapses
        # under the current RTO. PyTCP's count-based machinery
        # approximates Linux's time-based 'tcp_time_stamp -
        # tp->retrans_stamp' check; an exact time-based
        # implementation would need an additional
        # 'first_unacked_at_ms' tracker that the cum-ACK path
        # would have to maintain — out of scope for the
        # M6 surgery. Propagated from
        # 'TcpSocket._tcp_user_timeout' at connect() /
        # listen() time. M6 of
        # 'socket_linux_parity_audit.md'.
        self._user_timeout_ms: int = 0

        # Linux 'TCP_MAXSEG' per-connection SYN MSS-option
        # clamp (bytes). 0 means "no clamp — emit our usual
        # rcv_mss in the SYN's MSS option". When > 0 the
        # SYN-options assembly clamps the emitted MSS to no
        # more than this value. Propagated from
        # 'TcpSocket._tcp_maxseg' at connect() / listen() time.
        # M7 of 'socket_linux_parity_audit.md'.
        self._maxseg_override: int = 0

        # Zero-window persist timer state per RFC 9293 §3.8.6.1.
        # '_persist_active' is the sentinel that tells the timer
        # branch in '_tcp_fsm_established' whether a persist probe
        # is scheduled. False means "no probe pending" (we last
        # saw a non-zero peer window); True means "armed and
        # counting down toward the next zero-window probe". The
        # flag flips True when peer advertises 'tcp__win == 0' on
        # an ACK while we still have data to send; it flips False
        # when peer reopens the window. '_persist_timeout' carries
        # the current back-off interval (initial =
        # tcp__constants.TCP__RTO__INITIAL_MS, doubled per probe up to
        # tcp__constants.TCP__PERSIST__TIMEOUT_MAX_MS).
        self._persist: PersistState = PersistState()
        self._persist.timeout = tcp__constants.TCP__RTO__INITIAL_MS

        # Number of in-order data segments received since we last transmitted
        # an ACK. Tracks the RFC 1122 §4.2.3.2 "ACK every other segment"
        # rule: when this reaches 2 we force an inline ACK rather than
        # waiting for the delayed-ACK timer to fire.
        self._delayed_ack_segments_pending: int = 0

        # BSD-socket half-close flags per RFC 9293 §3.9.1 + POSIX
        # 'shutdown()'. '_shut_rd' silently discards subsequent
        # inbound data and makes 'recv()' return 0 once the buffer
        # drains. '_shut_wr' triggers FIN emission (same effect as
        # 'close()' on the write side) but leaves '_shut_rd'
        # untouched so the receive side stays open.
        self._shut: ShutdownState = ShutdownState()

        ###
        # Other variables.
        ###

        # tx_retransmit_request_counter and tx_buffer_seq_mod
        # both moved onto self._tx (TxBufferState) above. Anchor
        # the seq_mod baseline at the freshly-computed ISS.
        self._tx.seq_mod = self._snd_seq.ini

        # TCP FSM (Finite State Machine) state.
        self._state: FsmState = FsmState.CLOSED

        # Wakes the blocked CONNECT syscall once the FSM has reached
        # a terminal handshake outcome (ESTABLISHED, refused, or
        # timed out). 'Semaphore(0)' rather than 'threading.Event'
        # because we want the wake-up to be one-shot per CONNECT
        # call: 'Event' stays set, so a second CONNECT would
        # observe a stale signal; 'Semaphore' counts releases and
        # acquires, naturally consuming the signal.
        self._event__connect: Semaphore = threading.Semaphore(0)

        # Used to inform RECV syscall that there is new data in buffer ready
        # to be picked up.
        self._event__rx_buffer: Event = threading.Event()

        # Set when the FSM reaches CLOSED so a blocking lingering
        # close() (SO_LINGER {l_onoff=1, l_linger>0}) wakes as soon as
        # the connection is fully torn down rather than sleeping the
        # full linger timeout. Set from '_change_state'; in a running
        # stack the RX / timer threads drive the transition while the
        # application thread waits in 'TcpSocket.close'.
        # Phase: no-GIL — 'threading.Event' is self-synchronizing
        # (its internal Condition/Lock is the cross-thread barrier);
        # set on the terminal CLOSED state and never cleared, so no
        # lock and no lost/stale-wakeup window. See
        # no_gil_thread_safety_audit.md §5.
        self._event__closed: Event = threading.Event()

        # Used to ensure that only single event can run FSM at given time.
        self._lock__fsm: RLock = threading.RLock()

        # Used to ensure only single event has access to RX buffer at given time.
        self._lock__rx_buffer: Lock = threading.Lock()

        # Used to ensure only single event has access to TX buffer at given time.
        self._lock__tx_buffer: Lock = threading.Lock()

        # Indicates that CLOSE syscall is in progress, this lets to finish
        # sending data before FIN packet is transmitted.
        self._closing: bool = False

        # Out of order packet buffer.
        self._ooo_packet_queue: dict[int, TcpMetadata] = {}

        # Used to report cause of connection failure.
        self._connection_error: ConnError = ConnError.NONE

        # Per-session timer service — owns the logical-timer
        # deadline map ('_deadlines') and the coalesced service
        # handle ('_service_handle') plus the dedicated lock
        # ('_lock') that guards both. The FSM timer is
        # event-driven — there is no 1 ms periodic. The coalesced
        # service handle (armed by 'TcpTimerService._reschedule_locked'
        # from every public mutator and from the 'tcp_fsm' tail
        # via 'self._timers.reschedule()') drives both
        # logical-timer servicing and the 'tx_pump' FSM-pump
        # (§5.6/§5.7). Closes the no-GIL backlog item T2: the
        # deadline-map mutations no longer ride the FSM lock.
        # Lock ordering for the rest of the session is
        # '_lock__fsm' -> '_timers._lock' -> 'stack.timer._lock';
        # the timer-worker callback re-enters 'tcp_fsm' lock-free.
        self._timers: TcpTimerService = TcpTimerService(self)

        # Per-session TX engine — owns the outbound-segment
        # construction pipeline ('_transmit_packet' + the six
        # '_phase0..5' helpers), the buffered-data send pump
        # ('_transmit_data'), the delayed-ACK emit
        # ('_delayed_ack'), the SACK option builder
        # ('_build_sack_blocks'), and the RFC 5961
        # rate-limited challenge-ACK emit
        # ('_emit_challenge_ack'). Phase 2 of the TcpSession
        # god-class decomposition.
        self._tx_engine: TcpTxEngine = TcpTxEngine(self)

        # Per-session inbound-ACK processor — owns the five-
        # phase 'process_ack_packet' pipeline (cum-ACK side
        # effects, F-RTO spurious-RTO detection, RTT-sample
        # harvest, loss-detection + recovery-exit, segment
        # consume + delayed-ACK postprocess). Phase 3 of the
        # TcpSession god-class decomposition.
        self._ack_processor: TcpAckProcessor = TcpAckProcessor(self)

        # Per-session segment validator — owns the read-mostly
        # acceptability checks (RFC 9293 §3.10.7.4 step 1
        # segment acceptability, RFC 7323 §5 PAWS + §4.3
        # '_ts_recent' refresh, RFC 9293 / RFC 5961 §3.2 RST
        # acceptability, RFC 5927 §4 ICMP-embedded-seq
        # acceptability) plus the RFC 6191 §3 4-tuple-reuse
        # re-initialisation helper. Phase 4 of the TcpSession
        # god-class decomposition.
        self._validator: TcpSegmentValidator = TcpSegmentValidator(self)

        # Per-session retransmitter — owns the RFC 6298 §5 RTO
        # timeout path, the RFC 5681 §3.2 / RFC 6675 §3 fast-
        # retransmit-request path, the RFC 8985 §7.3 Tail Loss
        # Probe firing path, and the RFC 8985 §6.2 RACK
        # reorder-window + per-ACK update helpers. Phase 5
        # (final) of the TcpSession god-class decomposition.
        self._retransmitter: TcpRetransmitter = TcpRetransmitter(self)

    def _egress_interface_mtu(self) -> int:
        """
        Return the link MTU of the interface that egresses toward this
        session's remote — the per-destination input to MSS computation
        (RFC 6691 §2). Falls back to the default link MTU when no egress
        can be resolved (a reduced context with no interface registered),
        preserving the value the retired 'stack.interface_mtu' global held.
        """

        return stack.egress_interface_mtu(self._remote_ip_address) or stack.INTERFACE__TAP__MTU

    def _egress_interface_name(self) -> str | None:
        """
        Return the name of the interface that egresses toward this
        session's remote — the per-iface sysctl key the cold-start
        PLPMTUD path consults to resolve 'tcp.mtu_probing' and
        'tcp.base_mss'. Returns None when no FIB route covers the
        destination (mirrors '_egress_interface_mtu'); the per-iface
        lookup then falls through to the '"default"' template slot.
        """

        return stack.egress_interface_name(self._remote_ip_address)

    def _mss_ceiling(self) -> int:
        """
        Return the effective send-side MSS ceiling consumed by both
        the cold-start seed in '__init__' and the four handshake
        clamp sites (FSM listen / syn_sent / syn_sent-reuse /
        validate-rfc6191-reuse).

        When PLPMTUD active probing is disabled (the default), the
        ceiling is 'interface_mtu - overhead' — same value the
        handshake clamp used pre-Phase-2.

        When probing is enabled, the ceiling shrinks to
        'min(base_mss, interface_mtu) - overhead' so the engine has
        upward-probing headroom. The 'min' guards against a
        pathological operator config that raises 'tcp.base_mss'
        above the egress interface MTU; the seed always stays at
        or below the link ceiling so probes have somewhere to
        climb to.

        Reference: RFC 4821 §3 (Probing without ICMP).
        Reference: Linux 'tcp_mtu_probing=2' MSS-ceiling semantics.
        """

        iface_ceiling = self._egress_interface_mtu() - self._ip_tcp_overhead
        if not self._plpmtud_probing_enabled:
            return iface_ceiling
        base_mss: int = sysctl_iface.get_for_iface(
            "tcp.base_mss",
            self._egress_interface_name(),
        )
        return min(base_mss - self._ip_tcp_overhead, iface_ceiling)

    def _arm_timer(self, name: str, delay_ms: int, /) -> None:
        """
        Arm or re-arm the named logical timer to fire 'delay_ms'
        milliseconds from now. Thin delegator over
        'TcpTimerService.arm' — the deadline-map mutation +
        coalesced-service reschedule are serialized under the
        service's own '_lock'.
        """

        self._timers.arm(name, delay_ms)

    def _timer_expired(self, name: str, /) -> bool:
        """
        Return True iff the named logical timer is armed and its
        deadline has passed. An unarmed timer is NOT expired:
        'never armed' and 'fired' are distinct states (see
        '_timer_armed' for the complementary 'still running?'
        query).
        """

        return self._timers.expired(name)

    def _timer_armed(self, name: str, /) -> bool:
        """
        Return True iff the named logical timer is armed and has
        not yet fired (the 'is it still running?' query).
        """

        return self._timers.armed(name)

    def _cancel_timer(self, name: str, /) -> None:
        """
        Cancel the named logical timer if armed. Thin delegator
        over 'TcpTimerService.cancel'.
        """

        self._timers.cancel(name)

    def _cancel_all_timers(self) -> None:
        """
        Cancel every logical timer for this session and release
        the coalesced service handle. The session-teardown sweep
        that drops all of this session's armed timers in one call.
        Thin delegator over 'TcpTimerService.cancel_all'.
        """

        self._timers.cancel_all()

    def _reschedule_service(self) -> None:
        """
        Re-arm the coalesced per-session service handle to the
        soonest deadline among the logical timers serviced in
        the current state. Thin delegator over
        'TcpTimerService.reschedule' — kept on the session as a
        named hook for the rare external caller that needs to
        re-poke the schedule after an out-of-band state change.
        """

        self._timers.reschedule()

    def _has_pump_work(self) -> bool:
        """
        True while the FSM still needs the 1 ms pacing pump:
        unsent buffered data ('_transmit_data' dribbles one
        segment per tick), in-flight data (FIN/retransmit
        progression), or a pending close. When none hold — and
        no logical timer is armed — the session is genuinely
        idle and the pump stops (zero-idle-CPU). delayed-ACK /
        keep-alive / RACK / TLP / persist / TIME_WAIT need no
        entry here: each is a logical timer the coalesced
        '_service_handle' already drives.
        """

        return bool(self._tx.buffer) or self._snd_seq.una != self._snd_seq.max or self._closing

    def _pump_tail(self, state_at_entry: FsmState, external: bool, /) -> None:
        """
        Re-arm the 'tx_pump' FSM-pump (1 ms) at the 'tcp_fsm'
        tail while the FSM still needs ticking. The old 1 ms
        periodic was not merely an event-wake — it was a
        continuous send-pacing clock: '_transmit_data' emits one
        segment per tick, so a multi-segment send needs a tick
        per segment until the buffer drains. Re-pump iff this
        dispatch was an external stimulus (packet / syscall /
        ICMP), changed state, OR there is still pending pacing
        work ('_has_pump_work'). A fully quiescent TIMER
        dispatch (no state change, not external, no pump work)
        does NOT re-pump → zero-idle-CPU. The 1 ms delay (plus
        the 1 ms floor in '_reschedule_service') reproduces the
        periodic's exactly-one-tick-per-millisecond cadence, so
        active transfer is byte-identical. CLOSED is terminal —
        never re-pumped.
        """

        self._cancel_timer(_PUMP)
        if self._state is FsmState.CLOSED:
            return
        if external or self._state is not state_at_entry or self._has_pump_work():
            self._arm_timer(_PUMP, 1)

    def _kick_pump(self) -> None:
        """
        Arm the 'tx_pump' FSM-pump from a NON-'tcp_fsm' mutator
        (§5.7). 'TcpSession.send()' extends the TX buffer
        without routing through 'tcp_fsm', so '_pump_tail' never
        runs to pick up the buffered data; the old 1 ms periodic
        masked this by ticking unconditionally. Audit (Phase 4c,
        confirmed by the Phase-4b full-suite run whose only
        residual was send()-path): the sole non-'tcp_fsm'
        FSM-progression mutator is 'send()'; listen / connect /
        close / shutdown route through 'tcp_fsm', and receive /
        abort need no pump. No-op once CLOSED. Takes the
        'TcpTimerService' lock via '_arm_timer' (the deadline
        map's dedicated guard); the '_state' read is a single
        attribute read whose worst-case outcome on a torn
        transition is one extra pump tick that no-ops in the
        CLOSED branch of the next FSM dispatch — benign.
        """

        if self._state is not FsmState.CLOSED:
            self._arm_timer(_PUMP, 1)

    @override
    def __str__(self) -> str:
        """
        Get the TCP session string representation.
        """

        return f"{self._local_ip_address}/{self._local_port}/{self._remote_ip_address}/{self._remote_port}"

    @property
    def local_ip_address(self) -> Ip6Address | Ip4Address:
        """
        Get the '_local_ip_address' attribute.
        """

        return self._local_ip_address

    @property
    def remote_ip_address(self) -> Ip6Address | Ip4Address:
        """
        Get the '_remote_ip_address' attribute.
        """

        return self._remote_ip_address

    @property
    def local_port(self) -> int:
        """
        Get the '_local_port' attribute.
        """

        return self._local_port

    @property
    def remote_port(self) -> int:
        """
        Get the '_remote_port' attribute.
        """

        return self._remote_port

    @property
    def socket(self) -> TcpSocket:
        """
        Get the '_socket' attribute.
        """

        return self._socket

    @property
    def state(self) -> FsmState:
        """
        Get the '_state' attribute.
        """

        return self._state

    @property
    def _rcv_wnd(self) -> int:
        """
        Get the current receive-window advertisement: the configured
        maximum minus bytes currently sitting in '_rx_buffer'. The
        advertised window MUST shrink as inbound data accumulates so
        the peer's flow-control loop can throttle their send rate
        when the application is slow to consume (RFC 9293 §3.8.6).
        """

        return max(0, self._win.rcv_wnd_max - len(self._rx_buffer))

    @property
    def _tx_buffer_nxt(self) -> int:
        """
        Get the 'snd_nxt' number relative to TX buffer.

        Uses modular subtraction (RFC 9293 §3.4) so the returned
        offset is correct across the 32-bit wrap. Plain integer
        subtraction yields a large negative when 'snd_nxt' has
        wrapped past 'tx_buffer_seq_mod' (e.g. snd_nxt=3,
        seq_mod=0xFFFF_FFFF -> raw diff=-0xFFFF_FFFC, modular
        diff=4); the legacy 'max(diff, 0)' clamp would then
        wrongly yield 0 and the next 'transmit_data' call would
        try to re-send the already-sent prefix.
        """

        return (self._snd_seq.nxt - self._tx.seq_mod) & 0xFFFF_FFFF

    @property
    def _tx_buffer_una(self) -> int:
        """
        Get the 'snd_una' number relative to TX buffer.
        """

        return (self._snd_seq.una - self._tx.seq_mod) & 0xFFFF_FFFF

    def listen(self) -> None:
        """
        The 'LISTEN' syscall.
        """

        __debug__ and log(
            "tcp-ss",
            f"[{self}] - <ly>[{self._state}]</> - got <r>LISTEN</> syscall",
        )

        self.tcp_fsm(syscall=SysCall.LISTEN)

    def connect(self) -> None:
        """
        The 'CONNECT' syscall.
        """

        __debug__ and log(
            "tcp-ss",
            f"[{self}] - <ly>[{self._state}]</> - got <r>CONNECT</> syscall",
        )

        self.tcp_fsm(syscall=SysCall.CONNECT)
        self._event__connect.acquire()
        if self._state is not FsmState.ESTABLISHED and self._connection_error is ConnError.REFUSED:
            raise TcpSessionError("Connection refused")
        if self._state is not FsmState.ESTABLISHED and self._connection_error is ConnError.TIMEOUT:
            raise TcpSessionError("Connection timeout")
        if self._state is not FsmState.ESTABLISHED and self._connection_error is ConnError.CANCELED:
            raise TcpSessionError("Connection canceled")

    def send(self, *, data: bytes) -> int:
        """
        The 'SEND' syscall.
        """

        # RFC 9293 §3.10.6: once the application has called CLOSE,
        # any subsequent SEND must be rejected with a closing-error
        # response. The state-only check below is not enough because
        # 'close()' is deferred - it sets '_closing = True' but does
        # not transition the FSM out of ESTABLISHED until the next
        # timer tick after the TX buffer drains. Without this guard,
        # the post-close-but-pre-tick window would silently accept
        # writes that get serialised onto the wire ahead of the FIN.
        if self._closing or self._shut.wr:
            raise TcpSessionError("TCP session is closing")

        if self._state in {FsmState.ESTABLISHED, FsmState.CLOSE_WAIT}:
            with self._lock__tx_buffer:
                self._tx.buffer.extend(data)
            # Kick the FSM pump OUTSIDE '_lock__tx_buffer' (the
            # 'tcp_fsm' lock order is _lock__fsm -> _lock__tx_buffer;
            # taking _lock__fsm while holding _lock__tx_buffer here
            # would invert it and deadlock).
            self._kick_pump()
            return len(data)

        # This error should be raised when session is locally or fully closed.
        raise TcpSessionError("TCP session not in ESTABLISHED or CLOSE_WAIT state")

    def receive(self, *, byte_count: int | None = None, timeout: float | None = None) -> bytes:
        """
        The 'RECEIVE' syscall.
        """

        # Wait till there is any data in the buffer (this will get bypassed
        # when FSM goes into CLOSE_WAIT or CLOSED).
        if not self._event__rx_buffer.wait(timeout=timeout):
            raise TimeoutError("TCP session receive operation timed out while waiting for data.")

        # If there is no data in RX buffer and remote end closed connection
        # then notify application by returning empty byte string.
        if not self._rx_buffer and self._state in {
            FsmState.CLOSE_WAIT,
            FsmState.CLOSED,
        }:
            return b""

        with self._lock__rx_buffer:
            if byte_count is None:
                byte_count = len(self._rx_buffer)
            else:
                byte_count = min(byte_count, len(self._rx_buffer))

            rx_buffer = self._rx_buffer[:byte_count]
            del self._rx_buffer[:byte_count]

            # Clear the event only when the buffer is fully drained
            # AND the remote end is still open. When the remote
            # closed (CLOSE_WAIT or CLOSED), leave the event set so
            # the next 'receive()' returns 'b""' immediately - the
            # BSD-socket EOF semantics, where a connection-closed
            # state must be re-readable as zero bytes without
            # blocking the caller.
            if not self._rx_buffer and self._state not in {
                FsmState.CLOSE_WAIT,
                FsmState.CLOSED,
            }:
                self._event__rx_buffer.clear()
                # Drain the eventfd backing 'socket.fileno()' so the
                # next selector tick stops firing once the buffer is
                # empty. CLOSE_WAIT / CLOSED are deliberately
                # excluded so peer-FIN EOF stays select-readable as
                # a 0-byte recv() until the application closes its
                # half (matches BSD select-on-read-EOF semantics).
                self._socket._drain_readable()

        return bytes(rx_buffer)

    def close(self) -> None:
        """
        The 'CLOSE' syscall.
        """

        __debug__ and log(
            "tcp-ss",
            f"[{self}] - <ly>[{self._state}]</> - got <r>CLOSE</> syscall, {len(self._tx.buffer)} bytes in TX buffer",
        )

        self.tcp_fsm(syscall=SysCall.CLOSE)

    def shutdown(self, *, how: int) -> None:
        """
        BSD 'shutdown(how)' half-close per RFC 9293 §3.9.1
        + POSIX shutdown semantics.

        'how' values (matching pytcp.runtime.socket.SHUT_*):
            SHUT_RD   (0): no further reads. Inbound data is
                           silently discarded; recv() returns 0
                           after the buffer drains.
            SHUT_WR   (1): no further writes. Drains the TX
                           buffer and emits FIN (same effect as
                           close() on the write side); the read
                           side stays open until peer's FIN.
            SHUT_RDWR (2): both. Equivalent to close().

        Idempotent: shutdown() on a direction already shut is a
        no-op. Setting SHUT_WR on an already-closing session
        does NOT re-emit FIN.
        """

        assert how in (0, 1, 2), f"shutdown 'how' must be in {{SHUT_RD, SHUT_WR, SHUT_RDWR}}; got {how}."

        # SHUT_RD or SHUT_RDWR: discard subsequent inbound data
        # and unblock any pending recv() with end-of-stream.
        if how in (0, 2):
            if not self._shut.rd:
                self._shut.rd = True
                # Wake any blocked recv() so it observes the
                # shutdown and returns 0 (the FSM check + empty
                # buffer makes recv() yield empty bytes).
                self._event__rx_buffer.set()
                self._socket._signal_readable()
                __debug__ and log("tcp-ss", f"[{self}] - shutdown(SHUT_RD): receive side closed")

        # SHUT_WR or SHUT_RDWR: trigger FIN emission via the
        # existing close() machinery if not already closing.
        if how in (1, 2):
            if not self._shut.wr and not self._closing:
                self._shut.wr = True
                self.tcp_fsm(syscall=SysCall.CLOSE)
                __debug__ and log("tcp-ss", f"[{self}] - shutdown(SHUT_WR): send side closed")

    def abort(self) -> None:
        """
        The 'ABORT' syscall per RFC 9293 §3.9.1.

        Aborts the connection without graceful close: any pending
        SENDs are discarded, blocked RECEIVEs are released with
        an error, and a RST is emitted for synchronized states
        (SYN_RCVD, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2,
        CLOSE_WAIT). For unsynchronized states (CLOSED, LISTEN,
        SYN_SENT) and the post-close states (CLOSING, LAST_ACK,
        TIME_WAIT), the TCB is simply torn down without a wire-
        level RST per RFC 9293 §3.9.1's per-state ABORT spec.

        After abort() the session transitions to CLOSED and any
        blocked CONNECT / RECEIVE callers unblock with a connection
        error.
        """

        __debug__ and log(
            "tcp-ss",
            f"[{self}] - <ly>[{self._state}]</> - got <r>ABORT</> syscall",
        )

        if self._state in {
            FsmState.SYN_RCVD,
            FsmState.ESTABLISHED,
            FsmState.FIN_WAIT_1,
            FsmState.FIN_WAIT_2,
            FsmState.CLOSE_WAIT,
        }:
            # RFC 9293 §3.9.1 ABORT in synchronized states: emit
            # RST + ACK at SND.NXT, RCV.NXT.
            self._transmit_packet(flag_rst=True, flag_ack=True, seq=self._snd_seq.nxt)
        # Mark connection as aborted so any blocked recv() raises.
        self._connection_error = ConnError.CANCELED
        self._event__rx_buffer.set()
        self._socket._signal_readable()
        self._event__connect.release()
        self._change_state(FsmState.CLOSED)

    def is_seq_in_window(self, seq: int) -> bool:
        """
        Return True when 'seq' falls in the SND.UNA..SND.NXT range
        (RFC 5927 §4 ICMP-embedded-seq acceptability). Thin
        delegator over 'TcpSegmentValidator.is_seq_in_window'.
        """

        return self._validator.is_seq_in_window(seq)

    def _apply_pmtu_update(self, *, next_hop_mtu: int, ip_version: int) -> None:
        """
        Apply an inbound ICMP Path-MTU update to this session.
        Records the next-hop MTU into 'stack.pmtu_cache' for the
        remote address and recomputes 'self._win.snd_mss' from the
        new MTU minus IP+TCP fixed overhead. Called from the
        per-state ICMP handlers ('fsm__syn_sent__icmp' and
        'fsm__icmp__synchronized') for PMTU-category events.

        Implements the optional RFC 1191 §6.5 retransmit walkback:
        when the snd_mss shrink leaves in-flight segments oversized
        for the new path MTU, mark all in-flight segments lost and
        rewind 'snd_nxt' to 'snd_una' so the next timer tick re-emits
        from snd_una at the new (smaller) MSS rather than waiting for
        RTO. Unlike RTO, the walkback does NOT halve cwnd / ssthresh
        and does NOT bump '_retransmit_count' or back off RTO — the
        path narrowed but did not congest, so this is not a loss event.

        Reference: RFC 1191 §6 (PMTUD on the host).
        Reference: RFC 1191 §6.5 (PMTU shrink retransmit walkback).
        Reference: RFC 8201 §4 (IPv6 PMTUD MTU update rule).
        Reference: RFC 9293 §3.7.5 (MSS option update on path-MTU change).
        """

        # Fixed-overhead floor: IPv4 = 20, IPv6 = 40; TCP = 20.
        ip_overhead = 20 if ip_version == 4 else 40
        new_mss = max(next_hop_mtu - ip_overhead - 20, 0)
        # RFC 1191 §6.4 / RFC 791 §3.1 MIN_MTU floor: never let MSS
        # drop below 536 / 1280 on v4 / v6 respectively. The remote
        # peer's MSS option from the handshake is also a ceiling, so
        # only shrink, never grow.
        floor = 536 - 20 if ip_version == 4 else 1280 - 40 - 20
        new_mss = max(new_mss, floor)
        shrunk = new_mss < self._win.snd_mss
        if shrunk:
            self._win.snd_mss = new_mss

        stack.record_classical_pmtu(self._remote_ip_address, next_hop_mtu)

        # Route the classical PMTU signal through the per-session
        # PLPMTUD adapter (which dispatches to the engine), then
        # mirror the engine into the shared 'stack.pmtu_state'
        # registry so siblings to the same destination see the
        # same state.
        now = time.monotonic()
        self._plpmtud_adapter.on_classical_pmtu(next_hop_mtu, now=now)
        stack.record_pmtu_engine(self._remote_ip_address, self._plpmtud_adapter.engine)

        # RFC 1191 §6.5 walkback. Only fire when (a) the MSS actually
        # shrunk and (b) at least one in-flight segment is oversized
        # for the new MSS — single small segments that already fit
        # don't need walking back.
        if shrunk and any(
            (seg.end_seq - seq) & 0xFFFF_FFFF > new_mss for seq, seg in self._rack_tlp.rack_segments.items()
        ):
            from pytcp.protocols.tcp.tcp__rack import INFINITE_TS

            self._rack_tlp.rack_segments = {
                seq: RackSegment(
                    end_seq=seg.end_seq,
                    xmit_ts=INFINITE_TS,
                    retransmitted=seg.retransmitted,
                    lost=True,
                )
                for seq, seg in self._rack_tlp.rack_segments.items()
            }
            self._snd_seq.nxt = self._snd_seq.una
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - <ly>RFC 1191 §6.5 walkback: snd_mss -> "
                f"{new_mss}, snd_nxt rewound to snd_una "
                f"({self._snd_seq.una})</>",
            )

    def _change_state(self, state: FsmState) -> None:
        """
        Change the state of TCP finite state machine.
        """

        old_state = self._state
        self._state = state
        __debug__ and log(
            "tcp-ss",
            f"[{self}] - <ly>[{old_state} -> {self._state}]</>",
        )

        # RFC 6675 §5 RecoveryPoint is meaningful only inside the
        # ESTABLISHED loss-recovery loop. Clear on any transition
        # out of ESTABLISHED so post-half-close 'send()' that
        # experiences loss can re-enter recovery in the new state
        # without being inhibited by the stale marker. The
        # in-'_process_ack_packet' clearing only fires when
        # SND.UNA crosses the marker, which may not happen if
        # peer's transition-driving segment did not advance the
        # cum-ACK far enough (e.g. peer FIN with no cum-ACK
        # progress).
        if old_state is FsmState.ESTABLISHED and state is not FsmState.ESTABLISHED:
            self._cc.recovery_point = 0
            # RFC 6937 §3.1 PRR per-recovery state lives only
            # while a recovery episode is active in ESTABLISHED.
            # Clear alongside RecoveryPoint so half-close and
            # subsequent re-entries start clean.
            self._cc.recover_fs = 0
            self._cc.prr_delivered = 0
            self._cc.prr_out = 0

        # RFC 7413 §3.1 Fast Open server-side cookie state is
        # only meaningful while the session is in SYN_RCVD
        # awaiting the third-leg ACK. Once the handshake
        # completes (ESTABLISHED) or the session aborts (any
        # other terminal state), no further SYN+ACK will
        # fire so the cookie is no longer needed. Clear on
        # any transition out of SYN_RCVD.
        if old_state is FsmState.SYN_RCVD and state is not FsmState.SYN_RCVD:
            self._fastopen.cookie_to_emit = None
            # RFC 7413 §4.2: decrement the global pending-TFO
            # counter when this session leaves SYN_RCVD (either
            # the handshake completes -> ESTABLISHED, or it
            # aborts -> CLOSED). The '_fastopen_pending_counted'
            # guard ensures we only decrement for sessions that
            # were actually counted at TFO acceptance time.
            if self._fastopen.pending_counted:
                stack.tcp_stack.decr_fastopen_pending()
                self._fastopen.pending_counted = False

        # Unregister session.
        if self._state is FsmState.CLOSED:
            # Wake any lingering close() blocked on the
            # close-complete event (SO_LINGER {l_onoff=1,
            # l_linger>0}).
            self._event__closed.set()
            stack.sockets.unregister(self._socket)
            # Cancel every per-session logical timer and release
            # the coalesced service handle so nothing fires
            # against a dead session and it is GC-eligible (the
            # event-driven model has no periodic to unregister).
            self._cancel_all_timers()
            __debug__ and log("tcp-ss", f"[{self}] - Unregister associated socket")

        # RFC 1122 §4.2.3.6: arm the keep-alive idle timer on the
        # transition into ESTABLISHED (no-op when keep-alive is
        # disabled). Done here rather than in 'fsm__syn_sent' /
        # 'fsm__syn_rcvd' / 'fsm__listen' so all three handshake
        # paths share a single arm site.
        if state is FsmState.ESTABLISHED:
            self._keepalive_arm_idle()

    def _transmit_packet(
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
        Send out the TCP packet. Thin delegator over
        'TcpTxEngine.transmit_packet' — the segment-construction
        pipeline (the six phase helpers) lives on the TX engine.
        """

        self._tx_engine.transmit_packet(
            seq=seq,
            flag_syn=flag_syn,
            flag_ack=flag_ack,
            flag_fin=flag_fin,
            flag_rst=flag_rst,
            flag_psh=flag_psh,
            data=data,
        )

    def _build_sack_blocks(self) -> list[tuple[int, int]]:
        """
        Compute the SACK option block list for the next outbound
        ACK. Thin delegator over 'TcpTxEngine.build_sack_blocks'.
        """

        return self._tx_engine.build_sack_blocks()

    def _check_segment_acceptability(self, packet_rx_md: TcpMetadata) -> bool:
        """
        RFC 9293 §3.10.7.4 step 1 receive-window acceptability
        check. Thin delegator over
        'TcpSegmentValidator.check_segment_acceptability'.
        """

        return self._validator.check_segment_acceptability(packet_rx_md)

    def _check_paws_and_update_ts_recent(self, packet_rx_md: TcpMetadata) -> bool:
        """
        RFC 7323 §5 PAWS + §4.3 '_ts_recent' refresh. Thin
        delegator over
        'TcpSegmentValidator.check_paws_and_update_ts_recent'.
        """

        return self._validator.check_paws_and_update_ts_recent(packet_rx_md)

    def _check_rst_acceptability(self, packet_rx_md: TcpMetadata) -> bool:
        """
        RFC 9293 §3.10.7.4 / RFC 5961 §3.2 three-way RST handling.
        Thin delegator over
        'TcpSegmentValidator.check_rst_acceptability'.
        """

        return self._validator.check_rst_acceptability(packet_rx_md)

    def _reinit_for_rfc6191_reuse(self, packet_rx_md: TcpMetadata) -> None:
        """
        RFC 6191 §3 TIME-WAIT 4-tuple reuse re-initialisation.
        Thin delegator over
        'TcpSegmentValidator.reinit_for_rfc6191_reuse'.
        """

        self._validator.reinit_for_rfc6191_reuse(packet_rx_md)

    def _hystart_check_phase_transition(self) -> None:
        """
        Apply the RFC 9406 §4.2 phase-transition checks after
        a fresh RTT sample has been folded into the HyStart++
        state. Two transitions are possible:

          - Slow-start -> CSS: the §4.2 delay-increase trigger
            fires (currentRoundMinRTT exceeds lastRoundMinRTT
            by more than RttThresh) — record the baseline and
            switch to Conservative Slow Start.
          - CSS -> Slow-start: the §4.2 spurious-CSS-exit
            check fires (currentRoundMinRTT drops below the
            CSS-entry baseline) — clear CSS state and resume
            normal slow-start.

        Caller MUST have folded the RTT sample BEFORE calling
        this helper. Called from both the TSecr-driven RTTM
        site and the Karn sample-tracker harvest site.

        Reference: RFC 9406 §4.2 (delay-increase trigger / spurious-exit recovery).
        """

        if should_exit_slow_start_to_css(self._cc.hystart_state):
            enter_css(self._cc.hystart_state)
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - RFC 9406 §4.2 HyStart++ SS->CSS: "
                f"currentRoundMinRTT="
                f"{self._cc.hystart_state.current_round_min_rtt_ms} >= "
                f"lastRoundMinRTT="
                f"{self._cc.hystart_state.last_round_min_rtt_ms} + RttThresh; "
                f"baseline={self._cc.hystart_state.css_baseline_min_rtt_ms}",
            )
        elif should_resume_slow_start_from_css(self._cc.hystart_state):
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - RFC 9406 §4.2 HyStart++ CSS->SS: "
                f"currentRoundMinRTT="
                f"{self._cc.hystart_state.current_round_min_rtt_ms} < "
                f"cssBaselineMinRtt="
                f"{self._cc.hystart_state.css_baseline_min_rtt_ms}; "
                "early CSS exit was spurious, resuming slow-start",
            )
            resume_slow_start(self._cc.hystart_state)

    def _emit_challenge_ack(self) -> None:
        """
        RFC 5961 §3 / §4 rate-limited challenge-ACK emission.
        Thin delegator over 'TcpTxEngine.emit_challenge_ack'.
        """

        self._tx_engine.emit_challenge_ack()

    def _keepalive_arm_idle(self) -> None:
        """
        (Re)arm the keep-alive idle timer per RFC 1122 §4.2.3.6.

        Called from any code path that observes peer activity (an
        inbound data segment, an inbound ACK, or our own outbound
        transmission - peer's eventual response will reset the
        timer naturally) and from '_change_state' on the transition
        into ESTABLISHED. No-op when '_keepalive_enabled' is False.
        Resetting also clears the unanswered-probe counter so a
        fresh idle window starts from zero.
        """

        if not self._keepalive.enabled:
            return
        self._keepalive.reset_for_idle()
        self._arm_timer(
            "keepalive",
            self._keepalive.idle_timeout(default=tcp__constants.TCP__KEEPALIVE__IDLE_TIME_MS),
        )

    def _keepalive_tick(self) -> None:
        """
        Per-tick keep-alive timer service.

        Called from the synchronized-state FSM timer branch
        (currently ESTABLISHED only). When the keep-alive timer
        fires, either emit another probe or - if
        'TCP__KEEPALIVE__PROBE_MAX_COUNT' probes have already gone
        unanswered - tear the connection down per RFC 1122
        §4.2.3.6. The probe wire shape is an ACK with
        'SEG.SEQ = SND.NXT - 1' so peer's TCP is forced to respond
        with an ACK at the current SND.NXT (which we treat as a
        probe-ack and use to reset the idle timer); peer's
        application sees no segment text. The probe is emitted
        directly via the packet handler rather than via
        '_transmit_packet' because the latter rewrites SND.NXT
        from its 'seq' argument and the probe must consume no
        sequence space.

        Lazy-arm: when 'enable_keepalive' is flipped True after
        handshake completion (e.g. via a setsockopt-equivalent
        path), the first tick sees '_keepalive_enabled = True'
        but '_keepalive_active = False'. Arm the timer here and
        return so the next tick begins the regular idle countdown.
        """

        if not self._keepalive.enabled:
            return
        if not self._keepalive.active:
            self._keepalive_arm_idle()
            return
        if not self._timer_expired("keepalive"):
            return
        max_count = self._keepalive.max_probes(default=tcp__constants.TCP__KEEPALIVE__PROBE_MAX_COUNT)
        if self._keepalive.probes_unacked >= max_count:
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - Keep-alive: {self._keepalive.probes_unacked} probes "
                "unacked, tearing down connection (RFC 1122 §4.2.3.6)",
            )
            self._connection_error = ConnError.TIMEOUT
            self._event__connect.release()
            self._event__rx_buffer.set()
            self._socket._signal_readable()
            self._change_state(FsmState.CLOSED)
            return
        stack.egress_packet_handler(self._remote_ip_address).send_tcp_packet(
            ip__local_address=self._local_ip_address,
            ip__remote_address=self._remote_ip_address,
            ip__dscp=self._socket._effective_ip_dscp(),
            tcp__local_port=self._local_port,
            tcp__remote_port=self._remote_port,
            tcp__flag_ack=True,
            tcp__seq=sub32(self._snd_seq.nxt, 1),
            tcp__ack=self._rcv_seq.nxt,
            tcp__win=self._rcv_wnd >> self._win.rcv_wsc,
        )
        self._keepalive.probes_unacked += 1
        self._arm_timer(
            "keepalive",
            self._keepalive.interval_timeout(default=tcp__constants.TCP__KEEPALIVE__PROBE_INTERVAL_MS),
        )
        __debug__ and log(
            "tcp-ss",
            f"[{self}] - Keep-alive: emitted probe "
            f"{self._keepalive.probes_unacked}/{max_count} "
            f"at seq={sub32(self._snd_seq.nxt, 1)} ack={self._rcv_seq.nxt}",
        )

    def _ingest_sack_info(self, packet_rx_md: TcpMetadata) -> None:
        """
        Ingest peer's SACK blocks from 'packet_rx_md' into the
        send-side scoreboard, gated on '_send_sack' (bilateral
        negotiation succeeded). Per RFC 2018 §5 ("be liberal in
        what we accept") blocks whose edges fall outside
        '[SND.UNA, SND.MAX]' or are degenerate ('left >= right')
        are silently dropped - they cannot describe legitimate
        in-flight bytes.

        Also recognises RFC 2883 DSACK reports: the FIRST SACK
        block is treated as a DSACK marker (and excluded from
        scoreboard ingestion) when either of the RFC 2883 §4
        signatures holds:

          1. Below cum-ACK: 'right <= SND.UNA'. Peer is
             reporting a duplicate of bytes already
             cumulatively acknowledged.
          2. Contained-in-other: the first block lies inside
             one of the subsequent blocks. Peer is reporting
             a duplicate of bytes already SACKed.

        On detection '_dsack_received' is incremented for
        observability; the spurious-retransmit / RTO-management
        consumers of this counter are out of scope for phase 7.
        """

        if not self._advertise.send_sack:
            return

        blocks = list(packet_rx_md.tcp__sack_blocks)
        if not blocks:
            return

        # RFC 2883 DSACK detection on the first block.
        first_left, first_right = blocks[0]
        is_dsack = le32(first_right, self._snd_seq.una)
        if not is_dsack:
            for outer_left, outer_right in blocks[1:]:
                if le32(outer_left, first_left) and le32(first_right, outer_right):
                    is_dsack = True
                    break
        if is_dsack:
            self._dsack_received += 1
            # RFC 9438 §4.9.2 spurious-fast-retransmit restore:
            # a DSACK observed during a recovery episode that
            # had snapshotted CUBIC state at FR entry indicates
            # the retransmit was spurious. Roll back W_max, K,
            # epoch_start, W_est, cwnd, and ssthresh to their
            # pre-FR values so post-FR throughput is not
            # artificially anchored at the reduced W_max.
            if self._cc.cc_mode is CcMode.CUBIC and self._cc.fr_cubic_snapshot_valid and self._cc.recovery_point != 0:
                self._cc.restore_fr_cubic_snapshot()
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - RFC 9438 §4.9.2 spurious-FR "
                    "restore: rolled back CUBIC state on DSACK "
                    f"(cwnd={self._cc.cwnd}, ssthresh={self._cc.ssthresh}, "
                    f"W_max={self._cc.cubic_w_max})",
                )
            # RFC 8985 §6.2 step 4 DSACK-round handling. A
            # DSACK observed outside recovery indicates a
            # spurious retransmit (the peer received what we
            # thought was lost), so the reo_wnd_mult is
            # incremented to reduce future spurious losses by
            # using a larger reordering tolerance. Only fires
            # ONCE per round - the '_rack_dsack_round' marker
            # holds SND.MAX at the moment of observation; we
            # wait until SND.UNA crosses it before allowing
            # the next increment, so a burst of DSACKs at the
            # same round boundary doesn't multiply the
            # multiplier away.
            if self._cc.recovery_point == 0:
                self._rack_tlp.maybe_close_dsack_round(snd_una=self._snd_seq.una, snd_max=self._snd_seq.max)
            blocks = blocks[1:]

        # RFC 6937 §3.1 SACK delta tracking: when in recovery,
        # the bytes added to the scoreboard by THIS ingestion
        # count as 'DeliveredData' and feed PRR's per-ACK
        # 'sndcnt = ceil(prr_delivered * ssthresh / RecoverFS)
        # - prr_out' formula. Snapshot the scoreboard total
        # before adding the new blocks; the post-add total
        # minus the snapshot is the exact byte delta (the
        # merge invariant guarantees no overlap so the sum is
        # exact). DSACK blocks are excluded above (the slice
        # 'blocks[1:]') so they do not double-count peer's
        # report of bytes we already knew about.
        bytes_before = self._sack_scoreboard.total_sacked_bytes() if self._cc.recovery_point != 0 else 0

        for left, right in blocks:
            if le32(self._snd_seq.una, left) and le32(right, self._snd_seq.max) and lt32(left, right):
                self._sack_scoreboard.add_block(left, right)

        if self._cc.recovery_point != 0:
            self._cc.prr_delivered += self._sack_scoreboard.total_sacked_bytes() - bytes_before

    def _prune_sack_scoreboard(self) -> None:
        """
        Drop scoreboard blocks whose right edge is at or below
        the current 'SND.UNA' - the cumulative ACK has absorbed
        them and they cannot inform any further loss recovery
        (RFC 6675 §3 / RFC 2018 §3). Gated on '_send_sack' so the
        pruning is a no-op on connections without bilateral SACK.
        """

        if self._advertise.send_sack:
            self._sack_scoreboard.prune_below(self._snd_seq.una)

    def _advance_snd_nxt_past_sacked(self) -> None:
        """
        During fast-retransmit recovery, advance 'SND.NXT' past
        any peer-SACKed range that contains it so the next
        transmission does not redundantly re-send bytes peer
        already received. RFC 6675 §5 multi-gap recovery: the
        sender consults the scoreboard to skip SACKed regions
        and only retransmits genuine gaps. Walks the scoreboard
        in modular order from 'SND.UNA'; since the scoreboard
        coalesces adjacent blocks on insert a single pass
        suffices. No-op when not in recovery, when SACK is
        disabled, or when 'SND.NXT == SND.MAX' (everything we
        intended to send has been sent).
        """

        if self._cc.recovery_point == 0 or not self._advertise.send_sack:
            return

        for left, right in sorted(
            self._sack_scoreboard.blocks(),
            key=lambda b: (b[0] - self._snd_seq.una) & 0xFFFF_FFFF,
        ):
            if le32(left, self._snd_seq.nxt) and lt32(self._snd_seq.nxt, right):
                self._snd_seq.nxt = right

    def _enqueue_rx_buffer(self, data: memoryview) -> None:
        """
        Process the incoming segment and enqueue the data
        to be used by socket.
        """

        assert isinstance(data, memoryview)  # memoryview: check to ensure data gets here as memoryview not bytes.

        # POSIX 'shutdown(SHUT_RD)' silently discards inbound
        # data per RFC 9293 §3.9.1 half-close semantics. The
        # peer's ACK still acknowledges the seq space (advancing
        # RCV.NXT), but the application never sees the bytes.
        if self._shut.rd:
            return

        with self._lock__rx_buffer:
            self._rx_buffer.extend(data)
            # 'Event.set()' is idempotent so this is safe whether the
            # event was already set by a sibling FSM handler or not.
            self._event__rx_buffer.set()
            # Selector readability: an asyncio / trio / selectors
            # consumer waiting on 'self._socket.fileno()' must wake
            # on inbound data. The hook lives under the rx-buffer
            # lock so concurrent recv() drains observe a consistent
            # eventfd state.
            self._socket._signal_readable()

    def _transmit_data(self) -> None:
        """
        Send out data segment from TX buffer using TCP
        sliding window mechanism. Thin delegator over
        'TcpTxEngine.transmit_data'.
        """

        self._tx_engine.transmit_data()

    def _delayed_ack(self) -> None:
        """
        Run Delayed ACK mechanism. Thin delegator over
        'TcpTxEngine.delayed_ack'.
        """

        self._tx_engine.delayed_ack()

    def _retransmit_packet_timeout(self) -> None:
        """
        Retransmit packet after expired timeout (RFC 6298 §5).
        Thin delegator over 'TcpRetransmitter.retransmit_packet_timeout'.
        """

        self._retransmitter.retransmit_packet_timeout()

    def _retransmit_packet_request(self, packet_rx_md: TcpMetadata) -> None:
        """
        Retransmit packet after fast-retransmit request (RFC 5681
        §3.2 / RFC 6675 §3). Thin delegator over
        'TcpRetransmitter.retransmit_packet_request'.
        """

        self._retransmitter.retransmit_packet_request(packet_rx_md)

    def _tlp_pto_tick(self) -> None:
        """
        Per-tick service for the RFC 8985 §7.3 Tail Loss Probe.
        Thin delegator over 'TcpRetransmitter.tlp_pto_tick'.
        """

        self._retransmitter.tlp_pto_tick()

    def _rack_reorder_tick(self) -> None:
        """
        Per-tick service for the RFC 8985 §6.2 step 5 reordering
        timer. Thin delegator over 'TcpRetransmitter.rack_reorder_tick'.
        """

        self._retransmitter.rack_reorder_tick()

    def _rack_process_ack(self, packet_rx_md: TcpMetadata) -> None:
        """
        Apply RFC 8985 §6.2 step 1-2 (rack_update) + step 5
        (rack_detect_loss) on every accepted ACK. Thin delegator
        over 'TcpRetransmitter.rack_process_ack'.
        """

        self._retransmitter.rack_process_ack(packet_rx_md)

    def _confirm_neighbor_reachability(self) -> None:
        """
        RFC 4861 §7.3.1 upper-layer reachability confirmation
        — feed the appropriate NUD cache (ARP for IPv4 peers,
        ND for IPv6) the positive-evidence signal from a
        cum-ACK that advanced SND.UNA. Promotes a STALE /
        DELAY / PROBE entry directly to REACHABLE without
        firing a unicast probe; no-op for entries in
        INCOMPLETE / FAILED / PERMANENT or absent from the
        cache.

        Called from '_phase1_cum_ack_side_effects' after the
        SND.UNA-advance check, so dup-ACKs and stale ACKs do
        not fire the hook.
        """

        # The peer's neighbor entry lives in the EGRESS interface's
        # cache (Linux keys ARP / ND per ifindex). Resolve the egress
        # interface and feed its own cache — the Phase-6 successor to the
        # bare 'stack.arp_cache' / 'stack.nd_cache' singletons.
        # Phase 3: a dedicated neighbor-control API will replace this
        # reach-through into the handler's '_arp_cache' / '_nd_cache'.
        handler = stack.egress_packet_handler(self._remote_ip_address)
        if isinstance(self._remote_ip_address, Ip4Address):
            if handler._arp_cache is not None:
                handler._arp_cache.confirm_reachability(ip4_address=self._remote_ip_address)
        elif handler._nd_cache is not None:
            handler._nd_cache.confirm_reachability(ip6_address=self._remote_ip_address)

    def _process_ack_packet(self, packet_rx_md: TcpMetadata) -> None:
        """
        Process regular data/ACK packet. Thin delegator over
        'TcpAckProcessor.process_ack_packet' — the five-phase
        inbound-ACK pipeline lives on the ACK processor.
        """

        self._ack_processor.process_ack_packet(packet_rx_md)

    def tcp_fsm(
        self,
        packet_rx_md: TcpMetadata | None = None,
        syscall: SysCall | None = None,
        timer: bool | None = None,
        icmp: IcmpMetadata | None = None,
    ) -> None:
        """
        Run TCP finite state machine.
        """

        with self._lock__fsm:
            # Phase 4c: snapshot the state before any dispatch so
            # the tail can detect a transition and arm the
            # 'tx_pump' FSM-pump (§5.6/§5.7).
            state_at_entry = self._state

            # Phase 2 of the ICMP-into-FSM refactor: 'icmp' is
            # dispatched through 'FSM_ICMP_HANDLERS' to the per-state
            # handler carrying RFC 5927 §5.2 hard-vs-soft semantics
            # (synchronized states downgrade hard errors to soft;
            # SYN_SENT is the only state allowed to abort).
            if icmp is not None:
                tcp_fsm_dispatch_icmp(self, icmp)
                self._pump_tail(state_at_entry, True)
                return

            # RFC 3168 §6.1.2 / §6.1.3 receiver-side CE echo
            # tracking. Run BEFORE the FSM dispatch so the
            # state-handler-emitted ACK on this segment already
            # carries ECE, and the sender's CWR confirmation
            # observed on the same segment clears the flag.
            if self._ecn.enabled and packet_rx_md is not None:
                if packet_rx_md.tcp__flag_cwr:
                    self._ecn.send_ece = False
                if packet_rx_md.ip__ecn == 3:
                    self._ecn.send_ece = True
            # RFC 9768 §3.2.2 / §3.2.3 receiver-side counter
            # accumulation: r.cep packet counter on CE, plus
            # per-codepoint byte counters from the TCP payload.
            # All counters wrap modulo 2^24 per the option width.
            if self._accecn.enabled and packet_rx_md is not None:
                self._accecn.record_received_codepoint(
                    ip_ecn=packet_rx_md.ip__ecn,
                    payload_len=len(packet_rx_md.tcp__data),
                )
            # RFC 3168 §6.1.2 sender-side response to inbound
            # ECE. Halve ssthresh per RFC 5681 §3.1, collapse
            # cwnd to ssthresh, and arm '_ecn_send_cwr' so the
            # next outbound data segment confirms the response
            # via CWR. One-shot per RTT: '_ecn_recovery_point'
            # = SND.NXT at the moment of response; subsequent
            # ECEs within the same window of data are ignored
            # until SND.UNA crosses the recovery point.
            if (
                self._ecn.enabled
                and packet_rx_md is not None
                and packet_rx_md.tcp__flag_ece
                and (self._ecn.recovery_point == 0 or le32(self._ecn.recovery_point, self._snd_seq.una))
            ):
                flight_size = sub32(self._snd_seq.max, self._snd_seq.una)
                # RFC 8511 ABE: ECN signals early-warning
                # congestion (no actual loss yet); reduce
                # ssthresh by the less-aggressive 0.85
                # multiplier instead of the 0.5 used for
                # genuine packet-loss events.
                self._cc.ssthresh = compute_ecn_event_ssthresh(flight_size, self._win.snd_mss)
                self._cc.cwnd = self._cc.ssthresh
                self._cc.snd_ewn = min(self._cc.cwnd, self._win.snd_wnd)
                self._ecn.arm_cwr_response(snd_nxt=self._snd_seq.nxt)
            # RFC 9768 §3.4 sender-side response to AccECN
            # feedback. When the peer's inbound AccECN option
            # reports an r.CE byte counter higher than our
            # tracked value, treat the delta as a single
            # congestion event: halve ssthresh per RFC 5681
            # §3.1, collapse cwnd to ssthresh, and update the
            # tracker so subsequent ACKs reporting the same
            # cumulative count are idempotent. The same
            # one-shot recovery-point guard the RFC 3168
            # path uses prevents multiple AccECN events
            # within a single RTT from compounding the
            # reduction.
            if (
                self._accecn.enabled
                and packet_rx_md is not None
                and packet_rx_md.tcp__accecn0_counters is not None
                and packet_rx_md.tcp__accecn0_counters[1] is not None
                and packet_rx_md.tcp__accecn0_counters[1] > self._accecn.s_ce_b
                and (self._ecn.recovery_point == 0 or le32(self._ecn.recovery_point, self._snd_seq.una))
            ):
                flight_size = sub32(self._snd_seq.max, self._snd_seq.una)
                # RFC 8511 ABE: same as the RFC 3168 ECN path
                # above - on ECN-class events the sender uses
                # the less-aggressive 0.85 multiplier rather
                # than the 0.5 reserved for genuine packet
                # loss events.
                self._cc.ssthresh = compute_ecn_event_ssthresh(flight_size, self._win.snd_mss)
                self._cc.cwnd = self._cc.ssthresh
                self._cc.snd_ewn = min(self._cc.cwnd, self._win.snd_wnd)
                self._ecn.recovery_point = self._snd_seq.nxt
            # RFC 9768 §3.2.1 sender-side counter mirrors. Update
            # s.e0b / s.ce_b / s.e1b from the inbound option's
            # populated slots (per-slot None per the §3.2.3
            # abbreviation rule). Done outside the cwnd-response
            # gate above so the trackers advance even when the
            # recovery-point guard suppresses the response.
            if self._accecn.enabled and packet_rx_md is not None and packet_rx_md.tcp__accecn0_counters is not None:
                self._accecn.update_sender_counters_from_option(packet_rx_md.tcp__accecn0_counters)
            # RFC 9768 §3.2.2.5 ACE-based fallback. When an
            # AccECN-mode inbound ACK arrives WITHOUT the
            # AccECN option (e.g. a middlebox stripped it),
            # the byte-counter path above cannot detect new
            # CE marks. As a fallback, decode the ACE field
            # from the AE+CWR+ECE flags and compare to the
            # prior 's.cep & 7' value: a positive delta is
            # the apparent CE-marked-segment count since the
            # last seen ACE. If positive, treat as a
            # congestion event (gated by the same one-shot
            # recovery-point guard the byte-counter path
            # uses, so concurrent firing of both paths within
            # one RTT is harmless). The wrap-aware §3.2.2.5.2
            # safest-likely-case correction is omitted here:
            # for typical Internet workloads the option is
            # rarely stripped, so the apparent delta is
            # almost always the true delta; the simpler
            # detection captures the common case without
            # the over-aggressive wrap-correction risk.
            if (
                self._accecn.enabled
                and packet_rx_md is not None
                and packet_rx_md.tcp__accecn0_counters is None
                and not packet_rx_md.tcp__flag_syn
            ):
                incoming_ace = (
                    (int(packet_rx_md.tcp__flag_ns) << 2)
                    | (int(packet_rx_md.tcp__flag_cwr) << 1)
                    | int(packet_rx_md.tcp__flag_ece)
                )
                apparent_delta = self._accecn.apparent_ce_delta(incoming_ace)
                if apparent_delta > 0 and (
                    self._ecn.recovery_point == 0 or le32(self._ecn.recovery_point, self._snd_seq.una)
                ):
                    flight_size = sub32(self._snd_seq.max, self._snd_seq.una)
                    self._cc.ssthresh = compute_ecn_event_ssthresh(flight_size, self._win.snd_mss)
                    self._cc.cwnd = self._cc.ssthresh
                    self._cc.snd_ewn = min(self._cc.cwnd, self._win.snd_wnd)
                    self._ecn.recovery_point = self._snd_seq.nxt
            # Route to the per-event-kind dispatcher.
            # 'tcp_fsm()' is invoked with exactly one of the
            # three kwargs set; pick the matching dispatcher.
            if packet_rx_md is not None:
                tcp_fsm_dispatch_packet(self, packet_rx_md)
            elif syscall is not None:
                tcp_fsm_dispatch_syscall(self, syscall)
            elif timer:
                tcp_fsm_dispatch_timer(self)

            self._pump_tail(state_at_entry, packet_rx_md is not None or syscall is not None)
