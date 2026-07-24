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
This module contains the 'TcpTestCase' base class used by the
TCP session integration tests, layering a deterministic clock and TCP
probe helpers on top of 'NetworkTestCase'.

pytcp/tests/lib/tcp_testcase.py

ver 3.0.9
"""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, cast, override
from unittest.mock import _patch, patch

from net_addr import Ip4Address, Ip6Address
from net_proto.lib.enums import EtherType
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.ethernet.ethernet__parser import EthernetParser
from net_proto.protocols.ip4.ip4__parser import Ip4Parser
from net_proto.protocols.ip6.ip6__parser import Ip6Parser
from net_proto.protocols.tcp.tcp__parser import TcpParser
from pytcp import stack
from pytcp.protocols.icmp.icmp__error_emitter import IcmpErrorRateLimiter
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__enums import CcMode, FsmState, SysCall
from pytcp.protocols.tcp.tcp__stack import TcpStack
from pytcp.runtime.socket import AddressFamily
from pytcp.runtime.socket.tcp__socket import TcpSocket
from pytcp.runtime.timer import Timer
from pytcp.tests.lib.fake_timer import FakeTimer
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__IP6_ADDRESS,
    STACK__IP4_HOST,
    STACK__IP6_HOST,
    NetworkTestCase,
)
from pytcp.tests.lib.tcp_segment_factory import build_tcp4, build_tcp6

# Canonical 4-tuple defaults used by 95%+ of TCP integration tests.
# Tests with non-default addressing pass overrides as kwargs to
# '_make_active_session' / '_drive_handshake_to_established'.
_DEFAULT_LOCAL_PORT = 12345
_DEFAULT_REMOTE_PORT = 80
_DEFAULT_PEER_WIN = 64240
_DEFAULT_PEER_MSS = 1460

TCP_FLAG_NAMES: tuple[str, ...] = (
    "SYN",
    "ACK",
    "FIN",
    "RST",
    "PSH",
    "URG",
    "ECE",
    "CWR",
    "NS",
)

# Sentinel used by '_assert_segment' to distinguish "caller supplied no
# expected value, skip this check" from "caller explicitly asserted the
# field is None / absent". 'None' alone is ambiguous because option
# fields ('mss', 'wscale') legitimately use 'None' to mean "option not
# present on the wire".
_UNSET: object = object()


@dataclass(frozen=True, slots=True)
class TcpProbe:
    """
    Decoded snapshot of a single Ethernet/IP/TCP frame produced by
    the stack under test, used by 'TcpTestCase' assertions.
    """

    ip_src: Ip6Address | Ip4Address
    ip_dst: Ip6Address | Ip4Address
    # RFC 3168 §5: IP ECN field - 0=Not-ECT, 1=ECT(1), 2=ECT(0), 3=CE.
    ip_ecn: int
    # RFC 2474 §3: DS field DSCP (high 6 bits of the TOS / Traffic
    # Class byte), marked from the socket's IP_TOS / IPV6_TCLASS.
    ip_dscp: int
    sport: int
    dport: int
    seq: int
    ack: int
    flags: frozenset[str]
    win: int
    mss: int | None
    wscale: int | None
    sackperm: bool
    sack_blocks: tuple[tuple[int, int], ...]
    tsval: int | None
    tsecr: int | None
    # RFC 7413 §2 TFO option: None = absent on the wire,
    # b"" = empty-cookie request form, b"..." = cookie
    # response/use form.
    fastopen_cookie: bytes | None
    # RFC 9768 §3.2.3 AccECN option: tuple of three 24-bit
    # byte counters (ee0b, eceb, ee1b) when present, None
    # when absent on the wire. The ordering is the AccECN0
    # convention (ECT(0), CE, ECT(1)) regardless of which
    # kind appeared on the wire.
    accecn: tuple[int | None, int | None, int | None] | None
    # AccECN option ordering: 172 = AccECN0 (Order 0, ECT(0)
    # in first wire slot); 174 = AccECN1 (Order 1, ECT(1)
    # in first wire slot); None when no AccECN option is
    # present.
    accecn_kind: int | None
    payload: bytes


class TcpTestCase(NetworkTestCase):
    """
    Base class for TCP session integration tests. Adds a deterministic
    'FakeTimer' replacement for 'stack.timer', helpers to drive RX
    frames into the packet handler and capture the TX frames the stack
    emits, and a 'TcpProbe' parser for fluent segment-level assertions.
    """

    _timer: FakeTimer
    _patches: list[_patch[Any]]
    _sockets_prior: dict[Any, Any]
    _tcp_stack_prior: TcpStack
    _pmtu_cache_prior: dict[Any, Any]
    _pmtu_state_prior: dict[Any, Any]
    _icmp4_error_rate_limiter_prior: IcmpErrorRateLimiter
    _icmp6_error_rate_limiter_prior: IcmpErrorRateLimiter

    # Per-test-class congestion-control override pinned by
    # '_make_active_session'. None means "use the codebase default"
    # (currently CcMode.CUBIC after the Phase 7 RFC 9438 flip).
    # RFC 5681-only conformance tests set this to CcMode.RENO at the
    # class level so every session built via the harness pins Reno.
    _DEFAULT_CC_MODE: CcMode | None = None

    @override
    def setUp(self) -> None:
        """
        Install a 'FakeTimer' over 'stack.timer' on top of the parent
        mock-network setup, snapshot+clear the module-global
        'stack.sockets' dict and replace 'stack.tcp_stack' with a
        fresh 'TcpStack' instance so tests start with no leftover
        registrations or cached TFO state, and initialize the patch
        tracking list so per-test 'mock.patch' handles get torn down
        deterministically.
        """

        super().setUp()

        self._timer = FakeTimer()
        stack.mock__init(mock__timer=cast(Timer, self._timer))

        # 'stack.sockets' is a module-level dict that accumulates
        # registrations across tests if not cleared. Snapshot the prior
        # contents, then start each test with an empty dict; tearDown
        # restores so unrelated tests outside this class are unaffected.
        self._sockets_prior = dict(stack.sockets)
        stack.sockets.clear()

        # 'stack.tcp_stack' aggregates the RFC 7413 §4.1.3.1 negative-
        # response cache, §4.2 pending-request counter, and §3.1
        # cookie cache. Replace with a fresh instance so any
        # registrations from earlier tests (especially TFO peers added
        # to the negative cache via a SYN-RTO) do not silently
        # suppress TFO emission in subsequent tests' active-open paths.
        self._tcp_stack_prior = stack.tcp_stack
        stack.tcp_stack = TcpStack()

        # 'stack.pmtu_cache' is the per-destination Path-MTU dict
        # added by Phase 3 of the ICMP demux + PMTUD refactor.
        # Snapshot+clear+restore so a TCP session test that triggers
        # an MSS recompute via a PMTUD ICMP cannot leak its
        # per-destination MTU into an unrelated test.
        self._pmtu_cache_prior = dict(stack.pmtu_cache)
        stack.pmtu_cache.clear()

        # 'stack.pmtu_state' is the unified PLPMTUD engine registry
        # added by Phase 2 of the PLPMTUD plan; snapshot/clear it
        # alongside the legacy pmtu_cache.
        self._pmtu_state_prior = dict(stack.pmtu_state)
        stack.pmtu_state.clear()

        # ICMP error rate limiters: snapshot+replace with fresh
        # instances so a TCP test that triggers ICMP error suppression
        # (e.g. via the UDP closed-port emitter from a peer probe)
        # starts each case with a full burst quota.
        self._icmp4_error_rate_limiter_prior = stack.icmp4_error_rate_limiter
        stack.icmp4_error_rate_limiter = IcmpErrorRateLimiter()
        self._icmp6_error_rate_limiter_prior = stack.icmp6_error_rate_limiter
        stack.icmp6_error_rate_limiter = IcmpErrorRateLimiter()

        self._patches = []

    @override
    def tearDown(self) -> None:
        """
        Stop any 'mock.patch' handle started by '_start_patch', restore
        'stack.tcp_stack' to its pre-test value, then defer to the
        parent teardown so test-only state does not leak between tests.
        """

        while self._patches:
            self._patches.pop().stop()

        stack.sockets.clear()
        stack.sockets.update(self._sockets_prior)

        stack.tcp_stack = self._tcp_stack_prior

        stack.pmtu_cache.clear()
        stack.pmtu_cache.update(self._pmtu_cache_prior)

        stack.pmtu_state.clear()
        stack.pmtu_state.update(self._pmtu_state_prior)

        stack.icmp4_error_rate_limiter = self._icmp4_error_rate_limiter_prior
        stack.icmp6_error_rate_limiter = self._icmp6_error_rate_limiter_prior

        super().tearDown()

    def _start_patch(self, target: str, new: object) -> None:
        """
        Start a 'mock.patch' on 'target' replacing it with 'new' and
        register the patch so 'tearDown' stops it automatically.
        """

        handle = patch(target, new)
        handle.start()
        self._patches.append(handle)

    def _force_iss(self, value: int) -> None:
        """
        Force the next 'TcpSession' constructed in this test to choose
        'value' as its initial sequence number, so wrap-aware paths
        can be exercised deterministically. Patches 'compute_iss' in
        the 'pytcp.protocols.tcp.tcp__session' module scope; the
        canonical ISN choice was migrated from 'random.randint' to
        the RFC 6528 §3 hash in commit 'ac0d98b' / wired into
        TcpSession in the follow-up.
        """

        self._start_patch(
            "pytcp.protocols.tcp.session.tcp__session.compute_iss",
            lambda *_args, **_kwargs: value,
        )

    def _make_active_session(
        self,
        *,
        iss: int,
        family: AddressFamily = AddressFamily.INET4,
        local_ip: Ip4Address | Ip6Address | None = None,
        local_port: int = _DEFAULT_LOCAL_PORT,
        remote_ip: Ip4Address | Ip6Address | None = None,
        remote_port: int = _DEFAULT_REMOTE_PORT,
        so_rcvbuf: int | None = None,
    ) -> TcpSession:
        """
        Build a 'TcpSocket' / 'TcpSession' pair on the canonical
        4-tuple. Defaults match the addressing in
        'pytcp/tests/lib/network_testcase.py' (STACK
        10.0.1.7:12345 ↔ host A 10.0.1.91:80 for IPv4; the
        equivalent IPv6 pair when 'family' is INET6). Supply
        'local_ip' / 'remote_ip' / 'local_port' / 'remote_port' to
        override.

        The 'iss' argument is forced via '_force_iss' so the session
        constructed by this call uses 'iss' as its initial sequence
        number (RFC 6528 ISS is otherwise hash-derived). The newly
        created socket is registered in 'stack.sockets' and the
        session is returned.
        """

        if local_ip is None:
            local_ip = STACK__IP4_HOST.address if family is AddressFamily.INET4 else STACK__IP6_HOST.address
        if remote_ip is None:
            remote_ip = HOST_A__IP4_ADDRESS if family is AddressFamily.INET4 else HOST_A__IP6_ADDRESS

        self._force_iss(iss)
        sock = TcpSocket(family=family)
        sock._local_ip_address = local_ip
        sock._local_port = local_port
        sock._remote_ip_address = remote_ip
        sock._remote_port = remote_port
        # Set SO_RCVBUF before the session is built so its rcv_wnd_max
        # (advertised-receive-window cap) derives from it.
        if so_rcvbuf is not None:
            sock._so_rcvbuf = so_rcvbuf
        session = TcpSession(
            local_ip_address=local_ip,
            local_port=local_port,
            remote_ip_address=remote_ip,
            remote_port=remote_port,
            socket=sock,
        )
        sock._tcp_session = session
        stack.sockets[sock.socket_id] = sock
        if self._DEFAULT_CC_MODE is not None:
            session._cc.cc_mode = self._DEFAULT_CC_MODE
        return session

    def _drive_handshake_to_established(
        self,
        *,
        iss: int,
        peer_iss: int,
        family: AddressFamily = AddressFamily.INET4,
        local_ip: Ip4Address | Ip6Address | None = None,
        local_port: int = _DEFAULT_LOCAL_PORT,
        remote_ip: Ip4Address | Ip6Address | None = None,
        remote_port: int = _DEFAULT_REMOTE_PORT,
        peer_win: int = _DEFAULT_PEER_WIN,
        peer_mss: int = _DEFAULT_PEER_MSS,
        peer_sackperm: bool = False,
        peer_wscale: int | None = None,
        peer_tsval: int | None = None,
        peer_tsecr: int | None = None,
    ) -> TcpSession:
        """
        Build an active-open session and drive it to ESTABLISHED by
        emitting the local SYN, advancing the timer one tick, then
        injecting the peer's synthetic SYN-ACK. Returns the session
        in ESTABLISHED state. The local 'TcpSocket' is reachable
        via 'session._socket' if a caller needs to invoke socket-API
        methods (abort, close, shutdown, status).

        Reference: RFC 9293 §3.5 (Connection Establishment).
        """

        session = self._make_active_session(
            iss=iss,
            family=family,
            local_ip=local_ip,
            local_port=local_port,
            remote_ip=remote_ip,
            remote_port=remote_port,
        )
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        if family is AddressFamily.INET6:
            peer_syn_ack = build_tcp6(
                src_ip=cast(Ip6Address, session._remote_ip_address),
                dst_ip=cast(Ip6Address, session._local_ip_address),
                sport=session._remote_port,
                dport=session._local_port,
                seq=peer_iss,
                ack=iss + 1,
                flags=("SYN", "ACK"),
                win=peer_win,
                mss=peer_mss,
                sackperm=peer_sackperm,
                wscale=peer_wscale,
                tsval=peer_tsval,
                tsecr=peer_tsecr,
            )
        else:
            peer_syn_ack = build_tcp4(
                src_ip=cast(Ip4Address, session._remote_ip_address),
                dst_ip=cast(Ip4Address, session._local_ip_address),
                sport=session._remote_port,
                dport=session._local_port,
                seq=peer_iss,
                ack=iss + 1,
                flags=("SYN", "ACK"),
                win=peer_win,
                mss=peer_mss,
                sackperm=peer_sackperm,
                wscale=peer_wscale,
                tsval=peer_tsval,
                tsecr=peer_tsecr,
            )
        self._drive_rx(frame=peer_syn_ack)
        assert (
            session.state is FsmState.ESTABLISHED
        ), f"_drive_handshake_to_established: session did not reach ESTABLISHED; got {session.state!r}"
        return session

    def _drive_rx(self, *, frame: bytes) -> list[bytes]:
        """
        Feed 'frame' into 'PacketHandler._phrx_ethernet' and return
        the list of TX frames the stack produced as a direct result.
        """

        before = len(self._frames_tx)
        self._packet_handler._phrx_ethernet(PacketRx(frame))
        return list(self._frames_tx[before:])

    def _advance(self, *, ms: int) -> list[bytes]:
        """
        Advance the virtual clock by 'ms' milliseconds and return the
        list of TX frames produced during the tick.
        """

        before = len(self._frames_tx)
        self._timer.advance(ms)
        return list(self._frames_tx[before:])

    def _pending_session_timers(self, session: TcpSession, /) -> dict[str, int]:
        """
        Build a '{f"{session}-<name>": remaining_ms}' view from the
        session's timer-service deadline map (the source of truth).
        A logical timer is "pending" while it is armed and has not
        yet fired.
        """

        now = self._timer.now_ms
        return {
            f"{session}-{name}": deadline - now
            for name, deadline in session._timers._deadlines.items()
            if deadline > now
        }

    def _expire_timer(self, session: TcpSession, name: str, /) -> None:
        """
        Force the named logical timer to read as expired on the
        next service tick by back-dating its deadline to now.
        """

        session._timers._deadlines[name] = self._timer.now_ms

    def _parse_tx(self, frame: bytes, /) -> TcpProbe:
        """
        Parse a TX frame back into a 'TcpProbe' covering the IP and
        TCP fields the integration tests need to assert on.
        """

        packet_rx = PacketRx(frame)
        EthernetParser(packet_rx)

        if packet_rx.ethernet.type is EtherType.IP4:
            Ip4Parser(packet_rx)
        elif packet_rx.ethernet.type is EtherType.IP6:
            Ip6Parser(packet_rx)
        else:
            raise AssertionError(f"Unexpected EtherType in TX frame: {packet_rx.ethernet.type!r}")

        TcpParser(packet_rx)

        flags: set[str] = set()
        for name in TCP_FLAG_NAMES:
            if getattr(packet_rx.tcp, f"flag_{name.lower()}"):
                flags.add(name)

        # Read the option presence via the underlying TcpOptions container
        # ('_options.mss' / '_options.wscale' / '_options.sack' return None
        # when absent), not via the parser's 'OptionsProperties' mixin (which
        # substitutes defaults like TCP__MIN_MSS=536 / wscale=0 and so cannot
        # distinguish 'option absent' from 'option present with the default
        # value').
        sack_blocks_raw = packet_rx.tcp._options.sack
        sack_blocks: tuple[tuple[int, int], ...] = (
            () if sack_blocks_raw is None else tuple((block.left, block.right) for block in sack_blocks_raw)
        )
        timestamps_raw = packet_rx.tcp._options.timestamps
        tsval = timestamps_raw.tsval if timestamps_raw is not None else None
        tsecr = timestamps_raw.tsecr if timestamps_raw is not None else None
        # RFC 7413 §2 TFO option: pulled via the typed
        # 'fastopen' property on TcpOptions. Returns 'None'
        # when the option is absent on the wire, 'b""' for
        # the cookie-request form, and the cookie bytes for
        # the cookie-response/use form.
        fastopen_cookie = packet_rx.tcp._options.fastopen
        accecn_raw = packet_rx.tcp._options.accecn
        accecn = None if accecn_raw is None else (accecn_raw.ee0b, accecn_raw.eceb, accecn_raw.ee1b)
        accecn_kind = None if accecn_raw is None else int(accecn_raw.type)
        return TcpProbe(
            ip_src=packet_rx.ip.src,
            ip_dst=packet_rx.ip.dst,
            ip_ecn=packet_rx.ip.ecn,
            ip_dscp=packet_rx.ip.dscp,
            sport=packet_rx.tcp.sport,
            dport=packet_rx.tcp.dport,
            seq=packet_rx.tcp.seq,
            ack=packet_rx.tcp.ack,
            flags=frozenset(flags),
            win=packet_rx.tcp.win,
            mss=packet_rx.tcp._options.mss,
            wscale=packet_rx.tcp._options.wscale,
            sackperm=bool(packet_rx.tcp._options.sackperm),
            sack_blocks=sack_blocks,
            tsval=tsval,
            tsecr=tsecr,
            fastopen_cookie=fastopen_cookie,
            accecn=accecn,
            accecn_kind=accecn_kind,
            payload=bytes(packet_rx.tcp.payload),
        )

    def _assert_segment(
        self,
        probe: TcpProbe,
        *,
        flags: object = _UNSET,
        seq: object = _UNSET,
        ack: object = _UNSET,
        payload: object = _UNSET,
        win: object = _UNSET,
        mss: object = _UNSET,
        wscale: object = _UNSET,
        sackperm: object = _UNSET,
        sack_blocks: object = _UNSET,
        sport: object = _UNSET,
        dport: object = _UNSET,
    ) -> None:
        """
        Assert that the given 'TcpProbe' matches every supplied field.
        Fields left at the '_UNSET' sentinel are not checked. Pass
        'None' explicitly to assert that an option-bearing field
        ('mss', 'wscale') is absent from the wire.
        """

        if flags is not _UNSET:
            assert flags is not None, "'flags' must be an iterable of flag names, not None."
            # Connection-control flags only; ECN-related
            # flags (ECE, CWR, NS) are orthogonal and are
            # asserted directly via 'probe.flags' in the
            # ECN-specific tests. This lets non-ECN tests
            # specify expected flags as
            # 'frozenset({"SYN"})' without having to
            # enumerate the ECN advertisement state of
            # every active-open SYN.
            connection_control = frozenset({"SYN", "ACK", "FIN", "RST", "PSH", "URG"})
            self.assertEqual(
                probe.flags & connection_control,
                frozenset(cast(Iterable[str], flags)) & connection_control,
                msg=f"Unexpected TCP flag set on outbound segment: {probe!r}",
            )
        if seq is not _UNSET:
            self.assertEqual(
                probe.seq,
                seq,
                msg=f"Unexpected TCP seq on outbound segment: {probe!r}",
            )
        if ack is not _UNSET:
            self.assertEqual(
                probe.ack,
                ack,
                msg=f"Unexpected TCP ack on outbound segment: {probe!r}",
            )
        if payload is not _UNSET:
            self.assertEqual(
                probe.payload,
                payload,
                msg=f"Unexpected TCP payload on outbound segment: {probe!r}",
            )
        if win is not _UNSET:
            self.assertEqual(
                probe.win,
                win,
                msg=f"Unexpected TCP advertised window on outbound segment: {probe!r}",
            )
        if mss is not _UNSET:
            self.assertEqual(
                probe.mss,
                mss,
                msg=f"Unexpected TCP MSS option on outbound segment: {probe!r}",
            )
        if wscale is not _UNSET:
            self.assertEqual(
                probe.wscale,
                wscale,
                msg=f"Unexpected TCP WSCALE option on outbound segment: {probe!r}",
            )
        if sackperm is not _UNSET:
            self.assertEqual(
                probe.sackperm,
                sackperm,
                msg=f"Unexpected TCP SACK-permitted option on outbound segment: {probe!r}",
            )
        if sack_blocks is not _UNSET:
            expected_blocks: tuple[tuple[int, int], ...] = (
                () if sack_blocks is None else tuple(cast(Iterable[tuple[int, int]], sack_blocks))
            )
            self.assertEqual(
                probe.sack_blocks,
                expected_blocks,
                msg=f"Unexpected TCP SACK blocks on outbound segment: {probe!r}",
            )
        if sport is not _UNSET:
            self.assertEqual(
                probe.sport,
                sport,
                msg=f"Unexpected TCP sport on outbound segment: {probe!r}",
            )
        if dport is not _UNSET:
            self.assertEqual(
                probe.dport,
                dport,
                msg=f"Unexpected TCP dport on outbound segment: {probe!r}",
            )

    def _assert_no_tx(self) -> None:
        """
        Assert that no TX frames have been recorded since the last
        explicit drain (tests that drain via '_drive_rx' / '_advance'
        get a fresh list back; this method checks the global slot).
        """

        self.assertEqual(
            self._frames_tx,
            [],
            msg=f"Expected no TX frames, got {len(self._frames_tx)}: {self._frames_tx!r}",
        )
