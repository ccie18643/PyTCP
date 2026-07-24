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
Integration tests pinning the behavioural surfaces of the
per-connection 'TCP_USER_TIMEOUT' (M6) and 'TCP_MAXSEG' (M7)
overrides — the spec rows of
'docs/refactor/socket_linux_parity_audit.md'. The unit tests
in 'test__socket__tcp__socket.py::TestTcpSocketOptions' pin the
setsockopt/getsockopt round-trip and the propagation from
socket → freshly-constructed session; this file pins what the
session does once the overrides are in place — the M7 SYN MSS
clamp on outbound SYN and the M6 R2-abort budget reduction.

pytcp/tests/integration/socket/test__socket__tcp_user_options.py

ver 3.0.9
"""

import struct

from net_addr import Ip4Address
from pytcp.protocols.tcp.tcp__enums import ConnError, FsmState, SysCall
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_testcase import TcpTestCase

STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80
LOCAL__ISS: int = 0x0000_1000


# Offsets inside an Ethernet+IPv4+TCP frame for extracting the
# TCP MSS option from a SYN. Ethernet header = 14 bytes; IPv4
# header (no options on SYN) = 20 bytes; TCP fixed header = 20
# bytes; then TCP options. The MSS option is wired as
# 'kind=2, len=4, mss=uint16-be' (RFC 9293 §3.2). On SYN the
# MSS option is always the FIRST option (codified by the
# assembler in tcp__assembler.py).
_ETH__HEADER__LEN: int = 14
_IP4__HEADER__LEN: int = 20
_TCP__FIXED_HEADER__LEN: int = 20
_TCP_OPTIONS__OFFSET: int = _ETH__HEADER__LEN + _IP4__HEADER__LEN + _TCP__FIXED_HEADER__LEN
_TCP_OPTION__KIND_MSS: int = 2


def _mss_from_syn_frame(frame: bytes, /) -> int:
    """
    Extract the MSS option's wire value from a SYN Ethernet
    frame. Walks the TCP options looking for kind=2 (MSS).
    """

    # Confirm it's IPv4 / TCP first.
    # 0x0800 is the EtherType.IP4 wire codepoint; compared as
    # int because ProtoEnum members do not equality-match ints.
    assert int.from_bytes(frame[12:14], "big") == 0x0800
    options = frame[_TCP_OPTIONS__OFFSET:]
    idx = 0
    while idx < len(options):
        kind = options[idx]
        if kind == 0:  # End-of-Options.
            break
        if kind == 1:  # NOP — single-byte.
            idx += 1
            continue
        opt_len = options[idx + 1]
        if kind == _TCP_OPTION__KIND_MSS:
            (mss,) = struct.unpack("!H", options[idx + 2 : idx + 4])
            return int(mss)
        idx += opt_len
    raise AssertionError("MSS option not found in SYN")


class TestTcpMaxsegSynClamp(TcpTestCase):
    """
    'TCP_MAXSEG' SYN-options clamp tests — M7 of the socket-
    layer Linux parity audit.
    """

    def test__tcp_maxseg__zero_override_emits_rcv_mss(self) -> None:
        """
        Ensure the SYN-emitted MSS option carries the
        session's 'rcv_mss' value when no clamp is set
        ('_maxseg_override == 0', the default). Regression
        pin on the pre-M7 baseline.

        Reference: RFC 9293 §3.7.1 (MSS option default).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session._maxseg_override = 0
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        # The harness records every emitted frame in
        # 'self._frames_tx'. The first emitted frame after
        # CONNECT is the active-open SYN.
        self.assertGreaterEqual(
            len(self._frames_tx),
            1,
            msg="CONNECT must emit a SYN frame.",
        )
        emitted_mss = _mss_from_syn_frame(self._frames_tx[0])
        self.assertEqual(
            emitted_mss,
            session._win.rcv_mss,
            msg="SYN MSS option must carry session.rcv_mss when no clamp is set.",
        )

    def test__tcp_maxseg__positive_override_clamps_syn_mss(self) -> None:
        """
        Ensure setting 'session._maxseg_override = 1200'
        clamps the SYN-emitted MSS option to 1200 even though
        the session's 'rcv_mss' is higher (the egress
        interface MTU - overhead).

        Reference: RFC 9293 §3.7.1 (MSS option emission).
        Reference: Linux TCP_MAXSEG (SYN-option clamp).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session._maxseg_override = 1200
        # Sanity — without the clamp, the session would emit
        # the harness's default rcv_mss (the egress-interface
        # MTU minus IP+TCP overhead, > 1200 on the canonical
        # 1500-MTU TAP fixture).
        self.assertGreater(
            session._win.rcv_mss,
            1200,
            msg="Fixture precondition: harness rcv_mss > 1200.",
        )

        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        emitted_mss = _mss_from_syn_frame(self._frames_tx[0])
        self.assertEqual(
            emitted_mss,
            1200,
            msg="SYN MSS option must clamp at _maxseg_override (1200).",
        )

    def test__tcp_maxseg__override_above_rcv_mss_is_ineffective(self) -> None:
        """
        Ensure an override greater than the session's
        'rcv_mss' does NOT inflate the SYN MSS option past
        the actual stack-supported value — Linux clamps the
        socket-API value DOWN to the kernel's RX ceiling but
        never advertises a higher MSS than the stack can
        receive.

        Reference: RFC 9293 §3.7.1 (MSS option emission ≤ RX capacity).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session._maxseg_override = 0xFFFE  # Just under the uint16 ceiling.
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        emitted_mss = _mss_from_syn_frame(self._frames_tx[0])
        self.assertEqual(
            emitted_mss,
            session._win.rcv_mss,
            msg="An override above rcv_mss must not inflate the advertised MSS past rcv_mss.",
        )


class TestTcpUserTimeoutR2Abort(TcpTestCase):
    """
    'TCP_USER_TIMEOUT' R2-abort budget tests — M6 of the
    socket-layer Linux parity audit.
    """

    def test__tcp_user_timeout__zero_override_uses_default_budget(self) -> None:
        """
        Ensure '_user_timeout_ms == 0' (the default) leaves
        the R2 abort gated by the system-default budget
        ('TCP__RETRANSMIT__MAX_COUNT'). Regression pin on the
        pre-M6 baseline — driving fewer than the default
        budget worth of retransmits must NOT abort.

        Reference: RFC 1122 §4.2.3.5 R2 (default retransmit budget).
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=0x0000_2000,
        )
        session._user_timeout_ms = 0
        # Buffer some data so retransmits are non-trivial.
        session._tx.buffer.extend(b"A" * 100)
        session._cc.snd_ewn = 1000
        session._transmit_data()

        # Force-set the retransmit counter to one less than
        # the budget; one more timeout would abort. Verify
        # that with no override the abort is NOT armed yet —
        # the connection is still ESTABLISHED.
        from pytcp.protocols.tcp import tcp__constants

        session._retransmit_count = tcp__constants.TCP__RETRANSMIT__MAX_COUNT - 1

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Pre-budget-exhausted: session must still be ESTABLISHED.",
        )

    def test__tcp_user_timeout__positive_override_shrinks_budget(self) -> None:
        """
        Ensure a small '_user_timeout_ms' override reduces
        the effective R2 budget below the system default —
        the abort fires after the user's wall-time budget
        elapses under the current RTO. Concretely: with
        rto_ms = 1000 (initial-RTO default) and
        user_timeout_ms = 1500, the approximated count
        budget is max(1, 1500 // 1000) = 1, so the abort
        fires on the FIRST retransmit beyond cum-ACK
        progress.

        Reference: Linux net.ipv4.tcp_user_timeout (R2-abort time budget).
        Reference: RFC 6298 §2.1 (initial RTO 1 second).
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=0x0000_2000,
        )
        # 1500 ms / 1000 ms RTO ≈ 1-segment budget; the
        # first retransmit (count 1) trips the abort.
        session._user_timeout_ms = 1500
        # Buffer some data so the retransmit path is reachable.
        session._tx.buffer.extend(b"A" * 100)
        session._cc.snd_ewn = 1000
        session._transmit_data()

        # Drive past the budget by firing one RTO worth.
        session._retransmit_count = 1
        # Force the retransmit timer to expire on the next
        # tick so the abort path actually runs.
        session._timers.arm("retransmit", 0)
        self._advance(ms=2)

        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=(
                "With user_timeout=1500 ms and RTO=1000 ms, retransmit_count=1 must "
                "exhaust the approximated budget and abort to CLOSED."
            ),
        )
        self.assertIs(
            session._connection_error,
            ConnError.TIMEOUT,
            msg="Abort path must surface ConnError.TIMEOUT to the application.",
        )
