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
This module contains tests for the 'TcpSession' FSM state-transition
handlers ('_tcp_fsm_closed' through '_tcp_fsm_time_wait') and the
top-level 'tcp_fsm' dispatch.

pytcp/tests/unit/protocols/tcp/fsm/test__tcp__fsm.py

ver 3.0.8
"""

from types import SimpleNamespace
from typing import cast
from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_addr import Ip4Address, IpVersion
from pytcp import stack
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
from pytcp.socket.socket_table import SocketTable
from pytcp.socket.tcp__metadata import TcpMetadata

_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """Silence the stack log channels for this module's tests."""

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """Restore the original log channels after this module's tests."""

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


class _TcpSessionFsmFixture(TestCase):
    """
    Shared fixture that stubs the stack timer, interface MTU, socket
    registry, and logging so FSM state transitions can be driven
    without a running stack.
    """

    def setUp(self) -> None:
        """
        Install per-test stack patches and expose the timer mock on
        'self' so individual tests can observe scheduler calls.
        """

        self._timer = SimpleNamespace(
            call_periodic=MagicMock(),
            cancel=MagicMock(),
            call_later=MagicMock(),
            now_ms=0,
        )
        self._timer_patch = patch(
            "pytcp.protocols.tcp.session.tcp__session.stack.timer",
            self._timer,
        )
        self._timer_patch.start()

        self._mtu_patch = patch(
            "pytcp.protocols.tcp.session.tcp__session.stack.egress_interface_mtu",
            return_value=1500,
        )
        self._mtu_patch.start()

        self._sockets = SocketTable()
        self._sockets_patch = patch(
            "pytcp.protocols.tcp.session.tcp__session.stack.sockets",
            self._sockets,
        )
        self._sockets_patch.start()

        self._log_patch = patch("pytcp.protocols.tcp.session.tcp__session.log")
        self._log_patch.start()

    def tearDown(self) -> None:
        """
        Remove the stack patches.
        """

        self._timer_patch.stop()
        self._mtu_patch.stop()
        self._sockets_patch.stop()
        self._log_patch.stop()

    def _make_session(self) -> TcpSession:
        """
        Build a canonical IPv4 TcpSession with a mock socket.
        """

        mock_socket = MagicMock()
        mock_socket.socket_id = object()  # unique sentinel for dict keys
        self._sockets[mock_socket.socket_id] = mock_socket

        return TcpSession(
            local_ip_address=Ip4Address("10.0.0.1"),
            local_port=8080,
            remote_ip_address=Ip4Address("10.0.0.2"),
            remote_port=44444,
            socket=mock_socket,
        )


class TestTcpSessionChangeState(_TcpSessionFsmFixture):
    """
    The '_change_state' helper tests.
    """

    def test__tcp_session__change_state_updates_state(self) -> None:
        """
        Ensure '_change_state' writes the new state into '_state'.
        Reference: RFC 9293 §3.3.2 (state machine).
        """

        session = self._make_session()
        session._change_state(FsmState.LISTEN)

        self.assertIs(
            session.state,
            FsmState.LISTEN,
            msg="_change_state must update the '_state' attribute.",
        )

    def test__tcp_session__change_state_to_closed_unregisters(self) -> None:
        """
        Ensure transitioning to 'CLOSED' pops the associated socket
        from 'stack.sockets' — this is how closed sessions stop
        receiving packets.
        Reference: RFC 9293 §3.3.2 (CLOSED state) + §3.10.4 (CLOSE call).
        """

        session = self._make_session()
        session._state = FsmState.ESTABLISHED

        session._change_state(FsmState.CLOSED)

        self.assertNotIn(
            session.socket.socket_id,
            self._sockets,
            msg="Transitioning to CLOSED must unregister the socket from stack.sockets.",
        )


class TestTcpFsmClosed(_TcpSessionFsmFixture):
    """
    The '_tcp_fsm_closed' state-handler tests.
    """

    def test__tcp_session__closed_connect_to_syn_sent(self) -> None:
        """
        Ensure CONNECT from the CLOSED state transitions the
        FSM to 'SYN_SENT'. This is the active-open path.

        Reference: RFC 9293 §3.10.1 (OPEN call, active open).
        """

        session = self._make_session()
        session.tcp_fsm(syscall=SysCall.CONNECT)

        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg="CONNECT from CLOSED must transition to FsmState.SYN_SENT.",
        )

    def test__tcp_session__closed_listen_to_listen(self) -> None:
        """
        Ensure LISTEN from the CLOSED state transitions the
        FSM to 'LISTEN'. This is the passive-open path.

        Reference: RFC 9293 §3.10.1 (OPEN call, passive open).
        """

        session = self._make_session()
        session.tcp_fsm(syscall=SysCall.LISTEN)

        self.assertIs(
            session.state,
            FsmState.LISTEN,
            msg="LISTEN from CLOSED must transition to FsmState.LISTEN.",
        )

    def test__tcp_session__closed_ignores_close(self) -> None:
        """
        Ensure CLOSE in the CLOSED state is a no-op - the FSM
        stays put and does not crash.

        Reference: RFC 9293 §3.10.4 (CLOSE call from CLOSED).
        """

        session = self._make_session()
        session.tcp_fsm(syscall=SysCall.CLOSE)

        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="CLOSE in CLOSED must leave the FSM in CLOSED.",
        )


class TestTcpFsmListen(_TcpSessionFsmFixture):
    """
    The '_tcp_fsm_listen' state-handler tests.
    """

    def test__tcp_session__listen_close_to_closed(self) -> None:
        """
        Ensure CLOSE in the LISTEN state transitions the FSM
        to 'CLOSED'. Canonical server shutdown path.

        Reference: RFC 9293 §3.10.4 (CLOSE call from LISTEN).
        """

        session = self._make_session()
        session._state = FsmState.LISTEN

        session.tcp_fsm(syscall=SysCall.CLOSE)

        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="CLOSE from LISTEN must transition to FsmState.CLOSED.",
        )


class TestTcpFsmSynSent(_TcpSessionFsmFixture):
    """
    The '_tcp_fsm_syn_sent' state-handler tests.
    """

    def test__tcp_session__syn_sent_close_to_closed(self) -> None:
        """
        Ensure CLOSE in the SYN_SENT state transitions the FSM
        to 'CLOSED'. Happens when the caller abandons a
        pending connect.

        Reference: RFC 9293 §3.10.4 (CLOSE call from SYN-SENT).
        """

        session = self._make_session()
        session._state = FsmState.SYN_SENT

        session.tcp_fsm(syscall=SysCall.CLOSE)

        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="CLOSE from SYN_SENT must transition to FsmState.CLOSED.",
        )

    def test__tcp_session__syn_sent_simultaneous_open_to_syn_rcvd(self) -> None:
        """
        Ensure a bare SYN packet received while in SYN_SENT
        triggers the simultaneous-open branch - the FSM
        transitions to SYN_RCVD and a SYN+ACK is sent.

        Reference: RFC 9293 §3.10.7.3 (simultaneous open).
        """

        session = self._make_session()
        session._state = FsmState.SYN_SENT

        metadata = TcpMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=Ip4Address("10.0.0.1"),
            ip__remote_address=Ip4Address("10.0.0.2"),
            tcp__local_port=8080,
            tcp__remote_port=44444,
            tcp__flag_syn=True,
            tcp__flag_ack=False,
            tcp__flag_fin=False,
            tcp__flag_rst=False,
            tcp__flag_ece=False,
            tcp__flag_cwr=False,
            tcp__seq=12345,
            tcp__ack=0,
            tcp__win=65535,
            tcp__wscale=0,
            tcp__mss=1460,
            tcp__sackperm=False,
            tcp__sack_blocks=(),
            tcp__data=memoryview(b""),
        )

        with patch.object(session, "_transmit_packet") as mock_transmit:
            session.tcp_fsm(packet_rx_md=metadata)

        self.assertIs(
            session.state,
            FsmState.SYN_RCVD,
            msg="A bare SYN in SYN_SENT must transition to SYN_RCVD (simultaneous open).",
        )
        # Post-Bug-C fix: simultaneous-open emits SYN+ACK with
        # seq=self._snd_seq.ini (reuses original SYN's seq) rather
        # than letting it default to self._snd_seq.nxt (which would
        # have advanced past LOCAL__ISS to LOCAL__ISS+1 from the
        # initial SYN). The fix bootstraps peer state and emits
        # SYN+ACK at the original SYN's seq so peer accepts it.
        mock_transmit.assert_called_once_with(flag_syn=True, flag_ack=True, seq=session._snd_seq.ini)


class TestTcpFsmEstablished(_TcpSessionFsmFixture):
    """
    The '_tcp_fsm_established' state-handler tests.
    """

    def test__tcp_session__established_close_sets_closing_flag(self) -> None:
        """
        Ensure CLOSE in 'ESTABLISHED' sets the '_closing' flag
        without changing state immediately - the session only
        transitions to 'FIN_WAIT_1' once the TX buffer has
        been flushed (handled in the timer branch).

        Reference: RFC 9293 §3.10.4 (CLOSE call from ESTABLISHED).
        """

        session = self._make_session()
        session._state = FsmState.ESTABLISHED

        session.tcp_fsm(syscall=SysCall.CLOSE)

        self.assertTrue(
            session._closing,
            msg="CLOSE in ESTABLISHED must set the _closing flag.",
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="CLOSE in ESTABLISHED must NOT change state immediately — waits for TX flush.",
        )


class TestTcpFsmSynRcvd(_TcpSessionFsmFixture):
    """
    The '_tcp_fsm_syn_rcvd' state-handler tests.
    """

    def test__tcp_session__syn_rcvd_close_to_fin_wait_1(self) -> None:
        """
        Ensure CLOSE from 'SYN_RCVD' transitions the FSM to
        'FIN_WAIT_1' so the session can emit a FIN and begin
        active close without waiting for the peer's data path.

        Reference: RFC 9293 §3.10.4 (CLOSE call from SYN-RECEIVED).
        """

        session = self._make_session()
        session._state = FsmState.SYN_RCVD

        session.tcp_fsm(syscall=SysCall.CLOSE)

        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="CLOSE from SYN_RCVD must transition to FsmState.FIN_WAIT_1.",
        )


class TestTcpFsmCloseWait(_TcpSessionFsmFixture):
    """
    The '_tcp_fsm_close_wait' state-handler tests.
    """

    def test__tcp_session__close_wait_close_sets_closing_flag(self) -> None:
        """
        Ensure CLOSE from 'CLOSE_WAIT' sets the '_closing'
        flag - the actual transition to 'LAST_ACK' happens
        once the TX buffer drains (in the timer branch).

        Reference: RFC 9293 §3.10.4 (CLOSE call from CLOSE-WAIT).
        """

        session = self._make_session()
        session._state = FsmState.CLOSE_WAIT

        session.tcp_fsm(syscall=SysCall.CLOSE)

        self.assertTrue(
            session._closing,
            msg="CLOSE in CLOSE_WAIT must set the _closing flag.",
        )
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg="CLOSE in CLOSE_WAIT must NOT change state immediately — waits for TX flush.",
        )


class TestTcpFsmDispatch(_TcpSessionFsmFixture):
    """
    The top-level 'tcp_fsm' dispatch tests.
    """

    def test__tcp_session__fsm_dispatches_packet_by_current_state(self) -> None:
        """
        Ensure 'tcp_fsm' routes an inbound-packet event to the
        per-state packet handler matching the current '_state'.
        Exercised by seeding each packet-handling state in turn
        and verifying the corresponding entry in
        FSM_PACKET_HANDLERS was called with the packet metadata.

        Reference: RFC 9293 §3.3.2 (state machine dispatch).
        """

        from pytcp.protocols.tcp.fsm.tcp__fsm import FSM_PACKET_HANDLERS

        dummy_md = MagicMock()
        for state in FSM_PACKET_HANDLERS:
            with self.subTest(state=state):
                session = self._make_session()
                session._state = state
                mock_handler = MagicMock()
                with patch.dict(FSM_PACKET_HANDLERS, {state: mock_handler}):
                    session.tcp_fsm(packet_rx_md=dummy_md)
                mock_handler.assert_called_once_with(session, dummy_md)

    def test__tcp_session__fsm_dispatches_syscall_by_current_state(self) -> None:
        """
        Ensure 'tcp_fsm' routes a syscall event to the per-state
        syscall handler matching the current '_state'.

        Reference: RFC 9293 §3.3.2 (state machine dispatch).
        """

        from pytcp.protocols.tcp.fsm.tcp__fsm import FSM_SYSCALL_HANDLERS
        from pytcp.protocols.tcp.tcp__enums import SysCall

        for state in FSM_SYSCALL_HANDLERS:
            with self.subTest(state=state):
                session = self._make_session()
                session._state = state
                mock_handler = MagicMock()
                with patch.dict(FSM_SYSCALL_HANDLERS, {state: mock_handler}):
                    session.tcp_fsm(syscall=SysCall.CLOSE)
                mock_handler.assert_called_once_with(session, SysCall.CLOSE)

    def test__tcp_session__fsm_dispatches_timer_by_current_state(self) -> None:
        """
        Ensure 'tcp_fsm' routes a timer-tick event to the
        per-state timer handler matching the current '_state'.

        Reference: RFC 9293 §3.3.2 (state machine dispatch).
        """

        from pytcp.protocols.tcp.fsm.tcp__fsm import FSM_TIMER_HANDLERS

        for state in FSM_TIMER_HANDLERS:
            with self.subTest(state=state):
                session = self._make_session()
                session._state = state
                mock_handler = MagicMock()
                with patch.dict(FSM_TIMER_HANDLERS, {state: mock_handler}):
                    session.tcp_fsm(timer=True)
                mock_handler.assert_called_once_with(session)


class TestTcpFsmIcmpDispatch(_TcpSessionFsmFixture):
    """
    The top-level 'tcp_fsm(icmp=...)' dispatch tests.
    """

    def test__tcp_session__fsm_dispatches_icmp_by_current_state(self) -> None:
        """
        Ensure 'tcp_fsm' routes an inbound-ICMP event to the
        per-state ICMP handler matching the current '_state' via
        FSM_ICMP_HANDLERS, mirroring the packet / syscall / timer
        dispatch tables. The dispatch table is the routing layer;
        per-state handlers carry the hard-vs-soft semantics.

        Reference: RFC 9293 §3.3.2 (state machine dispatch).
        Reference: RFC 5927 §5.2 (per-state ICMP-error handling).
        """

        from pytcp.protocols.tcp.fsm.tcp__fsm import FSM_ICMP_HANDLERS
        from pytcp.protocols.tcp.tcp__icmp_metadata import (
            IcmpCategory,
            IcmpMetadata,
        )

        metadata = IcmpMetadata(
            category=IcmpCategory.DEST_UNREACHABLE,
            icmp_type=3,
            icmp_code=3,
            ip_version=4,
        )
        for state in FSM_ICMP_HANDLERS:
            with self.subTest(state=state):
                session = self._make_session()
                session._state = state
                mock_handler = MagicMock()
                with patch.dict(FSM_ICMP_HANDLERS, {state: mock_handler}):
                    session.tcp_fsm(icmp=metadata)
                mock_handler.assert_called_once_with(session, metadata)

    def test__tcp_session__fsm_icmp_does_not_invoke_packet_or_syscall_or_timer(self) -> None:
        """
        Ensure 'tcp_fsm(icmp=...)' does NOT also route through the
        packet, syscall, or timer dispatchers. The four event sources
        are mutually exclusive at the dispatch level; a stray fan-out
        would silently double-process events.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp.protocols.tcp.tcp__icmp_metadata import (
            IcmpCategory,
            IcmpMetadata,
        )

        session = self._make_session()

        with (
            patch("pytcp.protocols.tcp.session.tcp__session.tcp_fsm_dispatch_packet") as mock_packet,
            patch("pytcp.protocols.tcp.session.tcp__session.tcp_fsm_dispatch_syscall") as mock_syscall,
            patch("pytcp.protocols.tcp.session.tcp__session.tcp_fsm_dispatch_timer") as mock_timer,
        ):
            session._state = FsmState.ESTABLISHED  # any synchronized state
            session.tcp_fsm(
                icmp=IcmpMetadata(
                    category=IcmpCategory.TIME_EXCEEDED,
                    icmp_type=11,
                    icmp_code=0,
                    ip_version=4,
                ),
            )

        mock_packet.assert_not_called()
        mock_syscall.assert_not_called()
        mock_timer.assert_not_called()


class TestTcpFsmListenHandleIcmp(_TcpSessionFsmFixture):
    """
    The 'fsm__listen__icmp' state-handler tests.
    """

    def test__tcp_session__listen_icmp_is_no_op(self) -> None:
        """
        Ensure ICMP errors received against a LISTEN session do not
        mutate FSM state, set a connection error, or release the
        accept-blocked syscall. A passive listener has no per-flow
        flight to abort and no blocked CONNECT to wake; the ICMP error
        is purely informational and must be a no-op.

        Reference: RFC 5927 §5.2 (synchronized-state ICMP errors are
        advisory; the LISTEN equivalent is a no-op since there is no
        connection at risk).
        """

        from pytcp.protocols.tcp.tcp__icmp_metadata import (
            IcmpCategory,
            IcmpMetadata,
        )

        session = self._make_session()
        session._state = FsmState.LISTEN

        session.tcp_fsm(
            icmp=IcmpMetadata(
                category=IcmpCategory.DEST_UNREACHABLE,
                icmp_type=3,
                icmp_code=3,
                ip_version=4,
            ),
        )

        from pytcp.protocols.tcp.tcp__enums import ConnError

        self.assertIs(
            session.state,
            FsmState.LISTEN,
            msg="LISTEN session must stay in LISTEN on ICMP error.",
        )
        self.assertIs(
            session._connection_error,
            ConnError.NONE,
            msg="LISTEN session must not record a connection error on ICMP.",
        )


class TestTcpFsmSynSentHandleIcmp(_TcpSessionFsmFixture):
    """
    The 'fsm__syn_sent__icmp' state-handler tests covering the RFC
    5927 §6 hard-vs-soft taxonomy.
    """

    def _drive_icmp(self, *, icmp_type: int, icmp_code: int) -> "TcpSession":
        """
        Build a SYN_SENT session and drive a Dest-Unreachable ICMP
        event of the given type/code through the FSM. Returns the
        post-event session for assertion.
        """

        from pytcp.protocols.tcp.tcp__icmp_metadata import (
            IcmpCategory,
            IcmpMetadata,
        )

        session = self._make_session()
        session._state = FsmState.SYN_SENT
        session.tcp_fsm(
            icmp=IcmpMetadata(
                category=IcmpCategory.DEST_UNREACHABLE,
                icmp_type=icmp_type,
                icmp_code=icmp_code,
                ip_version=4 if icmp_type == 3 else 6,
            ),
        )
        return session

    def test__tcp_session__syn_sent_icmp_v4_port_unreachable_aborts(self) -> None:
        """
        Ensure SYN_SENT receiving ICMPv4 Type 3 / Code 3 (Port
        Unreachable) aborts the connection: state -> CLOSED, error ->
        REFUSED.

        Reference: RFC 1122 §3.2.2.1 (ICMP Port Unreachable in
        SYN_SENT MUST abort).
        Reference: RFC 5927 §5.2 (ICMPv4 Code 3 Port Unreachable is a
        hard error).
        """

        from pytcp.protocols.tcp.tcp__enums import ConnError

        session = self._drive_icmp(icmp_type=3, icmp_code=3)

        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="SYN_SENT + Port Unreachable must transition to CLOSED.",
        )
        self.assertIs(
            session._connection_error,
            ConnError.REFUSED,
            msg="SYN_SENT + Port Unreachable must record ConnError.REFUSED.",
        )

    def test__tcp_session__syn_sent_icmp_v4_protocol_unreachable_aborts(self) -> None:
        """
        Ensure SYN_SENT receiving ICMPv4 Type 3 / Code 2 (Protocol
        Unreachable) aborts with REFUSED. The per-state handler
        treats Code 2 as a hard error matching the canonical hard-
        error list, closing a historical gap where Code 2 was
        silently no-op'd.

        Reference: RFC 5927 §5.2 (ICMPv4 Code 2 Protocol Unreachable
        is a hard error).
        Reference: RFC 1122 §4.2.3.9 (TCP SHOULD abort on hard error).
        """

        from pytcp.protocols.tcp.tcp__enums import ConnError

        session = self._drive_icmp(icmp_type=3, icmp_code=2)

        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="SYN_SENT + Protocol Unreachable must transition to CLOSED.",
        )
        self.assertIs(
            session._connection_error,
            ConnError.REFUSED,
            msg="SYN_SENT + Protocol Unreachable must record ConnError.REFUSED.",
        )

    def test__tcp_session__syn_sent_icmp_v6_admin_prohibited_aborts(self) -> None:
        """
        Ensure SYN_SENT receiving ICMPv6 Type 1 / Code 1 (admin
        prohibited) aborts with REFUSED. The §5.2 extrapolation of
        hard errors to ICMPv6 explicitly enumerates Code 1 alongside
        Code 4 (port unreachable).

        Reference: RFC 5927 §5.2 (ICMPv6 Code 1 admin-prohibited is a
        hard error).
        Reference: RFC 4443 §3.1 (ICMPv6 Destination Unreachable).
        """

        from pytcp.protocols.tcp.tcp__enums import ConnError

        session = self._drive_icmp(icmp_type=1, icmp_code=1)

        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="SYN_SENT + ICMPv6 Admin-Prohibited must transition to CLOSED.",
        )
        self.assertIs(
            session._connection_error,
            ConnError.REFUSED,
            msg="SYN_SENT + ICMPv6 Admin-Prohibited must record ConnError.REFUSED.",
        )

    def test__tcp_session__syn_sent_icmp_v6_port_unreachable_aborts(self) -> None:
        """
        Ensure SYN_SENT receiving ICMPv6 Type 1 / Code 4 (port
        unreachable) aborts with REFUSED.

        Reference: RFC 5927 §5.2 (ICMPv6 Code 4 Port Unreachable is a
        hard error).
        Reference: RFC 4443 §3.1 (ICMPv6 Destination Unreachable).
        """

        from pytcp.protocols.tcp.tcp__enums import ConnError

        session = self._drive_icmp(icmp_type=1, icmp_code=4)

        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="SYN_SENT + ICMPv6 Port Unreachable must transition to CLOSED.",
        )
        self.assertIs(
            session._connection_error,
            ConnError.REFUSED,
            msg="SYN_SENT + ICMPv6 Port Unreachable must record ConnError.REFUSED.",
        )

    def test__tcp_session__syn_sent_icmp_v4_host_unreachable_is_advisory(self) -> None:
        """
        Ensure SYN_SENT receiving ICMPv4 Type 3 / Code 1 (Host
        Unreachable) records HOST_UNREACHABLE and releases the blocked
        CONNECT but does NOT abort the FSM — Net/Host Unreachable are
        hint-not-proof soft errors.

        Reference: RFC 5927 §6 (Net/Host Unreachable are hint-not-proof
        soft errors).
        Reference: RFC 1122 §4.2.3.9 (Net/Host Unreachable SHOULD merely
        be informed to the user, not used to abort).
        """

        from pytcp.protocols.tcp.tcp__enums import ConnError

        session = self._drive_icmp(icmp_type=3, icmp_code=1)

        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg="SYN_SENT + Host Unreachable must remain in SYN_SENT (advisory).",
        )
        self.assertIs(
            session._connection_error,
            ConnError.HOST_UNREACHABLE,
            msg="SYN_SENT + Host Unreachable must record ConnError.HOST_UNREACHABLE.",
        )

    def test__tcp_session__syn_sent_icmp_v4_net_unreachable_is_advisory(self) -> None:
        """
        Ensure SYN_SENT receiving ICMPv4 Type 3 / Code 0 (Net
        Unreachable) records NET_UNREACHABLE and releases the blocked
        CONNECT but does NOT abort.

        Reference: RFC 5927 §6 (Net/Host Unreachable are hint-not-proof
        soft errors).
        """

        from pytcp.protocols.tcp.tcp__enums import ConnError

        session = self._drive_icmp(icmp_type=3, icmp_code=0)

        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg="SYN_SENT + Net Unreachable must remain in SYN_SENT (advisory).",
        )
        self.assertIs(
            session._connection_error,
            ConnError.NET_UNREACHABLE,
            msg="SYN_SENT + Net Unreachable must record ConnError.NET_UNREACHABLE.",
        )

    def test__tcp_session__syn_sent_icmp_time_exceeded_is_soft(self) -> None:
        """
        Ensure SYN_SENT receiving ICMP Time Exceeded does NOT abort
        the connection — Time Exceeded is always a soft error.

        Reference: RFC 5927 §6 (Time Exceeded is a soft error).
        Reference: RFC 1122 §3.2.2.4 (Time Exceeded MUST be passed to
        the transport layer).
        """

        from pytcp.protocols.tcp.tcp__enums import ConnError
        from pytcp.protocols.tcp.tcp__icmp_metadata import (
            IcmpCategory,
            IcmpMetadata,
        )

        session = self._make_session()
        session._state = FsmState.SYN_SENT
        session.tcp_fsm(
            icmp=IcmpMetadata(
                category=IcmpCategory.TIME_EXCEEDED,
                icmp_type=11,
                icmp_code=0,
                ip_version=4,
            ),
        )

        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg="SYN_SENT + Time Exceeded must remain in SYN_SENT (soft error).",
        )
        self.assertIs(
            session._connection_error,
            ConnError.NONE,
            msg="SYN_SENT + Time Exceeded must NOT record a connection error.",
        )


class TestTcpFsmSynchronizedHandleIcmp(_TcpSessionFsmFixture):
    """
    The synchronized-state ICMP-handler tests covering RFC 5927 §5.2's
    counter-measure: hard errors are downgraded to soft once the
    connection has reached a synchronized state.
    """

    _SYNCHRONIZED_STATES = (
        FsmState.SYN_RCVD,
        FsmState.ESTABLISHED,
        FsmState.FIN_WAIT_1,
        FsmState.FIN_WAIT_2,
        FsmState.CLOSE_WAIT,
        FsmState.CLOSING,
        FsmState.LAST_ACK,
        FsmState.TIME_WAIT,
    )

    def test__tcp_session__synchronized_icmp_hard_codes_are_soft(self) -> None:
        """
        Ensure hard-error Dest-Unreachable codes (v4 Code 2/3, v6 Code
        1/4) received in any synchronized state are downgraded to soft
        — no FSM transition, no connection error. This is the
        counter-measure for the blind connection-reset attack.

        Reference: RFC 5927 §5.2 (synchronized-state hard errors are
        treated as soft).
        Reference: RFC 1122 §4.2.3.9 (TCP MUST react to ICMP).
        """

        from pytcp.protocols.tcp.tcp__enums import ConnError
        from pytcp.protocols.tcp.tcp__icmp_metadata import (
            IcmpCategory,
            IcmpMetadata,
        )

        for state in self._SYNCHRONIZED_STATES:
            for icmp_type, icmp_code in (
                (3, 2),  # ICMPv4 Protocol Unreachable
                (3, 3),  # ICMPv4 Port Unreachable
                (1, 1),  # ICMPv6 Admin Prohibited
                (1, 4),  # ICMPv6 Port Unreachable
            ):
                with self.subTest(state=state, icmp_type=icmp_type, icmp_code=icmp_code):
                    session = self._make_session()
                    session._state = state

                    session.tcp_fsm(
                        icmp=IcmpMetadata(
                            category=IcmpCategory.DEST_UNREACHABLE,
                            icmp_type=icmp_type,
                            icmp_code=icmp_code,
                            ip_version=4 if icmp_type == 3 else 6,
                        ),
                    )

                    self.assertIs(
                        session.state,
                        state,
                        msg=(
                            f"{state} + ICMP type={icmp_type} code={icmp_code} must NOT "
                            "transition (hard-as-soft per RFC 5927 §5.2)."
                        ),
                    )
                    self.assertIs(
                        session._connection_error,
                        ConnError.NONE,
                        msg=(
                            f"{state} + ICMP type={icmp_type} code={icmp_code} must NOT "
                            "set a connection error (hard-as-soft per RFC 5927 §5.2)."
                        ),
                    )

    def test__tcp_session__synchronized_icmp_pmtu_updates_snd_mss(self) -> None:
        """
        Ensure a PMTU event in any synchronized state shrinks
        '_win.snd_mss' to (next_hop_mtu - 40) and writes the
        next-hop MTU into 'stack.pmtu_cache' so future segments and
        the loss-recovery path see the new ceiling.

        Reference: RFC 1191 §6 (PMTUD on the host).
        Reference: RFC 9293 §3.7.5 (MSS option update on path-MTU
        change).
        """

        from pytcp.protocols.tcp.tcp__icmp_metadata import (
            IcmpCategory,
            IcmpMetadata,
        )

        for state in self._SYNCHRONIZED_STATES:
            with self.subTest(state=state):
                session = self._make_session()
                session._state = state
                session._win.snd_mss = 1460

                cache: dict[object, int] = {}
                with patch(
                    "pytcp.protocols.tcp.session.tcp__session.stack.pmtu_cache",
                    cache,
                    create=True,
                ):
                    session.tcp_fsm(
                        icmp=IcmpMetadata(
                            category=IcmpCategory.PMTU,
                            icmp_type=3,
                            icmp_code=4,
                            next_hop_mtu=1280,
                            ip_version=4,
                        ),
                    )

                self.assertEqual(
                    session._win.snd_mss,
                    1280 - 20 - 20,
                    msg=(f"{state} + PMTU=1280 must shrink snd_mss to " "1280 - IP(20) - TCP(20) = 1240."),
                )
                self.assertEqual(
                    cache.get(session._remote_ip_address),
                    1280,
                    msg=f"{state} + PMTU must write 1280 into pmtu_cache.",
                )


class TestTcpSessionTransmitPacket(_TcpSessionFsmFixture):
    """
    The '_transmit_packet' helper tests.
    """

    def test__tcp_session__transmit_packet_routes_through_packet_handler(self) -> None:
        """
        Ensure '_transmit_packet' delegates to the egress interface's
        'send_tcp_packet' (resolved via 'stack.egress_packet_handler()')
        with the expected keyword arguments (local/remote IPs, ports,
        seq, ack, flags).

        Reference: RFC 9293 §3.10.3 (SEND call) — segment construction.
        """

        handler = MagicMock()
        handler.send_tcp_packet = MagicMock()

        with patch(
            "pytcp.protocols.tcp.session.tcp__session.stack.egress_packet_handler",
            return_value=handler,
        ):
            session = self._make_session()
            session._transmit_packet(flag_ack=True, data=b"payload")

        handler.send_tcp_packet.assert_called_once()
        kwargs = handler.send_tcp_packet.call_args.kwargs
        self.assertEqual(
            kwargs["ip__local_address"],
            Ip4Address("10.0.0.1"),
            msg="_transmit_packet must forward the session's local IP.",
        )
        self.assertEqual(
            kwargs["ip__remote_address"],
            Ip4Address("10.0.0.2"),
            msg="_transmit_packet must forward the session's remote IP.",
        )
        self.assertEqual(
            kwargs["tcp__local_port"],
            8080,
            msg="_transmit_packet must forward the session's local port.",
        )
        self.assertEqual(
            kwargs["tcp__remote_port"],
            44444,
            msg="_transmit_packet must forward the session's remote port.",
        )
        self.assertEqual(
            kwargs["tcp__payload"],
            b"payload",
            msg="_transmit_packet must forward the data as the payload.",
        )
        self.assertTrue(
            kwargs["tcp__flag_ack"],
            msg="_transmit_packet must forward flag_ack=True.",
        )

    def test__tcp_session__transmit_packet_advances_snd_nxt(self) -> None:
        """
        Ensure '_transmit_packet' advances '_snd_nxt' by
        'len(data) + flag_syn + flag_fin'. This is the
        invariant the retransmit / ACK logic relies on.

        Reference: RFC 9293 §3.4 (sequence numbers consume one for SYN/FIN).
        """

        handler = MagicMock()
        with patch(
            "pytcp.protocols.tcp.session.tcp__session.stack.egress_packet_handler",
            return_value=handler,
        ):
            session = self._make_session()
            initial_nxt = session._snd_seq.nxt
            session._transmit_packet(flag_syn=True, data=b"abc")

        self.assertEqual(
            session._snd_seq.nxt,
            initial_nxt + len(b"abc") + 1,
            msg="_transmit_packet must advance _snd_nxt by len(data) + flag_syn + flag_fin.",
        )

    def test__tcp_session__transmit_packet_records_fin_seq(self) -> None:
        """
        Ensure '_transmit_packet' with 'flag_fin=True' records
        the next sequence number into '_snd_fin' so the
        session can detect the peer's ACK of our FIN.

        Reference: RFC 9293 §3.4 (FIN consumes one sequence number).
        """

        handler = MagicMock()
        with patch(
            "pytcp.protocols.tcp.session.tcp__session.stack.egress_packet_handler",
            return_value=handler,
        ):
            session = self._make_session()
            session._transmit_packet(flag_fin=True, flag_ack=True)

        self.assertEqual(
            session._snd_seq.fin,
            session._snd_seq.nxt,
            msg="_transmit_packet with flag_fin=True must record _snd_fin = _snd_nxt.",
        )


class TestTcpSessionEnqueueRxBuffer(_TcpSessionFsmFixture):
    """
    The '_enqueue_rx_buffer' helper tests.
    """

    def test__tcp_session__enqueue_extends_rx_buffer(self) -> None:
        """
        Ensure '_enqueue_rx_buffer' extends '_rx_buffer' with the
        supplied memoryview and releases the rx-ready event so
        receive() can wake.
        Reference: RFC 9293 §3.10.5 (RECEIVE call) — buffer delivery.
        """

        session = self._make_session()
        session._enqueue_rx_buffer(memoryview(b"hello"))

        self.assertEqual(
            bytes(session._rx_buffer),
            b"hello",
            msg="_enqueue_rx_buffer must extend _rx_buffer with the data.",
        )

    def test__tcp_session__enqueue_requires_memoryview(self) -> None:
        """
        Ensure the assertion guard rejects non-memoryview input — the
        helper only accepts memoryview to keep the data path zero-copy.
        Reference: RFC 9293 §3.10.5 (RECEIVE call) — implementation guard.
        """

        session = self._make_session()
        with self.assertRaises(AssertionError):
            session._enqueue_rx_buffer(b"raw-bytes")  # type: ignore[arg-type]

    def test__tcp_session__enqueue_signals_readable_on_socket(self) -> None:
        """
        Ensure '_enqueue_rx_buffer' calls '_signal_readable' on the
        owning socket so the selector-readable bit on the socket's
        fileno() flips ready when data lands. Without this hook,
        asyncio / trio loops blocked on the socket's fd would never
        wake on inbound data.

        Reference: RFC 9293 §3.10.5 (RECEIVE call) — buffer delivery.
        """

        session = self._make_session()
        session._enqueue_rx_buffer(memoryview(b"hello"))

        # session._socket is a MagicMock from the fixture; cast lets
        # mypy see the dynamic '.assert_called()' on the auto-spec'd
        # '_signal_readable' attribute without widening the production
        # method's typed signature.
        signal = cast(MagicMock, session._socket._signal_readable)
        signal.assert_called()
