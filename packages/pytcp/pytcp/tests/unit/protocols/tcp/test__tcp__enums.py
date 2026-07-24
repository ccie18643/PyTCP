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
This module contains tests for the 'FsmState', 'SysCall', and
'ConnError' enums in 'pytcp/protocols/tcp/tcp__enums.py', the
'TcpSessionError' exception class in
'pytcp/protocols/tcp/tcp__errors.py', and the module-level
constants in 'pytcp/protocols/tcp/tcp__constants.py'.

pytcp/tests/unit/protocols/tcp/test__tcp__enums.py

ver 3.0.9
"""

from unittest import TestCase

from pytcp.protocols.tcp.tcp__constants import (
    TCP__DELAYED_ACK__DELAY_MS,
    TCP__RETRANSMIT__MAX_COUNT,
    TCP__RTO__INITIAL_MS,
    TCP__TIME_WAIT__DELAY_MS,
)
from pytcp.protocols.tcp.tcp__enums import (
    ConnError,
    FsmState,
    SysCall,
)
from pytcp.protocols.tcp.tcp__errors import TcpSessionError


class TestTcpSessionModuleConstants(TestCase):
    """
    The 'tcp__session' module-level constant tests.
    """

    def test__tcp_session__retransmit_timeout_is_1000(self) -> None:
        """
        Ensure 'TCP__RTO__INITIAL_MS' stays at the canonical 1000
        ms base delay. Changing it shifts every retransmit cadence, so
        any drift must be an intentional, reviewed change.

        Reference: RFC 6298 §2.1 (initial RTO = 1 second).
        Reference: RFC 8961 §2 (initial RTO best practices).
        """

        self.assertEqual(
            TCP__RTO__INITIAL_MS,
            1000,
            msg="TCP__RTO__INITIAL_MS must remain 1000 ms.",
        )

    def test__tcp_session__retransmit_max_count(self) -> None:
        """
        Ensure 'TCP__RETRANSMIT__MAX_COUNT' stays at 6 retries so the
        connection-abort timeout reaches 2**7 - 1 = 127 s under the
        binary-doubling cadence, satisfying the R2 floor of >= 100 s.

        Reference: RFC 1122 §4.2.3.5 (R2 >= 100 s before connection abort).
        Reference: RFC 6298 §5.5 (binary backoff).
        """

        self.assertEqual(
            TCP__RETRANSMIT__MAX_COUNT,
            6,
            msg=(
                "TCP__RETRANSMIT__MAX_COUNT must remain 6 - lower "
                "values violate the RFC 1122 §4.2.3.5 R2 floor "
                "(>= 100 s before connection abort)."
            ),
        )

    def test__tcp_session__time_wait_delay(self) -> None:
        """
        Ensure 'TCP__TIME_WAIT__DELAY_MS' stays at the canonical 30-second
        value used for the TCP TIME_WAIT state. PyTCP uses 30 s
        rather than the spec's 240 s default — a documented deviation.

        Reference: RFC 9293 §3.4.2 (TIME-WAIT 2*MSL).
        """

        self.assertEqual(
            TCP__TIME_WAIT__DELAY_MS,
            30000,
            msg="TCP__TIME_WAIT__DELAY_MS must remain 30000 ms (30 seconds).",
        )

    def test__tcp_session__delayed_ack_delay(self) -> None:
        """
        Ensure 'TCP__DELAYED_ACK__DELAY_MS' stays at the canonical 100 ms delay
        for consecutive delayed ACKs.

        Reference: RFC 1122 §4.2.3.2 (delayed ACK timer must be < 500 ms).
        """

        self.assertEqual(
            TCP__DELAYED_ACK__DELAY_MS,
            100,
            msg="TCP__DELAYED_ACK__DELAY_MS must remain 100 ms.",
        )


class TestFsmState(TestCase):
    """
    The 'FsmState' enum tests.
    """

    def test__tcp_session__fsm_state_has_every_tcp_state(self) -> None:
        """
        Ensure 'FsmState' exposes every standard TCP state name.
        Missing or renamed members would silently break the
        state-transition machinery.

        Reference: RFC 9293 §3.3.2 (eleven TCP states).
        """

        expected = {
            "CLOSED",
            "LISTEN",
            "SYN_SENT",
            "SYN_RCVD",
            "ESTABLISHED",
            "FIN_WAIT_1",
            "FIN_WAIT_2",
            "CLOSING",
            "CLOSE_WAIT",
            "LAST_ACK",
            "TIME_WAIT",
        }
        self.assertEqual(
            {member.name for member in FsmState},
            expected,
            msg="FsmState must expose the canonical eleven RFC 793 TCP state names.",
        )

    def test__tcp_session__fsm_state_str_is_name(self) -> None:
        """
        Ensure FsmState members stringify as their member name (the
        'NameEnum' base overrides '__str__') so log lines are readable.

        Reference: RFC 9293 §3.3.2 (state names).
        """

        self.assertEqual(
            str(FsmState.ESTABLISHED),
            "ESTABLISHED",
            msg="FsmState members must stringify as their name.",
        )


class TestSysCall(TestCase):
    """
    The 'SysCall' enum tests.
    """

    def test__tcp_session__syscall_members(self) -> None:
        """
        Ensure 'SysCall' exposes the four syscalls the session
        recognizes: LISTEN, CONNECT, CLOSE, ABORT.

        Reference: RFC 9293 §3.9.1 (User/TCP interface calls).
        """

        self.assertEqual(
            {member.name for member in SysCall},
            {"LISTEN", "CONNECT", "CLOSE", "ABORT"},
            msg="SysCall must expose exactly LISTEN, CONNECT, CLOSE, ABORT.",
        )

    def test__tcp_session__syscall_str_is_name(self) -> None:
        """
        Ensure SysCall members stringify as their name (NameEnum
        override).

        Reference: RFC 9293 §3.9.1 (User/TCP interface call names).
        """

        self.assertEqual(str(SysCall.CONNECT), "CONNECT", msg="SysCall.CONNECT must stringify as 'CONNECT'.")


class TestConnError(TestCase):
    """
    The 'ConnError' enum tests.
    """

    def test__tcp_session__conn_error_members(self) -> None:
        """
        Ensure 'ConnError' exposes the four connection-failure codes
        used by the session: NONE, REFUSED, TIMEOUT, CANCELED.
        'CANCELED' supports 'close()' issued mid-handshake from a
        different thread than the one blocked on 'connect()'; signals
        the canceled-error so the blocked caller raises
        'TcpSessionError("Connection canceled")' on unblock.

        Reference: RFC 9293 §3.10.1 (OPEN error signalling).
        Reference: RFC 9293 §3.10.7.3 (RST in SYN-SENT triggers connection refused).
        """

        self.assertEqual(
            {member.name for member in ConnError},
            {"NONE", "REFUSED", "TIMEOUT", "CANCELED", "HOST_UNREACHABLE", "NET_UNREACHABLE"},
            msg=(
                "ConnError must expose the six canonical connection-fail reasons "
                "(NONE, REFUSED, TIMEOUT, CANCELED, HOST_UNREACHABLE, NET_UNREACHABLE)."
            ),
        )


class TestTcpSessionError(TestCase):
    """
    The 'TcpSessionError' exception tests.
    """

    def test__tcp_session__error_is_exception_subclass(self) -> None:
        """
        Ensure 'TcpSessionError' inherits from 'Exception' so callers
        using a broad except clause catch it.

        Reference: RFC 9293 §3.10.1 (OPEN error signalling).
        """

        self.assertTrue(
            issubclass(TcpSessionError, Exception),
            msg="TcpSessionError must inherit from Exception.",
        )

    def test__tcp_session__error_preserves_message(self) -> None:
        """
        Ensure the exception's 'str()' returns the constructor
        message verbatim — test fixtures match on exact text.

        Reference: RFC 9293 §3.10.1 (error signalling to user).
        """

        try:
            raise TcpSessionError("Connection refused")
        except TcpSessionError as exc:
            self.assertEqual(
                str(exc),
                "Connection refused",
                msg="TcpSessionError must preserve its constructor message in str().",
            )
