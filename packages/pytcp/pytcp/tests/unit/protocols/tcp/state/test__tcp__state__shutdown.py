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
Unit tests for ShutdownState.

pytcp/tests/unit/protocols/tcp/state/test__tcp__state__shutdown.py

ver 3.0.9
"""

from unittest import TestCase

from pytcp.protocols.tcp.state.tcp__state__shutdown import ShutdownState


class TestShutdownState(TestCase):
    """
    Defaults for 'ShutdownState'.
    """

    def test__shutdown__defaults(self) -> None:
        """
        Ensure rd and wr both default to False — the canonical
        no-shutdown-called state.

        Reference: RFC 9293 §3.10.4 (CLOSE syscall semantics).
        """

        s = ShutdownState()
        self.assertFalse(s.rd, msg="rd must default to False.")
        self.assertFalse(s.wr, msg="wr must default to False.")


class TestShutdownState__Slotted(TestCase):
    """
    The slotted-dataclass invariant for ShutdownState.
    """

    def test__tcp_state__shutdown__is_slotted(self) -> None:
        """
        Ensure ShutdownState is a slotted dataclass so it grows no per-instance
        __dict__ on the TcpSession state object.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            hasattr(ShutdownState(), "__dict__"),
            msg="ShutdownState must be declared with slots=True (no per-instance __dict__).",
        )
