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
Unit tests for the per-session TFO state container.

pytcp/tests/unit/protocols/tcp/state/test__tcp__state__fastopen.py

ver 3.0.8
"""

from unittest import TestCase

from pytcp.protocols.tcp.state.tcp__state__fastopen import FastOpenState


class TestFastOpenState__Defaults(TestCase):
    """
    Defaults for 'FastOpenState'.
    """

    def test__fastopen__defaults(self) -> None:
        """
        Ensure cookie_to_emit defaults to None, pending_counted
        and syn_retransmitted default to False — the canonical
        no-TFO-activity state on a fresh session.

        Reference: RFC 7413 §3.1 (listener cookie stash).
        Reference: RFC 7413 §4.2 (PendingFastOpenRequests counter).
        Reference: RFC 7413 §4.4 (SYN-retransmit bypass).
        """

        s = FastOpenState()
        self.assertIsNone(s.cookie_to_emit, msg="cookie_to_emit must default to None.")
        self.assertFalse(s.pending_counted, msg="pending_counted must default to False.")
        self.assertFalse(s.syn_retransmitted, msg="syn_retransmitted must default to False.")


class TestFastOpenState__Slotted(TestCase):
    """
    The slotted-dataclass invariant for FastOpenState.
    """

    def test__tcp_state__fastopen__is_slotted(self) -> None:
        """
        Ensure FastOpenState is a slotted dataclass so it grows no per-instance
        __dict__ on the TcpSession state object.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            hasattr(FastOpenState(), "__dict__"),
            msg="FastOpenState must be declared with slots=True (no per-instance __dict__).",
        )
