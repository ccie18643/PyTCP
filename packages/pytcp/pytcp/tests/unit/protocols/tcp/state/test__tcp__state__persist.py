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
Unit tests for PersistState.

pytcp/tests/unit/protocols/tcp/state/test__tcp__state__persist.py

ver 3.0.8
"""

from unittest import TestCase

from pytcp.protocols.tcp.state.tcp__state__persist import PersistState


class TestPersistState(TestCase):
    """
    Defaults + deactivate() behaviour.
    """

    def test__persist__defaults(self) -> None:
        """
        Ensure active defaults False and timeout defaults to 0
        — the canonical no-persist-timer-armed state.

        Reference: RFC 9293 §3.8.6.1 (persist timer state).
        """

        s = PersistState()
        self.assertFalse(s.active, msg="active must default to False.")
        self.assertEqual(s.timeout, 0, msg="timeout must default to 0.")

    def test__persist__deactivate_clears_and_resets(self) -> None:
        """
        Ensure 'deactivate' clears the active gate and resets
        the back-off interval to the supplied initial timeout
        so a future zero-window event arms a fresh probe at
        the canonical baseline.

        Reference: RFC 9293 §3.8.6.1 (deactivation on window reopen).
        """

        s = PersistState()
        s.active = True
        s.timeout = 30000  # exponential-backed-off value
        s.deactivate(initial_timeout=1000)
        self.assertFalse(s.active, msg="deactivate must clear active.")
        self.assertEqual(
            s.timeout,
            1000,
            msg="deactivate must reset timeout to the initial value.",
        )
