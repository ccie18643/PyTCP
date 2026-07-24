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
Unit tests for AdvertiseState.

pytcp/tests/unit/protocols/tcp/state/test__tcp__state__advertise.py

ver 3.0.9
"""

from unittest import TestCase

from pytcp.protocols.tcp.state.tcp__state__advertise import AdvertiseState


class TestAdvertiseState(TestCase):
    """
    Defaults for 'AdvertiseState'.
    """

    def test__advertise__defaults(self) -> None:
        """
        Ensure all six advertise flags default to True (modern
        throughput-friendly defaults) and 'send_sack' defaults
        to False (set by handshake on bilateral success).

        Reference: RFC 7323 §2.2 (TSopt + WSCALE advertisement).
        Reference: RFC 2018 §2 (SACK-Permitted advertisement).
        Reference: RFC 3168 §6.1.1 (ECN advertisement).
        Reference: RFC 9768 §3.1.1 (AccECN advertisement).
        Reference: RFC 7413 §3.1 (TFO advertisement).
        """

        s = AdvertiseState()
        self.assertTrue(s.ts, msg="ts must default to True.")
        self.assertTrue(s.wscale, msg="wscale must default to True.")
        self.assertTrue(s.sack, msg="sack must default to True.")
        self.assertTrue(s.ecn, msg="ecn must default to True.")
        self.assertTrue(s.accecn, msg="accecn must default to True.")
        self.assertTrue(s.fastopen, msg="fastopen must default to True.")
        self.assertFalse(s.send_sack, msg="send_sack must default to False.")


class TestAdvertiseState__Slotted(TestCase):
    """
    The slotted-dataclass invariant for AdvertiseState.
    """

    def test__tcp_state__advertise__is_slotted(self) -> None:
        """
        Ensure AdvertiseState is a slotted dataclass so it grows no per-instance
        __dict__ on the TcpSession state object.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            hasattr(AdvertiseState(), "__dict__"),
            msg="AdvertiseState must be declared with slots=True (no per-instance __dict__).",
        )
