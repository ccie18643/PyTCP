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
Unit tests for the TCP buffer auto-tuning sysctl knobs — the Tier-3
'tcp.moderate_rcvbuf' enable flag and the 'tcp.rmem' / 'tcp.wmem'
(min / default / max) bound triples registered as the clamp + default
source for receive-buffer DRS and send-buffer auto-tuning
(docs/refactor/tcp_buffer_autotuning.md §6). No runtime consumer yet;
these tests pin the registration, defaults, and cross-field validators.

pytcp/tests/unit/protocols/tcp/test__tcp__constants.py

ver 3.0.8
"""

from typing import override
from unittest import TestCase

from pytcp.protocols.tcp.tcp__constants import (
    TCP__MODERATE_RCVBUF,
    TCP__RMEM__DEFAULT,
    TCP__RMEM__MAX,
    TCP__RMEM__MIN,
    TCP__WMEM__DEFAULT,
    TCP__WMEM__MAX,
    TCP__WMEM__MIN,
)
from pytcp.stack import sysctl as sysctl_module


class TestTcpBufferTuningConstants(TestCase):
    """
    The TCP buffer auto-tuning sysctl-knob registration tests.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore every sysctl to its registered default so a mutated
        triple cannot leak into a sibling test.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__tcp__moderate_rcvbuf__default_on(self) -> None:
        """
        Ensure 'tcp.moderate_rcvbuf' registers with the default-on
        value so receive-buffer DRS is enabled by default, matching
        Linux.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            sysctl_module.get("tcp.moderate_rcvbuf"),
            TCP__MODERATE_RCVBUF,
            msg="'tcp.moderate_rcvbuf' must register with its module default.",
        )
        self.assertEqual(
            TCP__MODERATE_RCVBUF,
            1,
            msg="DRS must default on (1), matching Linux net.ipv4.tcp_moderate_rcvbuf.",
        )

    def test__tcp__moderate_rcvbuf__accepts_zero_and_one(self) -> None:
        """
        Ensure 'tcp.moderate_rcvbuf' accepts the two valid boolean
        modes 0 (off) and 1 (on).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for mode in (0, 1):
            sysctl_module.set("tcp.moderate_rcvbuf", mode)
            self.assertEqual(
                sysctl_module.get("tcp.moderate_rcvbuf"),
                mode,
                msg=f"'tcp.moderate_rcvbuf' must accept the boolean mode {mode}.",
            )

    def test__tcp__moderate_rcvbuf__rejects_out_of_range(self) -> None:
        """
        Ensure 'tcp.moderate_rcvbuf' rejects a value outside {0, 1}.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl_module.set("tcp.moderate_rcvbuf", 2)

    def test__tcp__rmem__triple_defaults(self) -> None:
        """
        Ensure the 'tcp.rmem' min / default / max triple registers
        with its module defaults so the DRS clamp source is present.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            (
                sysctl_module.get("tcp.rmem.min"),
                sysctl_module.get("tcp.rmem.default"),
                sysctl_module.get("tcp.rmem.max"),
            ),
            (TCP__RMEM__MIN, TCP__RMEM__DEFAULT, TCP__RMEM__MAX),
            msg="'tcp.rmem' triple must register with its module defaults.",
        )

    def test__tcp__wmem__triple_defaults(self) -> None:
        """
        Ensure the 'tcp.wmem' min / default / max triple registers
        with its module defaults so the send-autotune clamp source is
        present.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            (
                sysctl_module.get("tcp.wmem.min"),
                sysctl_module.get("tcp.wmem.default"),
                sysctl_module.get("tcp.wmem.max"),
            ),
            (TCP__WMEM__MIN, TCP__WMEM__DEFAULT, TCP__WMEM__MAX),
            msg="'tcp.wmem' triple must register with its module defaults.",
        )

    def test__tcp__rmem__triple_defaults_are_ordered(self) -> None:
        """
        Ensure the registered 'tcp.rmem' defaults satisfy
        min <= default <= max so the shipped configuration passes its
        own cross-field validator.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertLessEqual(
            TCP__RMEM__MIN,
            TCP__RMEM__DEFAULT,
            msg="'tcp.rmem' default must be >= min.",
        )
        self.assertLessEqual(
            TCP__RMEM__DEFAULT,
            TCP__RMEM__MAX,
            msg="'tcp.rmem' default must be <= max.",
        )

    def test__tcp__wmem__triple_defaults_are_ordered(self) -> None:
        """
        Ensure the registered 'tcp.wmem' defaults satisfy
        min <= default <= max so the shipped configuration passes its
        own cross-field validator.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertLessEqual(
            TCP__WMEM__MIN,
            TCP__WMEM__DEFAULT,
            msg="'tcp.wmem' default must be >= min.",
        )
        self.assertLessEqual(
            TCP__WMEM__DEFAULT,
            TCP__WMEM__MAX,
            msg="'tcp.wmem' default must be <= max.",
        )

    def test__tcp__rmem__finalize_rejects_default_over_max(self) -> None:
        """
        Ensure the 'tcp.rmem' cross-field finalize validator rejects a
        configuration whose default exceeds max — an inverted triple
        would let DRS clamp below its own seed.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sysctl_module.set("tcp.rmem.default", TCP__RMEM__MAX + 1)
        with self.assertRaises(ValueError):
            sysctl_module.finalize_validators()

    def test__tcp__rmem__finalize_rejects_min_over_default(self) -> None:
        """
        Ensure the 'tcp.rmem' cross-field finalize validator rejects a
        configuration whose min exceeds default.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sysctl_module.set("tcp.rmem.min", TCP__RMEM__DEFAULT + 1)
        with self.assertRaises(ValueError):
            sysctl_module.finalize_validators()

    def test__tcp__wmem__finalize_rejects_default_over_max(self) -> None:
        """
        Ensure the 'tcp.wmem' cross-field finalize validator rejects a
        configuration whose default exceeds max.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sysctl_module.set("tcp.wmem.default", TCP__WMEM__MAX + 1)
        with self.assertRaises(ValueError):
            sysctl_module.finalize_validators()

    def test__tcp__wmem__finalize_rejects_min_over_default(self) -> None:
        """
        Ensure the 'tcp.wmem' cross-field finalize validator rejects a
        configuration whose min exceeds default.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sysctl_module.set("tcp.wmem.min", TCP__WMEM__DEFAULT + 1)
        with self.assertRaises(ValueError):
            sysctl_module.finalize_validators()
