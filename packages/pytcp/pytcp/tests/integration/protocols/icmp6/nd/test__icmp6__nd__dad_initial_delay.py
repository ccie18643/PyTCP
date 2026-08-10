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
Integration tests for the random initial DAD probe delay —
nd_linux_parity §20.2.

RFC 4862 §5.4.2 SHOULD a host delay sending the first DAD
probe by a uniform random amount in
[0, MAX_RTR_SOLICITATION_DELAY) seconds. This alleviates
fleet-wide synchronisation when many hosts boot at the same
instant (e.g. after a power outage). RFC 4861 §10 fixes
MAX_RTR_SOLICITATION_DELAY at 1 second; PyTCP exposes the
ceiling as the 'icmp6.max_rtr_solicitation_delay_ms' sysctl,
default 1000. Setting the sysctl to 0 disables the delay
entirely (kill switch — useful for low-latency boot
environments).

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__dad_initial_delay.py

ver 3.0.9
"""

from typing import Any, override
from unittest.mock import patch

from net_addr import Ip6Address
from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.nd_testcase import NdTestCase

_CANDIDATE = Ip6Address("2001:db8:0:1::5")


class TestIcmp6Nd__DadInitialDelay__SysctlRegistration(NdTestCase):
    """
    The 'icmp6.max_rtr_solicitation_delay_ms' sysctl is
    registered with default 1000 (RFC 4861 §10
    MAX_RTR_SOLICITATION_DELAY = 1 second). Validator
    accepts non-negative int; 0 disables.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__dad_initial_delay__default_one_second(self) -> None:
        """
        Ensure 'icmp6.max_rtr_solicitation_delay_ms' is
        registered with default 1000.

        Reference: RFC 4861 §10 (MAX_RTR_SOLICITATION_DELAY = 1 second).
        """

        self.assertEqual(
            sysctl_module.get("icmp6.default.max_rtr_solicitation_delay_ms"),
            1000,
            msg="Default must be 1000ms (RFC 4861 §10).",
        )

    def test__icmp6__nd__dad_initial_delay__validator_accepts_zero(self) -> None:
        """
        Ensure 0 is accepted (kill switch disables the delay).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sysctl_module.set("icmp6.default.max_rtr_solicitation_delay_ms", 0)
        self.assertEqual(
            sysctl_module.get("icmp6.default.max_rtr_solicitation_delay_ms"),
            0,
            msg="Validator must accept 0 (disable).",
        )

    def test__icmp6__nd__dad_initial_delay__validator_rejects_negative(self) -> None:
        """
        Ensure negative integers are rejected.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl_module.set("icmp6.default.max_rtr_solicitation_delay_ms", -1)

    def test__icmp6__nd__dad_initial_delay__validator_rejects_bool(self) -> None:
        """
        Ensure boolean values are rejected even though Python
        admits 'isinstance(True, int)'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl_module.set("icmp6.default.max_rtr_solicitation_delay_ms", True)


class TestIcmp6Nd__DadInitialDelay__BeforeFirstProbe(NdTestCase):
    """
    '_perform_ip6_nd_dad' calls 'time.sleep' once before
    starting the probe loop, with a duration in
    [0, max_rtr_solicitation_delay_ms / 1000.0). Setting the
    sysctl to 0 suppresses the call entirely.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__dad_initial_delay__sleeps_before_probe(self) -> None:
        """
        Ensure the DAD function sleeps for a random duration in
        [0, max_rtr_solicitation_delay_ms / 1000.0) before the
        first probe.

        Reference: RFC 4862 §5.4.2 (random delay before first NS).
        """

        sleeps: list[float] = []

        def _no_op_sleep(duration: float) -> None:
            sleeps.append(duration)

        with patch("pytcp.runtime.packet_handler.time.sleep", side_effect=_no_op_sleep):
            with sysctl_module.override("icmp6.default.max_rtr_solicitation_delay_ms", 1000):
                with sysctl_module.override("icmp6.default.dad_transmits", 0):
                    self._packet_handler._perform_ip6_nd_dad(ip6_unicast_candidate=_CANDIDATE)

        # 'dad_transmits=0' skips the probe loop, so the only
        # 'time.sleep' call must be the initial RFC 4862 §5.4.2
        # delay.
        self.assertEqual(
            len(sleeps),
            1,
            msg=f"Expected exactly one 'time.sleep' call (initial delay). Got: {sleeps!r}",
        )
        self.assertGreaterEqual(
            sleeps[0],
            0.0,
            msg=f"Initial delay must be non-negative. Got: {sleeps[0]!r}",
        )
        self.assertLess(
            sleeps[0],
            1.0,
            msg=f"Initial delay must be < MAX_RTR_SOLICITATION_DELAY (1s). Got: {sleeps[0]!r}",
        )

    def test__icmp6__nd__dad_initial_delay__sysctl_zero_disables(self) -> None:
        """
        Ensure setting 'icmp6.max_rtr_solicitation_delay_ms=0'
        suppresses the 'time.sleep' call entirely.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sleeps: list[float] = []

        def _no_op_sleep(duration: float) -> None:
            sleeps.append(duration)

        with patch("pytcp.runtime.packet_handler.time.sleep", side_effect=_no_op_sleep):
            with sysctl_module.override("icmp6.default.max_rtr_solicitation_delay_ms", 0):
                with sysctl_module.override("icmp6.default.dad_transmits", 0):
                    self._packet_handler._perform_ip6_nd_dad(ip6_unicast_candidate=_CANDIDATE)

        self.assertEqual(
            sleeps,
            [],
            msg=f"sysctl=0 must suppress the initial delay. Got sleeps: {sleeps!r}",
        )

    def test__icmp6__nd__dad_initial_delay__custom_ceiling(self) -> None:
        """
        Ensure the random delay's upper bound matches the
        sysctl-configured value. Set the ceiling to 200 ms;
        observed delay must be < 0.2 s.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sleeps: list[float] = []

        def _no_op_sleep(duration: float) -> None:
            sleeps.append(duration)

        with patch("pytcp.runtime.packet_handler.time.sleep", side_effect=_no_op_sleep):
            with sysctl_module.override("icmp6.default.max_rtr_solicitation_delay_ms", 200):
                with sysctl_module.override("icmp6.default.dad_transmits", 0):
                    self._packet_handler._perform_ip6_nd_dad(ip6_unicast_candidate=_CANDIDATE)

        self.assertEqual(len(sleeps), 1)
        self.assertGreaterEqual(sleeps[0], 0.0)
        self.assertLess(
            sleeps[0],
            0.2,
            msg=f"Custom ceiling 200ms must cap the delay at 0.2s. Got: {sleeps[0]!r}",
        )


# Suppress unused-import warning for 'Any' — it's reserved for
# future test variants that need broader type annotations on
# parametric helpers.
_ = Any
