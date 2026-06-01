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
Integration tests for the DAD-failure retry mechanism —
nd_linux_parity §20.3.

RFC 7217 §6 and RFC 8981 §3.3.3 mandate retrying address
derivation on DAD failure. PyTCP exposes the retry count
as 'icmp6.idgen_retries' (default 3, Linux parity); the
'_claim_ip6_address_async' helper now accepts a 'regenerate'
callback that returns a fresh candidate for the same prefix.
On DAD failure the worker calls 'regenerate()' up to
'idgen_retries' times before giving up.

The boot loop wires this for RFC 7217 stable addresses
(re-deriving with an incremented 'dad_counter'); the §18b
temp-address mutator wires it for RFC 8981 (each call
returns a fresh random IID).

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__idgen_retries.py

ver 3.0.8
"""

import threading
from unittest.mock import patch

from net_addr import Ip6Address, Ip6IfAddr
from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.nd_testcase import NdTestCase


class TestIcmp6Nd__IdgenRetries__SysctlRegistration(NdTestCase):
    """
    'icmp6.idgen_retries' is registered with default 3 (RFC
    7217 §6 IDGEN_RETRIES); validator accepts non-negative
    int.
    """

    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__idgen_retries__default_three(self) -> None:
        """
        Ensure 'icmp6.idgen_retries' defaults to 3.

        Reference: RFC 7217 §6 (IDGEN_RETRIES default).
        """

        self.assertEqual(
            sysctl_module.get("icmp6.default.idgen_retries"),
            3,
            msg="Default must be 3 (RFC 7217 IDGEN_RETRIES).",
        )

    def test__icmp6__nd__idgen_retries__validator_accepts_zero(self) -> None:
        """
        Ensure 0 is admitted (no retries — give up on first
        DAD failure).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sysctl_module.set("icmp6.default.idgen_retries", 0)
        self.assertEqual(sysctl_module.get("icmp6.default.idgen_retries"), 0)

    def test__icmp6__nd__idgen_retries__validator_rejects_negative(self) -> None:
        """
        Ensure negative integers are rejected.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl_module.set("icmp6.default.idgen_retries", -1)

    def test__icmp6__nd__idgen_retries__validator_rejects_bool(self) -> None:
        """
        Ensure booleans are rejected.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl_module.set("icmp6.default.idgen_retries", True)


class TestIcmp6Nd__IdgenRetries__WorkerRetryLoop(NdTestCase):
    """
    '_claim_ip6_address_async' with a 'regenerate' callback
    retries on DAD failure up to 'icmp6.idgen_retries' times,
    then gives up.
    """

    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__idgen_retries__retry_until_success(self) -> None:
        """
        Ensure the worker retries on DAD failure and accepts
        a candidate that DAD passes — the third call succeeds
        in this scenario, exhausting two failures.

        Reference: RFC 7217 §6 (retry on DAD failure).
        """

        # Address sequence: original ip6_host fails, regen #1
        # fails, regen #2 succeeds.
        original = Ip6IfAddr("2001:db8:0:1::a/64")
        regen1 = Ip6IfAddr("2001:db8:0:1::b/64")
        regen2 = Ip6IfAddr("2001:db8:0:1::c/64")
        regen_calls: list[Ip6IfAddr] = [regen1, regen2]
        regen_idx = [0]

        def _regenerate() -> Ip6IfAddr:
            host = regen_calls[regen_idx[0]]
            regen_idx[0] += 1
            return host

        # Mock '_perform_ip6_nd_dad' to fail for the first two
        # candidates and pass for the third.
        attempted: list[Ip6Address] = []

        def _mock_dad(*, ip6_unicast_candidate: Ip6Address) -> bool:
            attempted.append(ip6_unicast_candidate)
            return ip6_unicast_candidate == regen2.address

        with sysctl_module.override("icmp6.default.max_rtr_solicitation_delay_ms", 0):
            with patch.object(self._packet_handler, "_perform_ip6_nd_dad", side_effect=_mock_dad):
                thread = self._packet_handler._claim_ip6_address_async(
                    ip6_host=original,
                    regenerate=_regenerate,
                )
                thread.join(timeout=5.0)

        self.assertEqual(
            attempted,
            [original.address, regen1.address, regen2.address],
            msg=f"Expected 3 DAD attempts in order. Got: {attempted!r}",
        )
        self.assertIn(
            regen2.address,
            [host.address for host in self._packet_handler._ip6_ifaddr],
            msg="The successful candidate (regen2) must end up in _ip6_ifaddr.",
        )
        # Nor should the failed candidates.
        self.assertNotIn(
            original.address,
            [host.address for host in self._packet_handler._ip6_ifaddr],
            msg="Failed original candidate must NOT be in _ip6_ifaddr.",
        )

    def test__icmp6__nd__idgen_retries__exhaustion_gives_up(self) -> None:
        """
        Ensure that when DAD fails on every retry, the worker
        gives up after 'idgen_retries' attempts and returns
        without installing any address.

        Reference: RFC 7217 §6 (IDGEN_RETRIES bound).
        """

        original = Ip6IfAddr("2001:db8:0:1::a/64")
        regen_calls = [Ip6IfAddr(f"2001:db8:0:1::{n:x}/64") for n in range(0xB, 0xB + 10)]
        regen_idx = [0]

        def _regenerate() -> Ip6IfAddr:
            host = regen_calls[regen_idx[0]]
            regen_idx[0] += 1
            return host

        attempted: list[Ip6Address] = []

        def _mock_dad(*, ip6_unicast_candidate: Ip6Address) -> bool:
            attempted.append(ip6_unicast_candidate)
            return False  # always fail

        with sysctl_module.override("icmp6.default.idgen_retries", 3):
            with sysctl_module.override("icmp6.default.max_rtr_solicitation_delay_ms", 0):
                with patch.object(self._packet_handler, "_perform_ip6_nd_dad", side_effect=_mock_dad):
                    thread = self._packet_handler._claim_ip6_address_async(
                        ip6_host=original,
                        regenerate=_regenerate,
                    )
                    thread.join(timeout=5.0)

        # Original + 3 retries = 4 attempts total.
        self.assertEqual(
            len(attempted),
            4,
            msg=f"With idgen_retries=3 expected 4 total attempts (original + 3 retries). Got: {attempted!r}",
        )
        # No address installed.
        self.assertNotIn(
            original.address,
            [host.address for host in self._packet_handler._ip6_ifaddr],
            msg="With all attempts failing no address must be installed.",
        )

    def test__icmp6__nd__idgen_retries__no_regenerate_no_retry(self) -> None:
        """
        Ensure '_claim_ip6_address_async' without a
        'regenerate' callback (legacy callers) does NOT retry
        — preserves the prior behaviour exactly.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        original = Ip6IfAddr("2001:db8:0:1::a/64")
        attempted: list[Ip6Address] = []

        def _mock_dad(*, ip6_unicast_candidate: Ip6Address) -> bool:
            attempted.append(ip6_unicast_candidate)
            return False

        with sysctl_module.override("icmp6.default.max_rtr_solicitation_delay_ms", 0):
            with patch.object(self._packet_handler, "_perform_ip6_nd_dad", side_effect=_mock_dad):
                thread = self._packet_handler._claim_ip6_address_async(ip6_host=original)
                thread.join(timeout=5.0)

        self.assertEqual(
            len(attempted),
            1,
            msg=f"Without regenerate callback, no retry. Got attempts: {attempted!r}",
        )

    def test__icmp6__nd__idgen_retries__zero_disables_retry(self) -> None:
        """
        Ensure 'icmp6.idgen_retries=0' suppresses retries even
        when a regenerate callback is supplied.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        original = Ip6IfAddr("2001:db8:0:1::a/64")
        attempted: list[Ip6Address] = []

        def _mock_dad(*, ip6_unicast_candidate: Ip6Address) -> bool:
            attempted.append(ip6_unicast_candidate)
            return False

        regen_calls = [Ip6IfAddr("2001:db8:0:1::b/64")]

        def _regenerate() -> Ip6IfAddr:
            return regen_calls[0]

        with sysctl_module.override("icmp6.default.idgen_retries", 0):
            with sysctl_module.override("icmp6.default.max_rtr_solicitation_delay_ms", 0):
                with patch.object(self._packet_handler, "_perform_ip6_nd_dad", side_effect=_mock_dad):
                    thread = self._packet_handler._claim_ip6_address_async(
                        ip6_host=original,
                        regenerate=_regenerate,
                    )
                    thread.join(timeout=5.0)

        self.assertEqual(
            len(attempted),
            1,
            msg=f"idgen_retries=0 must suppress retries. Got attempts: {attempted!r}",
        )


class TestIcmp6Nd__IdgenRetries__AcceptDadCompose(NdTestCase):
    """
    Combined behaviour: 'accept_dad=2' fail-hard (§20.4) only
    fires AFTER all 'idgen_retries' retries have been
    exhausted. The disable-IPv6 reaction must not happen on
    intermediate failures during the retry loop.
    """

    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__idgen_retries__accept_dad_two_fires_after_exhaustion(self) -> None:
        """
        Ensure '_ip6_support' is flipped only after retries
        are exhausted — intermediate failures during retry
        loop must NOT trigger the kill switch.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        original = Ip6IfAddr("2001:db8:0:1::a/64")
        regen_calls = [Ip6IfAddr(f"2001:db8:0:1::{n:x}/64") for n in range(0xB, 0xB + 10)]
        regen_idx = [0]
        ip6_support_during_retry: list[bool] = []

        def _regenerate() -> Ip6IfAddr:
            ip6_support_during_retry.append(self._packet_handler._ip6_support)
            host = regen_calls[regen_idx[0]]
            regen_idx[0] += 1
            return host

        def _mock_dad(*, ip6_unicast_candidate: Ip6Address) -> bool:
            return False

        with sysctl_module.override("icmp6.default.accept_dad", 2):
            with sysctl_module.override("icmp6.default.idgen_retries", 3):
                with sysctl_module.override("icmp6.default.max_rtr_solicitation_delay_ms", 0):
                    with patch.object(self._packet_handler, "_perform_ip6_nd_dad", side_effect=_mock_dad):
                        thread = self._packet_handler._claim_ip6_address_async(
                            ip6_host=original,
                            regenerate=_regenerate,
                        )
                        thread.join(timeout=5.0)

        # During the 3 retries, _ip6_support stayed True.
        self.assertEqual(
            ip6_support_during_retry,
            [True, True, True],
            msg=(
                "_ip6_support must remain True during retries; flipped only after exhaustion. "
                f"Got: {ip6_support_during_retry!r}"
            ),
        )
        # After exhaustion, kill switch fired.
        self.assertFalse(
            self._packet_handler._ip6_support,
            msg="accept_dad=2 + retry exhaustion must flip _ip6_support to False.",
        )


# Suppress unused-import warning — 'threading' is used by the
# §18b/§18c follow-on tests; this file keeps the import for
# parity with the other DAD-test files in this directory.
_ = threading
