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
Unit tests for the 'stack.pmtu_state' module-level registry and
the 'stack.current_pmtu' read-only accessor introduced by Phase
2 of the PLPMTUD unified-engine plan. Exercises:

  * Registry shape: dict keyed by Ip4Address | Ip6Address,
    valued by PmtuSearch instances.
  * Lazy-allocation invariant: 'current_pmtu' returns None for
    unknown destinations.
  * Read precedence: 'current_pmtu' prefers 'pmtu_state' when
    present and falls back to the legacy 'pmtu_cache' scalar.
  * Per-destination isolation: distinct PmtuSearch instances
    per remote address.

pytcp/tests/unit/lib/test__lib__pmtu_state.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Ip4Address, Ip6Address
from pytcp import stack
from pytcp.lib.plpmtud import PmtuSearch

_IP4_A = Ip4Address("10.0.1.91")
_IP4_B = Ip4Address("10.0.1.92")
_IP6_A = Ip6Address("2001:db8::91")


class TestPmtuStateRegistry(TestCase):
    """
    The 'stack.pmtu_state' registry shape and basic
    behaviour.
    """

    _pmtu_state_prior: dict[Any, Any]
    _pmtu_cache_prior: dict[Any, Any]

    @override
    def setUp(self) -> None:
        self._pmtu_state_prior = dict(stack.pmtu_state)
        stack.pmtu_state.clear()
        self._pmtu_cache_prior = dict(stack.pmtu_cache)
        stack.pmtu_cache.clear()

    @override
    def tearDown(self) -> None:
        stack.pmtu_state.clear()
        stack.pmtu_state.update(self._pmtu_state_prior)
        stack.pmtu_cache.clear()
        stack.pmtu_cache.update(self._pmtu_cache_prior)

    def test__pmtu_state__attribute_exists(self) -> None:
        """
        Ensure 'stack.pmtu_state' is defined at module scope so
        per-transport adapters can register PmtuSearch instances
        keyed by destination address.

        Reference: RFC 8899 §3 #9 (shared PLPMTU state per destination).
        """

        self.assertTrue(
            hasattr(stack, "pmtu_state"),
            msg="stack.pmtu_state must be defined at module scope.",
        )
        self.assertIsInstance(
            stack.pmtu_state,
            dict,
            msg="stack.pmtu_state must be a dict keyed by remote address.",
        )

    def test__pmtu_state__current_pmtu_returns_none_for_unknown(self) -> None:
        """
        Ensure 'current_pmtu' returns None for a destination that
        has no entry in either 'pmtu_state' or 'pmtu_cache'.
        Callers fall back to 'stack.egress_interface_mtu(dst)' when
        None is returned (matching Linux IP_MTU semantics).

        Reference: RFC 8899 §3 #5 (PMTU parameter / fallback to link MTU).
        """

        self.assertIsNone(
            stack.current_pmtu(_IP4_A),
            msg="current_pmtu(unknown_dst) must return None.",
        )

    def test__pmtu_state__current_pmtu_returns_scalar_from_legacy_cache(self) -> None:
        """
        Ensure 'current_pmtu' falls back to the legacy
        'stack.pmtu_cache' scalar when no PmtuSearch entry exists
        — the backward-compat path keeps existing
        classical-PMTUD callers working before the per-transport
        adapters are wired.

        Reference: RFC 8201 §5.2 (cached PMTU per destination).
        """

        stack.pmtu_cache[_IP4_A] = 1400

        self.assertEqual(
            stack.current_pmtu(_IP4_A),
            1400,
            msg="current_pmtu must return pmtu_cache scalar when no pmtu_state entry exists.",
        )

    def test__pmtu_state__current_pmtu_prefers_engine_over_cache(self) -> None:
        """
        Ensure 'current_pmtu' returns the PmtuSearch engine's
        current_mtu when both 'pmtu_state' and 'pmtu_cache' have
        entries for the destination — the active engine is the
        canonical source of truth, the cache is the legacy view.

        Reference: RFC 4821 §5.2 (active PLPMTUD overrides cached PMTU).
        """

        stack.pmtu_cache[_IP4_A] = 1400  # legacy scalar
        engine: PmtuSearch[Ip4Address] = PmtuSearch(address=_IP4_A, interface_mtu=1500)
        stack.pmtu_state[_IP4_A] = engine

        self.assertEqual(
            stack.current_pmtu(_IP4_A),
            engine.current_mtu,
            msg="current_pmtu must prefer pmtu_state engine value over pmtu_cache scalar.",
        )

    def test__pmtu_state__per_destination_isolation(self) -> None:
        """
        Ensure two PmtuSearch instances for different
        destinations live as distinct entries in the registry —
        a state mutation on one MUST NOT affect the other.

        Reference: RFC 8899 §3 #9 (per-destination state isolation).
        """

        engine_a: PmtuSearch[Ip4Address] = PmtuSearch(address=_IP4_A, interface_mtu=1500)
        engine_b: PmtuSearch[Ip4Address] = PmtuSearch(address=_IP4_B, interface_mtu=1500)
        stack.pmtu_state[_IP4_A] = engine_a
        stack.pmtu_state[_IP4_B] = engine_b

        # Mutate engine_a; engine_b must not move.
        engine_a.on_classical_pmtu(1300, now=0.0)

        self.assertEqual(
            stack.current_pmtu(_IP4_A),
            engine_a.current_mtu,
            msg="current_pmtu(_IP4_A) must reflect engine_a's state.",
        )
        self.assertEqual(
            stack.current_pmtu(_IP4_B),
            engine_b.current_mtu,
            msg="current_pmtu(_IP4_B) must reflect engine_b's state (unaffected by engine_a).",
        )
        self.assertIsNot(
            stack.pmtu_state[_IP4_A],
            stack.pmtu_state[_IP4_B],
            msg="Per-destination PmtuSearch instances must be distinct objects.",
        )

    def test__pmtu_state__ip6_destination_keying(self) -> None:
        """
        Ensure an Ip6Address-keyed PmtuSearch instance can be
        stored and read back via 'current_pmtu' — the registry
        is heterogeneous across the IPv4 / IPv6 address families.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        engine: PmtuSearch[Ip6Address] = PmtuSearch(address=_IP6_A, interface_mtu=1500)
        stack.pmtu_state[_IP6_A] = engine

        self.assertEqual(
            stack.current_pmtu(_IP6_A),
            engine.current_mtu,
            msg="current_pmtu(IPv6 dst) must return the registry entry's current_mtu.",
        )
