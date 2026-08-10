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
Unit tests for the 'Ip4LinkLocal' CLAIMING-state behaviour —
RFC 3927 §2.2 ARP Probe + §2.4 ARP Announce delegation via
the sanctioned 'AddressApi.claim_with_acd' surface, plus
the retry / rate-limit loop pinned by §9 MAX_CONFLICTS /
RATE_LIMIT_INTERVAL.

pytcp/tests/unit/protocols/ip4/link_local/test__link_local__client__claiming.py

ver 3.0.9
"""

from typing import cast, override
from unittest import TestCase
from unittest.mock import MagicMock, create_autospec, patch

from net_addr import MacAddress
from pytcp.protocols.ip4.acd.ip4_acd import AcdResult, Ip4Acd
from pytcp.protocols.ip4.link_local import link_local__constants as ip4ll_const
from pytcp.protocols.ip4.link_local.link_local__client import (
    Ip4LinkLocal,
    Ip4LinkLocalState,
)
from pytcp.stack import sysctl as sysctl_module
from pytcp.stack.address import AddressApi


class TestIp4LinkLocalClaiming(TestCase):
    """
    The 'Ip4LinkLocal' CLAIMING-state tests.
    """

    @override
    def setUp(self) -> None:
        """
        Stand up a fresh client with a mocked address API; the
        ACD API stays under the harness' direct control so each
        test can drive success / conflict outcomes synchronously.
        Silence the subsystem's '<stack>' log.
        """

        self.enterContext(patch("pytcp.protocols.ip4.link_local.link_local__client.log"))
        self.enterContext(patch("pytcp.runtime.subsystem.log"))
        # 'time.sleep' is patched globally for the test class so
        # the rate-limit cool-down does not actually block.
        self._mock_sleep = self.enterContext(
            patch("pytcp.protocols.ip4.link_local.link_local__client.time.sleep"),
        )

        self._mac = MacAddress("02:00:00:00:00:07")
        self._address_api: AddressApi = create_autospec(AddressApi, spec_set=True)
        self._acd: Ip4Acd = create_autospec(Ip4Acd, spec_set=True)
        self._client = Ip4LinkLocal(
            mac_address=self._mac,
            address_api=self._address_api,
            acd=self._acd,
        )
        # Hop past the INIT tick so the harness can drive
        # CLAIMING directly.
        self._client._do_init()

    @override
    def tearDown(self) -> None:
        """
        Restore the sysctl defaults so a per-test override does
        not leak into a subsequent test's baseline.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def _set_claim_outcome(self, *, success: bool, peer_mac: MacAddress | None = None) -> None:
        """
        Configure the mocked ACD engine to return the named outcome
        for the next 'claim' call.
        """

        candidate = self._client._candidate
        assert candidate is not None
        cast(MagicMock, self._acd).claim.return_value = AcdResult(
            success=success,
            address=candidate.address,
            conflict_mac=peer_mac,
        )

    def test__ip4_link_local__claiming_clean_transitions_to_bound(self) -> None:
        """
        Ensure a successful 'claim_with_acd' returns the FSM to
        BOUND and the candidate stays installed.

        Reference: RFC 3927 §2.2 + §2.4 (probe-then-announce on clean probe).
        """

        self._set_claim_outcome(success=True)

        self._client._do_claiming()

        self.assertEqual(
            self._client._state,
            Ip4LinkLocalState.BOUND,
            msg="Clean claim must transition CLAIMING -> BOUND.",
        )
        candidate = self._client._candidate
        self.assertIsNotNone(
            candidate,
            msg="Clean claim must leave the candidate installed on the client.",
        )
        cast(MagicMock, self._acd).claim.assert_called_once()
        cast(MagicMock, self._address_api).add.assert_called_once()

    def test__ip4_link_local__claiming_conflict_returns_to_init_and_bumps_counter(self) -> None:
        """
        Ensure a conflicting 'claim_with_acd' returns the FSM
        to INIT, bumps the conflict counter, and clears the
        candidate so the next INIT tick picks a fresh address
        from the RNG.

        Reference: RFC 3927 §2.2 + §9 (retry on probe conflict).
        """

        peer_mac = MacAddress("02:00:00:00:00:99")
        self._set_claim_outcome(success=False, peer_mac=peer_mac)

        self._client._do_claiming()

        self.assertEqual(
            self._client._state,
            Ip4LinkLocalState.INIT,
            msg="Conflict must transition CLAIMING -> INIT for a fresh candidate.",
        )
        self.assertEqual(
            self._client._conflict_count,
            1,
            msg="Conflict must bump the conflict counter.",
        )
        self.assertIsNone(
            self._client._candidate,
            msg="Conflict must clear the candidate so INIT picks a new one.",
        )

    def test__ip4_link_local__claiming_retry_picks_different_candidate(self) -> None:
        """
        Ensure that running INIT after a conflict picks a
        DIFFERENT candidate — the RNG's attempt counter rolls
        the sequence forward so the retry doesn't probe the
        same address.

        Reference: RFC 3927 §2.1 (attempt counter rolls the sequence).
        """

        first_candidate = self._client._candidate
        assert first_candidate is not None

        peer_mac = MacAddress("02:00:00:00:00:99")
        self._set_claim_outcome(success=False, peer_mac=peer_mac)
        self._client._do_claiming()
        self._client._do_init()  # pick the next candidate
        second_candidate = self._client._candidate
        assert second_candidate is not None

        self.assertNotEqual(
            first_candidate.address,
            second_candidate.address,
            msg="Retry after conflict must pick a different candidate.",
        )

    def test__ip4_link_local__claiming_max_conflicts_rate_limits(self) -> None:
        """
        Ensure that after MAX_CONFLICTS consecutive conflicts
        the FSM sleeps RATE_LIMIT_INTERVAL seconds and resets
        the conflict counter so the next attempt round can
        start fresh.

        Reference: RFC 3927 §9 (MAX_CONFLICTS, RATE_LIMIT_INTERVAL).
        """

        peer_mac = MacAddress("02:00:00:00:00:99")
        self._set_claim_outcome(success=False, peer_mac=peer_mac)

        # Drive MAX_CONFLICTS conflicts. Each iteration:
        #   - _do_claiming sees the conflict, calls _on_claim_conflict
        #   - _on_claim_conflict bumps count, clears candidate,
        #     and (at the MAX-th conflict) sleeps + resets count.
        #   - _do_init picks the next candidate so the next
        #     _do_claiming has something to claim.
        for _ in range(ip4ll_const.IP4_LINK_LOCAL__MAX_CONFLICTS):
            self._client._do_claiming()
            self._client._do_init()

        self.assertEqual(
            self._client._conflict_count,
            0,
            msg="Rate-limit pause must reset the conflict counter.",
        )
        # The sleep MUST have been called with the documented
        # RATE_LIMIT_INTERVAL value.
        sleep_arg_values = [c.args[0] for c in self._mock_sleep.call_args_list]
        self.assertIn(
            ip4ll_const.IP4_LINK_LOCAL__RATE_LIMIT_INTERVAL,
            sleep_arg_values,
            msg=f"time.sleep must be called with RATE_LIMIT_INTERVAL "
            f"({ip4ll_const.IP4_LINK_LOCAL__RATE_LIMIT_INTERVAL}). Got sleeps: {sleep_arg_values}",
        )

    def test__ip4_link_local__claiming_sysctl_overrides_honoured(self) -> None:
        """
        Ensure the FSM reads 'ip4_link_local.max_conflicts' /
        'rate_limit_interval_s' via qualified-module access so
        an operator override resolves on the next read rather
        than freezing at import time.

        Reference: PyTCP sysctl framework (qualified-module read pattern).
        """

        sysctl_module.set("ip4_link_local.max_conflicts", 2)
        sysctl_module.set("ip4_link_local.rate_limit_interval_s", 7)

        peer_mac = MacAddress("02:00:00:00:00:99")
        self._set_claim_outcome(success=False, peer_mac=peer_mac)

        # Two conflicts triggers the rate-limit under the
        # override.
        for _ in range(2):
            self._client._do_claiming()
            self._client._do_init()

        sleep_arg_values = [c.args[0] for c in self._mock_sleep.call_args_list]
        self.assertIn(
            7,
            sleep_arg_values,
            msg=f"Sleep must use the live sysctl-overridden interval (7). " f"Got sleeps: {sleep_arg_values}",
        )

    def test__ip4_link_local__subsystem_loop_drives_claiming(self) -> None:
        """
        Ensure '_subsystem_loop' dispatches the CLAIMING state
        to '_do_claiming' — the FSM-driver contract.

        Reference: PyTCP test infrastructure (FSM dispatch contract).
        """

        self._set_claim_outcome(success=True)
        # Confirm we're in CLAIMING from the INIT-tick in setUp.
        self.assertEqual(self._client._state, Ip4LinkLocalState.CLAIMING)

        self._client._subsystem_loop()

        self.assertEqual(
            self._client._state,
            Ip4LinkLocalState.BOUND,
            msg="One CLAIMING-tick must hand off to _do_claiming and reach BOUND on clean probe.",
        )


class TestIp4LinkLocalConstantsSysctls(TestCase):
    """
    The 'ip4_link_local.max_conflicts' /
    'rate_limit_interval_s' sysctl registration and validator
    tests.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so a per-test mutation never
        leaks into a subsequent test's baseline.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__ip4_link_local__sysctl__max_conflicts_default_matches_rfc(self) -> None:
        """
        Ensure 'IP4_LINK_LOCAL__MAX_CONFLICTS' defaults to 10
        — the documented MAX_CONFLICTS value.

        Reference: RFC 3927 §9 (MAX_CONFLICTS = 10).
        """

        self.assertEqual(
            ip4ll_const.IP4_LINK_LOCAL__MAX_CONFLICTS,
            10,
            msg="MAX_CONFLICTS default must match the RFC §9 value of 10.",
        )

    def test__ip4_link_local__sysctl__rate_limit_default_matches_rfc(self) -> None:
        """
        Ensure 'IP4_LINK_LOCAL__RATE_LIMIT_INTERVAL' defaults
        to 60 seconds — the documented RATE_LIMIT_INTERVAL.

        Reference: RFC 3927 §9 (RATE_LIMIT_INTERVAL = 60 seconds).
        """

        self.assertEqual(
            ip4ll_const.IP4_LINK_LOCAL__RATE_LIMIT_INTERVAL,
            60,
            msg="RATE_LIMIT_INTERVAL default must match the RFC §9 value of 60.",
        )

    def test__ip4_link_local__sysctl__max_conflicts_registered(self) -> None:
        """
        Ensure 'ip4_link_local.max_conflicts' is registered in
        the sysctl registry so operator overrides resolve.

        Reference: PyTCP sysctl framework (knob registration).
        """

        self.assertIn(
            "ip4_link_local.max_conflicts",
            sysctl_module.list_keys(),
            msg="ip4_link_local.max_conflicts must be a registered sysctl.",
        )

    def test__ip4_link_local__sysctl__rate_limit_registered(self) -> None:
        """
        Ensure 'ip4_link_local.rate_limit_interval_s' is
        registered in the sysctl registry.

        Reference: PyTCP sysctl framework (knob registration).
        """

        self.assertIn(
            "ip4_link_local.rate_limit_interval_s",
            sysctl_module.list_keys(),
            msg="ip4_link_local.rate_limit_interval_s must be a registered sysctl.",
        )

    def test__ip4_link_local__sysctl__max_conflicts_rejects_zero(self) -> None:
        """
        Ensure the 'max_conflicts' validator rejects zero —
        the retry loop needs at least one attempt before
        rate-limiting.

        Reference: PyTCP sysctl framework (positive-int validator).
        """

        with self.assertRaises(ValueError) as ctx:
            sysctl_module.set("ip4_link_local.max_conflicts", 0)

        self.assertIn(
            "ip4_link_local.max_conflicts",
            str(ctx.exception),
            msg="Rejection must surface the offending key.",
        )

    def test__ip4_link_local__sysctl__rate_limit_rejects_zero(self) -> None:
        """
        Ensure the 'rate_limit_interval_s' validator rejects
        zero — a zero interval defeats the rate-limit's
        purpose (back-to-back attempts).

        Reference: PyTCP sysctl framework (positive-int validator).
        """

        with self.assertRaises(ValueError) as ctx:
            sysctl_module.set("ip4_link_local.rate_limit_interval_s", 0)

        self.assertIn(
            "ip4_link_local.rate_limit_interval_s",
            str(ctx.exception),
            msg="Rejection must surface the offending key.",
        )

    def test__ip4_link_local__sysctl__set_propagates_to_module_attr(self) -> None:
        """
        Ensure 'sysctl.set' updates the backing module
        attribute so qualified-module reads see the new
        value on the next access.

        Reference: PyTCP sysctl framework (qualified-module read pattern).
        """

        sysctl_module.set("ip4_link_local.max_conflicts", 5)

        self.assertEqual(
            ip4ll_const.IP4_LINK_LOCAL__MAX_CONFLICTS,
            5,
            msg="set('ip4_link_local.max_conflicts', 5) must update the module attribute.",
        )
