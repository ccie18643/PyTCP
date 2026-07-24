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
Unit tests for the 'Ip4LinkLocal' DHCPv4 coordination logic —
RFC 3927 §2.11 (DHCP behaviour is unchanged) and §1.9 (DHCP-
fail fallback timer).

pytcp/tests/unit/protocols/ip4/link_local/test__link_local__client__dhcp.py

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


class TestIp4LinkLocalDhcpCoordination(TestCase):
    """
    The 'Ip4LinkLocal' DHCPv4 coordination tests — initial-
    state selection, halt-on-bind, fallback-timer kick.
    """

    @override
    def setUp(self) -> None:
        """
        Stand up a mock address API and a controllable DHCP
        state getter. The 'dhcp_bound' flag drives the
        '_is_dhcp_bound' callable the link-local subsystem
        polls.
        """

        self.enterContext(patch("pytcp.protocols.ip4.link_local.link_local__client.log"))
        self.enterContext(patch("pytcp.runtime.subsystem.log"))
        self._mock_time = self.enterContext(
            patch("pytcp.protocols.ip4.link_local.link_local__client.time.monotonic"),
        )
        self._mock_time.return_value = 1000.0

        self._mac = MacAddress("02:00:00:00:00:07")
        self._address_api: AddressApi = create_autospec(AddressApi, spec_set=True)
        self._acd: Ip4Acd = create_autospec(Ip4Acd, spec_set=True)
        self._dhcp_bound = False

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test mutations do not
        leak into a subsequent test's baseline.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def _is_dhcp_bound(self) -> bool:
        """Closure the client polls — flips via 'self._dhcp_bound'."""

        return self._dhcp_bound

    def _build_client(self) -> Ip4LinkLocal:
        """Construct a client with the test's mocked dependencies."""

        return Ip4LinkLocal(
            mac_address=self._mac,
            address_api=self._address_api,
            acd=self._acd,
            is_dhcp_bound=self._is_dhcp_bound,
        )

    def test__ip4_link_local__dhcp_fallback_disabled__starts_init(self) -> None:
        """
        Ensure that with 'dhcp_fallback_timeout_ms = 0' (the
        default — feature off) the client starts in INIT and
        claims eagerly regardless of DHCP state.

        Reference: PyTCP RFC 3927 plan §4 (fallback disabled = eager).
        """

        # Default is 0; do not override.
        self._dhcp_bound = False
        client = self._build_client()

        self.assertEqual(
            client._state,
            Ip4LinkLocalState.INIT,
            msg="With fallback disabled the client must start in INIT (eager).",
        )

    def test__ip4_link_local__dhcp_fallback_enabled__starts_halted(self) -> None:
        """
        Ensure that with 'dhcp_fallback_timeout_ms > 0' and a
        DHCP getter present the client starts in HALTED — the
        fallback timer / reconciler is responsible for kicking
        it off.

        Reference: RFC 3927 §1.9 (link-local fallback after DHCP fail).
        """

        sysctl_module.set("ip4_link_local.dhcp_fallback_timeout_ms", 5_000)

        client = self._build_client()

        self.assertEqual(
            client._state,
            Ip4LinkLocalState.HALTED,
            msg="With fallback enabled the client must start in HALTED.",
        )

    def test__ip4_link_local__dhcp_bound_halts_bound_state(self) -> None:
        """
        Ensure that when DHCP transitions to BOUND while the
        link-local subsystem is BOUND the link-local address
        is released, the subscription is cancelled, and the
        FSM transitions to HALTED.

        Reference: RFC 3927 §2.11 / §1.9 (DHCP success halts link-local).
        """

        sysctl_module.set("ip4_link_local.dhcp_fallback_timeout_ms", 5_000)

        # Get to BOUND first: pretend DHCP unbound, complete a
        # claim by manually walking INIT -> CLAIMING.
        self._dhcp_bound = False
        client = self._build_client()
        # Hop to INIT manually (bypass the reconciler for the
        # boot path) and pick a candidate so claim_with_acd has
        # a real address to receive on success.
        client._state = Ip4LinkLocalState.INIT
        client._do_init()
        candidate = client._candidate
        assert candidate is not None
        cast(MagicMock, self._acd).claim.return_value = AcdResult(success=True, address=candidate.address)
        client._do_claiming()
        assert client._state is Ip4LinkLocalState.BOUND

        # Now flip DHCP to BOUND and drive a subsystem-loop tick.
        self._dhcp_bound = True
        client._subsystem_loop()

        # Verify the release path: ACD release, remove, halted.
        cast(MagicMock, self._acd).release.assert_called_once()
        cast(MagicMock, self._address_api).remove.assert_called_once()
        self.assertEqual(
            client._state,
            Ip4LinkLocalState.HALTED,
            msg="DHCP bound while link-local BOUND must release and HALT.",
        )
        self.assertIsNone(
            client._candidate,
            msg="DHCP-bind release must clear the candidate.",
        )

    def test__ip4_link_local__dhcp_unbound_kicks_after_timeout(self) -> None:
        """
        Ensure that after DHCP has been unbound continuously
        for 'dhcp_fallback_timeout_ms' the FSM transitions
        HALTED -> INIT so the next tick picks a candidate.

        Reference: RFC 3927 §1.9 (link-local fallback after DHCP fail).
        """

        sysctl_module.set("ip4_link_local.dhcp_fallback_timeout_ms", 5_000)

        self._dhcp_bound = False
        self._mock_time.return_value = 1000.0
        client = self._build_client()
        assert client._state is Ip4LinkLocalState.HALTED

        # Tick 1: starts the fallback timer; stays HALTED (no time elapsed).
        client._subsystem_loop()
        self.assertEqual(
            client._state,
            Ip4LinkLocalState.HALTED,
            msg="First tick before timeout must keep the client HALTED.",
        )

        # Fast-forward past the timeout (5 s) and tick again.
        self._mock_time.return_value = 1010.0  # 10 s elapsed
        client._subsystem_loop()

        # The reconciler should have transitioned HALTED -> INIT
        # and then the dispatch picked a candidate (state -> CLAIMING).
        # Either INIT or CLAIMING is "kicked off"; the contract is
        # that we're no longer HALTED.
        self.assertNotEqual(
            client._state,
            Ip4LinkLocalState.HALTED,
            msg="After fallback timeout the client must leave HALTED.",
        )

    def test__ip4_link_local__dhcp_unbound_before_timeout_stays_halted(self) -> None:
        """
        Ensure that ticks BEFORE the fallback window has
        elapsed keep the FSM HALTED — link-local does not
        race DHCP to claim.

        Reference: RFC 3927 §1.9 (wait for DHCP to fail before fallback).
        """

        sysctl_module.set("ip4_link_local.dhcp_fallback_timeout_ms", 5_000)

        self._dhcp_bound = False
        self._mock_time.return_value = 1000.0
        client = self._build_client()

        # Tick at t=1000: starts timer.
        client._subsystem_loop()
        # Tick at t=1003 (3s elapsed; window is 5s) — still HALTED.
        self._mock_time.return_value = 1003.0
        client._subsystem_loop()

        self.assertEqual(
            client._state,
            Ip4LinkLocalState.HALTED,
            msg="Within the fallback window the client must stay HALTED.",
        )

    def test__ip4_link_local__dhcp_bind_during_timer_resets(self) -> None:
        """
        Ensure that a DHCP bind during the fallback window
        cancels the fallback timer — the FSM stays HALTED and
        the timer resets so a later DHCP-loss restarts the
        countdown from zero.

        Reference: RFC 3927 §2.11 (DHCP success cancels fallback).
        """

        sysctl_module.set("ip4_link_local.dhcp_fallback_timeout_ms", 5_000)

        self._dhcp_bound = False
        self._mock_time.return_value = 1000.0
        client = self._build_client()

        # Tick 1: starts timer.
        client._subsystem_loop()
        self.assertEqual(client._state, Ip4LinkLocalState.HALTED)

        # Flip DHCP to BOUND mid-window.
        self._dhcp_bound = True
        self._mock_time.return_value = 1002.0
        client._subsystem_loop()

        # Now flip back to unbound at t=1003. The fallback
        # timer should restart from t=1003 (not t=1000) so a
        # subsequent tick at t=1006 (3 s elapsed since restart;
        # window is 5 s) is still HALTED.
        self._dhcp_bound = False
        self._mock_time.return_value = 1003.0
        client._subsystem_loop()
        self._mock_time.return_value = 1006.0
        client._subsystem_loop()

        self.assertEqual(
            client._state,
            Ip4LinkLocalState.HALTED,
            msg="DHCP bind during the fallback window must reset the timer.",
        )

    def test__ip4_link_local__no_dhcp_getter_means_eager(self) -> None:
        """
        Ensure that when no DHCP getter is wired (e.g. no
        DHCP client on the stack) the client runs eager even
        with the fallback timeout set — there's nothing to
        coordinate against.

        Reference: PyTCP RFC 3927 plan §4 (no DHCP getter = no coordination).
        """

        sysctl_module.set("ip4_link_local.dhcp_fallback_timeout_ms", 5_000)

        client = Ip4LinkLocal(
            mac_address=self._mac,
            address_api=self._address_api,
            acd=self._acd,
            is_dhcp_bound=None,
        )

        self.assertEqual(
            client._state,
            Ip4LinkLocalState.INIT,
            msg="With no DHCP getter the client must start eager (INIT).",
        )

    def test__ip4_link_local__sysctl_dhcp_fallback_default_is_zero(self) -> None:
        """
        Ensure the default 'dhcp_fallback_timeout_ms' is 0 —
        feature off by default; operator opts in.

        Reference: PyTCP RFC 3927 plan §4 (opt-in by default).
        """

        self.assertEqual(
            ip4ll_const.IP4_LINK_LOCAL__DHCP_FALLBACK_TIMEOUT_MS,
            0,
            msg="dhcp_fallback_timeout_ms must default to 0 (feature off).",
        )

    def test__ip4_link_local__sysctl_dhcp_fallback_registered(self) -> None:
        """
        Ensure 'ip4_link_local.dhcp_fallback_timeout_ms' is
        registered in the sysctl registry.

        Reference: PyTCP sysctl framework (knob registration).
        """

        self.assertIn(
            "ip4_link_local.dhcp_fallback_timeout_ms",
            sysctl_module.list_keys(),
            msg="dhcp_fallback_timeout_ms must be a registered sysctl.",
        )

    def test__ip4_link_local__sysctl_dhcp_fallback_rejects_negative(self) -> None:
        """
        Ensure the validator rejects negative values — a
        negative fallback timeout has no defined semantics.

        Reference: PyTCP sysctl framework (non-negative-int validator).
        """

        with self.assertRaises(ValueError) as ctx:
            sysctl_module.set("ip4_link_local.dhcp_fallback_timeout_ms", -1)

        self.assertIn(
            "ip4_link_local.dhcp_fallback_timeout_ms",
            str(ctx.exception),
            msg="Rejection must surface the offending key.",
        )
