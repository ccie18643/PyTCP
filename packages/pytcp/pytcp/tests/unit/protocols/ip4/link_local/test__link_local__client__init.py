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
Unit tests for the 'Ip4LinkLocal' subsystem skeleton — the
RFC 3927 IPv4 link-local autoconfig FSM. Phase 1 covers the
INIT state (candidate selection); Phase 2 will cover the
CLAIMING state.

pytcp/tests/unit/protocols/ip4/link_local/test__link_local__client__init.py

ver 3.0.10
"""

from typing import cast, override
from unittest import TestCase
from unittest.mock import patch

from net_addr import MacAddress
from pytcp.protocols.ip4.acd.ip4_acd import Ip4Acd
from pytcp.protocols.ip4.link_local.link_local__client import (
    Ip4LinkLocal,
    Ip4LinkLocalState,
)
from pytcp.stack.address import AddressApi


def _make_address_api_mock() -> AddressApi:
    """Build an autospec'd AddressApi for tests."""

    from unittest.mock import create_autospec

    return cast(AddressApi, create_autospec(AddressApi, spec_set=True))


def _make_acd_mock() -> Ip4Acd:
    """Build an autospec'd Ip4Acd for tests."""

    from unittest.mock import create_autospec

    return cast(Ip4Acd, create_autospec(Ip4Acd, spec_set=True))


class TestIp4LinkLocalState(TestCase):
    """
    The 'Ip4LinkLocalState' enum membership tests.
    """

    def test__ip4_link_local_state__has_init_claiming_bound_halted(self) -> None:
        """
        Ensure the FSM enum carries the four canonical states —
        INIT (pick candidate), CLAIMING (claim_with_acd in
        flight), BOUND (address installed), HALTED (disabled).

        Reference: RFC 3927 §2 (link-local autoconfig state machine).
        """

        names = {member.name for member in Ip4LinkLocalState}

        self.assertEqual(
            names,
            {"INIT", "CLAIMING", "BOUND", "HALTED"},
            msg="Ip4LinkLocalState must carry exactly INIT / CLAIMING / BOUND / HALTED.",
        )


class TestIp4LinkLocalInit(TestCase):
    """
    The 'Ip4LinkLocal' INIT-state tests — Phase 1 covers
    candidate selection only; subsequent phases add the
    claim / defend / DHCP-coordination behaviour.
    """

    @override
    def setUp(self) -> None:
        """
        Silence the subsystem's '<stack>' log line so test
        output isn't speckled with stack-init traces.
        """

        self.enterContext(patch("pytcp.protocols.ip4.link_local.link_local__client.log"))
        self.enterContext(patch("pytcp.runtime.subsystem.log"))
        self._mac = MacAddress("02:00:00:00:00:07")
        self._client = Ip4LinkLocal(
            mac_address=self._mac,
            address_api=_make_address_api_mock(),
            acd=_make_acd_mock(),
        )

    def test__ip4_link_local__initial_state_is_init(self) -> None:
        """
        Ensure a freshly constructed 'Ip4LinkLocal' is in the
        INIT state — no candidate selected yet; the first
        subsystem-loop tick picks the first candidate.

        Reference: RFC 3927 §2.1 (initial candidate selection).
        """

        self.assertEqual(
            self._client._state,
            Ip4LinkLocalState.INIT,
            msg="Ip4LinkLocal must start in the INIT state.",
        )
        self.assertIsNone(
            self._client._candidate,
            msg="Ip4LinkLocal must start with no candidate selected.",
        )
        self.assertEqual(
            self._client._conflict_count,
            0,
            msg="Ip4LinkLocal conflict counter must start at zero.",
        )

    def test__ip4_link_local__do_init_picks_link_local_candidate(self) -> None:
        """
        Ensure '_do_init' transitions INIT → CLAIMING and
        installs a candidate whose address is in the RFC
        3927 §2.1 link-local range (169.254.1.0..169.254.254.255).

        Reference: RFC 3927 §2.1 (pseudo-random selection from the link-local range).
        """

        self._client._do_init()

        self.assertEqual(
            self._client._state,
            Ip4LinkLocalState.CLAIMING,
            msg="After _do_init the state must transition to CLAIMING.",
        )
        candidate = self._client._candidate
        self.assertIsNotNone(
            candidate,
            msg="_do_init must install a non-None candidate.",
        )
        assert candidate is not None  # mypy narrowing
        self.assertTrue(
            candidate.address.is_link_local,
            msg=f"Candidate address {candidate.address} must be link-local.",
        )

    def test__ip4_link_local__do_init_uses_mac_seeded_rng(self) -> None:
        """
        Ensure '_do_init' picks the candidate via the MAC-
        seeded RNG so two clients with the same MAC pick the
        same first candidate — required for reboot-stability
        (the §2.1 SHOULD).

        Reference: RFC 3927 §2.1 (deterministic per-host selection).
        """

        client_a = Ip4LinkLocal(mac_address=self._mac, address_api=_make_address_api_mock(), acd=_make_acd_mock())
        client_b = Ip4LinkLocal(mac_address=self._mac, address_api=_make_address_api_mock(), acd=_make_acd_mock())

        client_a._do_init()
        client_b._do_init()

        assert client_a._candidate is not None and client_b._candidate is not None
        self.assertEqual(
            client_a._candidate.address,
            client_b._candidate.address,
            msg="Two clients with the same MAC must pick the same first candidate.",
        )

    def test__ip4_link_local__subsystem_loop_dispatches_on_state(self) -> None:
        """
        Ensure '_subsystem_loop' delegates to '_do_init' when
        the state is INIT — Phase 1's only wired dispatch
        branch. Phase 2 adds CLAIMING, Phase 3 adds BOUND
        with the conflict-callback wiring.

        Reference: PyTCP test infrastructure (FSM dispatch contract).
        """

        # Hop straight into INIT (default) and run one loop
        # tick — assert the state advanced to CLAIMING.
        self._client._subsystem_loop()

        self.assertEqual(
            self._client._state,
            Ip4LinkLocalState.CLAIMING,
            msg="One INIT-state subsystem-loop tick must advance to CLAIMING.",
        )

    def test__ip4_link_local__halted_state_is_inert(self) -> None:
        """
        Ensure '_subsystem_loop' is a no-op when the state is
        HALTED — the client stays HALTED until something else
        (e.g. DHCP loss) flips it back to INIT.

        Reference: RFC 3927 §2.11 (DHCP success halts link-local).
        """

        self._client._state = Ip4LinkLocalState.HALTED

        self._client._subsystem_loop()

        self.assertEqual(
            self._client._state,
            Ip4LinkLocalState.HALTED,
            msg="HALTED must remain HALTED across subsystem-loop ticks.",
        )
        self.assertIsNone(
            self._client._candidate,
            msg="HALTED state must not pick a candidate.",
        )
