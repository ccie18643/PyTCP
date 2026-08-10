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
Unit tests for the 'Ip4LinkLocal' BOUND-state conflict
defence logic — RFC 3927 §2.5 defend / abandon decision
tree driven by polling the 'Ip4Acd' engine's
'poll_conflict' each BOUND tick.

pytcp/tests/unit/protocols/ip4/link_local/test__link_local__client__bound.py

ver 3.0.9
"""

from typing import cast, override
from unittest import TestCase
from unittest.mock import MagicMock, create_autospec, patch

from net_addr import MacAddress
from pytcp.protocols.arp import arp__constants
from pytcp.protocols.ip4.acd.ip4_acd import AcdResult, Ip4Acd
from pytcp.protocols.ip4.link_local.link_local__client import (
    Ip4LinkLocal,
    Ip4LinkLocalState,
)
from pytcp.stack.address import AddressApi

_PEER_MAC = MacAddress("02:00:00:00:00:99")


class TestIp4LinkLocalBoundConflict(TestCase):
    """
    The 'Ip4LinkLocal' BOUND-state conflict-defence tests.
    """

    @override
    def setUp(self) -> None:
        """
        Stand up a client and drive it to BOUND so each test
        can drive conflict outcomes directly through the mocked
        'Ip4Acd' engine's 'poll_conflict' return value.
        """

        self.enterContext(patch("pytcp.protocols.ip4.link_local.link_local__client.log"))
        self.enterContext(patch("pytcp.runtime.subsystem.log"))
        self._mock_time = self.enterContext(
            patch("pytcp.protocols.ip4.link_local.link_local__client.time.monotonic"),
        )
        self._mock_time.return_value = 100.0

        self._mac = MacAddress("02:00:00:00:00:07")
        self._address_api: AddressApi = create_autospec(AddressApi, spec_set=True)
        self._acd: Ip4Acd = create_autospec(Ip4Acd, spec_set=True)

        self._client = Ip4LinkLocal(
            mac_address=self._mac,
            address_api=self._address_api,
            acd=self._acd,
        )
        # Drive to BOUND: pick a candidate, configure the ACD engine's
        # claim to succeed, run the claim (which installs via the
        # address API and leaves the engine's defense socket open).
        self._client._do_init()
        candidate = self._client._candidate
        assert candidate is not None
        cast(MagicMock, self._acd).claim.return_value = AcdResult(success=True, address=candidate.address)
        self._client._do_claiming()
        assert self._client._state is Ip4LinkLocalState.BOUND

    def test__ip4_link_local__bound_tick_polls_acd_for_conflict(self) -> None:
        """
        Ensure a BOUND subsystem tick polls the ACD engine for a
        post-claim conflict — ongoing detection reads ARP off the
        engine's packet socket, not a callback from the ARP RX path.

        Reference: RFC 3927 §2.5 (ongoing conflict detection while bound).
        """

        cast(MagicMock, self._acd).poll_conflict.return_value = None

        self._client._subsystem_loop()

        cast(MagicMock, self._acd).poll_conflict.assert_called_once()

    def test__ip4_link_local__first_conflict_defends_and_stays_bound(self) -> None:
        """
        Ensure the first conflict within the DEFEND_INTERVAL
        triggers a single defensive gratuitous ARP and the
        FSM stays BOUND.

        Reference: RFC 3927 §2.5(b) (defend with one gratuitous ARP).
        """

        self._client._handle_bound_conflict(_PEER_MAC)

        cast(MagicMock, self._acd).defend.assert_called_once_with()
        self.assertEqual(
            self._client._state,
            Ip4LinkLocalState.BOUND,
            msg="First conflict must keep the FSM in BOUND.",
        )

    def test__ip4_link_local__second_conflict_in_window_abandons(self) -> None:
        """
        Ensure a second conflict within DEFEND_INTERVAL of the first
        triggers the abandon path — remove the host (which aborts bound
        TCP sessions), release the ACD claim, transition to INIT.

        Reference: RFC 3927 §2.5(a) (abandon after second conflict within DEFEND_INTERVAL).
        """

        # First conflict at t=100s; second at t=105s (within DEFEND_INTERVAL=10s).
        bound_candidate = self._client._candidate
        assert bound_candidate is not None
        bound_address = bound_candidate.address

        self._mock_time.return_value = 100.0
        self._client._handle_bound_conflict(_PEER_MAC)

        self._mock_time.return_value = 105.0
        self._client._handle_bound_conflict(_PEER_MAC)

        # Verify abandon side effects: remove (aborts sessions by
        # default) + ACD release.
        cast(MagicMock, self._address_api).remove.assert_called_once_with(address=bound_address)
        cast(MagicMock, self._acd).release.assert_called_once()
        self.assertEqual(
            self._client._state,
            Ip4LinkLocalState.INIT,
            msg="Second conflict in DEFEND_INTERVAL must transition to INIT for reconfigure.",
        )
        self.assertIsNone(
            self._client._candidate,
            msg="Abandon must clear the candidate.",
        )
        # Counter bumps so the next _do_init picks a different attempt.
        self.assertEqual(
            self._client._conflict_count,
            1,
            msg="Abandon must bump the conflict_count for the RNG attempt roll.",
        )

    def test__ip4_link_local__second_conflict_outside_window_defends_again(self) -> None:
        """
        Ensure a second conflict OUTSIDE DEFEND_INTERVAL is
        treated as a fresh first-conflict — defend again,
        stay BOUND, no abandon. The RFC's "within
        DEFEND_INTERVAL" window is rolling, not cumulative.

        Reference: RFC 3927 §2.5(b) (DEFEND_INTERVAL is rolling).
        """

        self._mock_time.return_value = 100.0
        self._client._handle_bound_conflict(_PEER_MAC)

        # Second conflict at t=200s — well past DEFEND_INTERVAL (10s).
        self._mock_time.return_value = 200.0
        self._client._handle_bound_conflict(_PEER_MAC)

        # Two defends (one per conflict), no abandon.
        self.assertEqual(
            cast(MagicMock, self._acd).defend.call_count,
            2,
            msg="Two conflicts outside the window must both trigger defends.",
        )
        cast(MagicMock, self._address_api).remove.assert_not_called()
        cast(MagicMock, self._acd).release.assert_not_called()
        self.assertEqual(
            self._client._state,
            Ip4LinkLocalState.BOUND,
            msg="FSM must remain BOUND across rolling-window conflicts.",
        )

    def test__ip4_link_local__abandon_uses_arp_defend_interval(self) -> None:
        """
        Ensure the defend-or-abandon decision reads
        'ARP__DEFEND_INTERVAL' via qualified-module access so
        an operator override of 'arp.defend_interval' resolves
        on the next conflict.

        Reference: PyTCP sysctl framework (qualified-module read pattern).
        """

        # Default DEFEND_INTERVAL is 10s. With a value of 1s,
        # a 2-second gap between conflicts crosses the window
        # and the second one defends (no abandon).
        with patch.object(arp__constants, "ARP__DEFEND_INTERVAL", 1):
            self._mock_time.return_value = 100.0
            self._client._handle_bound_conflict(_PEER_MAC)
            self._mock_time.return_value = 102.0  # gap = 2s > 1s
            self._client._handle_bound_conflict(_PEER_MAC)

        cast(MagicMock, self._acd).release.assert_not_called()
        self.assertEqual(
            self._client._state,
            Ip4LinkLocalState.BOUND,
            msg="With shortened DEFEND_INTERVAL the second conflict must be outside the window.",
        )
