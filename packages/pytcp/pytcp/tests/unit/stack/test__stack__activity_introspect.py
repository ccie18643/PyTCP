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
This module contains tests for the per-interface activity introspection API.

pytcp/tests/unit/stack/test__stack__activity_introspect.py

ver 3.0.9
"""

from types import SimpleNamespace
from typing import cast
from unittest import TestCase

from net_addr import Ip6Address
from pytcp.protocols.dhcp4.dhcp4__client import Dhcp4State
from pytcp.protocols.icmp6.nd.nd__router_state import Icmp6DadState
from pytcp.stack.activity_introspect import (
    InterfaceActivity,
    build_interface_activity,
)


def _handler(
    *,
    name: str,
    dhcp4_state: Dhcp4State | None = None,
    dad: dict[Ip6Address, Icmp6DadState] | None = None,
) -> object:
    """
    Build a duck-typed interface stand-in with the attributes the activity
    reader consults.
    """

    return SimpleNamespace(
        interface_name=name,
        dhcp4_client=(SimpleNamespace(state=dhcp4_state) if dhcp4_state is not None else None),
        dad_states=dad if dad is not None else {},
    )


class TestBuildInterfaceActivity(TestCase):
    """
    The 'build_interface_activity' reader tests.
    """

    def test__activity__reports_dhcp4_state(self) -> None:
        """
        Ensure the per-interface activity reports the DHCPv4 client's FSM
        state as the 'acquiring DHCP' indicator.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler = _handler(name="tap7", dhcp4_state=Dhcp4State.SELECTING)

        activity = build_interface_activity([(1, handler)])

        self.assertEqual(
            activity,
            (InterfaceActivity(ifindex=1, name="tap7", dhcp4_state="SELECTING", tentative_ip6=()),),
            msg="The activity must report the DHCPv4 FSM state.",
        )

    def test__activity__no_dhcp4_client_reports_none(self) -> None:
        """
        Ensure an interface without a DHCPv4 client reports a None DHCPv4
        state (e.g. a TUN interface).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        activity = build_interface_activity([(3, _handler(name="tun3"))])

        self.assertIsNone(
            activity[0].dhcp4_state,
            msg="An interface with no DHCPv4 client must report a None DHCPv4 state.",
        )

    def test__activity__reports_only_in_progress_dad_addresses(self) -> None:
        """
        Ensure the tentative address list reports only addresses still in
        Duplicate Address Detection (TENTATIVE / OPTIMISTIC), not addresses
        that have already passed DAD (VALID).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        dad = {
            Ip6Address("2603:808c::1"): Icmp6DadState.TENTATIVE,
            Ip6Address("2603:808c::2"): Icmp6DadState.OPTIMISTIC,
            Ip6Address("2603:808c::3"): Icmp6DadState.VALID,
        }

        activity = build_interface_activity([(1, _handler(name="tap7", dad=dad))])

        self.assertEqual(
            set(activity[0].tentative_ip6),
            {Ip6Address("2603:808c::1"), Ip6Address("2603:808c::2")},
            msg="Only TENTATIVE / OPTIMISTIC addresses are still autoconfiguring (in DAD).",
        )

    def test__activity__sorted_by_ifindex(self) -> None:
        """
        Ensure the activity list is deterministically ordered by ifindex.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        activity = build_interface_activity(
            [
                (2, _handler(name="tap9")),
                (1, _handler(name="tap7")),
            ]
        )

        self.assertEqual(
            [a.ifindex for a in activity],
            [1, 2],
            msg="The activity list must be sorted by ifindex.",
        )


class TestActivityIntrospectApi(TestCase):
    """
    The 'ActivityIntrospectApi.list_activity' tests.
    """

    def test__activity_api__reads_stack_interfaces(self) -> None:
        """
        Ensure 'list_activity' reads the live interface table and returns a
        per-interface activity snapshot.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from unittest.mock import patch

        from pytcp.stack.activity_introspect import ActivityIntrospectApi

        handler = _handler(name="tap7", dhcp4_state=Dhcp4State.BOUND)
        fake_interfaces = cast("object", SimpleNamespace(items=lambda: [(1, handler)]))

        with patch("pytcp.stack.interfaces", fake_interfaces, create=True):
            activity = ActivityIntrospectApi().list_activity()

        self.assertEqual(
            activity,
            (InterfaceActivity(ifindex=1, name="tap7", dhcp4_state="BOUND", tentative_ip6=()),),
            msg="list_activity must snapshot the live interface table.",
        )
