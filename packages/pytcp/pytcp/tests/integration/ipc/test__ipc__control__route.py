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
Integration tests for the out-of-process route control mirror.

pytcp/tests/integration/ipc/test__ipc__control__route.py

ver 3.0.9
"""

from net_addr import Ip4Address, Ip4Network
from pytcp import stack
from pytcp.runtime.fib import Route, RouteProtocol
from pytcp.runtime.socket import AddressFamily
from pytcp.tests.lib.ipc_control_testcase import IpcControlTestCase


class TestIpcControlRoute(IpcControlTestCase):
    """
    The out-of-process route control-mirror tests.
    """

    def test__ipc__control__route_list_matches_in_process(self) -> None:
        """
        Ensure an out-of-process route list returns the same routes the
        in-process FIB holds, so Route snapshots round-trip across the
        boundary.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()

        self.assertEqual(
            client.route.list_routes(),
            stack.route.list_routes(),
            msg="A client route list must match the in-process route table.",
        )

    def test__ipc__control__route_add_reflected_in_process(self) -> None:
        """
        Ensure an out-of-process add_route installs the route in the
        real daemon FIB, visible to a subsequent in-process list.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()
        route = Route(
            destination=Ip4Network("10.9.9.0/24"),
            gateway=Ip4Address("10.0.1.1"),
            protocol=RouteProtocol.STATIC,
        )

        client.route.add_route(route=route)

        self.assertIn(
            route,
            stack.route.list_routes(),
            msg="A client add_route must install the route in the daemon FIB.",
        )

    def test__ipc__control__route_remove_default_returns_count(self) -> None:
        """
        Ensure an out-of-process remove_default removes the fixture
        IPv4 default route and reports the removed count.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()

        self.assertEqual(
            client.route.remove_default(family=AddressFamily.INET4),
            1,
            msg="A client remove_default must remove and count the IPv4 default route.",
        )
