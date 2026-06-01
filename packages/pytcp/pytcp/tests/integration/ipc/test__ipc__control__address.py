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
Integration tests for the out-of-process address control mirror.

pytcp/tests/integration/ipc/test__ipc__control__address.py

ver 3.0.8
"""

from pytcp import stack
from pytcp.runtime.socket import AddressFamily
from pytcp.tests.lib.ipc_control_testcase import IpcControlTestCase


class TestIpcControlAddress(IpcControlTestCase):
    """
    The out-of-process address control-mirror tests.
    """

    def test__ipc__control__address_list_matches_in_process(self) -> None:
        """
        Ensure an out-of-process list_ifaddrs returns the same interface
        addresses the in-process API reports, so Ip4IfAddr / Ip6IfAddr
        values round-trip across the boundary.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()

        self.assertEqual(
            client.address.interface(self._ifindex).list_ifaddrs(),
            stack.address.interface(self._ifindex).list_ifaddrs(),
            msg="A client list_ifaddrs must match the in-process interface addresses.",
        )

    def test__ipc__control__address_list_family_filter_matches_in_process(self) -> None:
        """
        Ensure an out-of-process list_ifaddrs filtered by address family
        matches the in-process family-filtered result.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()

        self.assertEqual(
            client.address.interface(self._ifindex).list_ifaddrs(family=AddressFamily.INET4),
            stack.address.interface(self._ifindex).list_ifaddrs(family=AddressFamily.INET4),
            msg="A client family-filtered list_ifaddrs must match the in-process result.",
        )
