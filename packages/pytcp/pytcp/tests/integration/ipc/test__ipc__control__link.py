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
Integration tests for the out-of-process link control mirror.

pytcp/tests/integration/ipc/test__ipc__control__link.py

ver 3.0.8
"""

from pytcp import stack
from pytcp.tests.lib.ipc_control_testcase import IpcControlTestCase


class TestIpcControlLink(IpcControlTestCase):
    """
    The out-of-process link control-mirror tests.
    """

    def test__ipc__control__link_list_interfaces_matches_in_process(self) -> None:
        """
        Ensure an out-of-process list_interfaces returns the same
        ifindex set the in-process link API reports.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()

        self.assertEqual(
            client.link.list_interfaces(),
            stack.link.list_interfaces(),
            msg="A client list_interfaces must match the in-process ifindex set.",
        )

    def test__ipc__control__link_read_properties_match_in_process(self) -> None:
        """
        Ensure the per-interface read properties (mtu, mac_address,
        is_running, interface_layer, flags, stats) read out of process
        equal the in-process values, so scalar / enum / frozenset /
        snapshot returns round-trip across the boundary.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()
        remote = client.link.interface(self._ifindex)
        local = stack.link.interface(self._ifindex)

        self.assertEqual(
            (
                remote.mtu,
                remote.mac_address,
                remote.is_running,
                remote.interface_layer,
                remote.flags,
                remote.stats,
            ),
            (
                local.mtu,
                local.mac_address,
                local.is_running,
                local.interface_layer,
                local.flags,
                local.stats,
            ),
            msg="The client link read properties must match the in-process values.",
        )

    def test__ipc__control__link_set_mtu_mutates_daemon_state(self) -> None:
        """
        Ensure an out-of-process set_mtu mutates the real daemon
        interface, visible to a subsequent in-process mtu read.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()

        client.link.interface(self._ifindex).set_mtu(mtu=1400)

        self.assertEqual(
            stack.link.interface(self._ifindex).mtu,
            1400,
            msg="A client set_mtu must mutate the daemon interface MTU.",
        )
