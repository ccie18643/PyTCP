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
Integration tests for the out-of-process activity introspection API.

pytcp/tests/integration/ipc/test__ipc__control__activity_introspect.py

ver 3.0.9
"""

from types import SimpleNamespace
from typing import cast

from pytcp.protocols.dhcp4.dhcp4__client import Dhcp4Client, Dhcp4State
from pytcp.tests.lib.ipc_control_testcase import IpcControlTestCase


class TestIpcControlActivityIntrospect(IpcControlTestCase):
    """
    The out-of-process activity introspection integration tests.
    """

    def test__activity__reports_dhcp4_state_over_ipc(self) -> None:
        """
        Ensure a per-interface DHCPv4 FSM state is reported by the activity
        introspection API across the IPC boundary — the 'acquiring DHCP'
        indicator the daemon-status view renders.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._packet_handler._dhcp4_client = cast(Dhcp4Client, SimpleNamespace(state=Dhcp4State.SELECTING))

        activity = self._connect().activity.list_activity()

        match = [entry for entry in activity if entry.ifindex == self._ifindex]
        self.assertEqual(
            len(match),
            1,
            msg="The activity API must report exactly one entry for the interface.",
        )
        self.assertEqual(
            match[0].dhcp4_state,
            "SELECTING",
            msg="The DHCPv4 FSM state must cross the IPC boundary.",
        )
