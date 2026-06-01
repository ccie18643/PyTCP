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
Integration tests for the out-of-process membership control mirror.

pytcp/tests/integration/ipc/test__ipc__control__membership.py

ver 3.0.8
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.tests.lib.ipc_control_testcase import IpcControlTestCase

_GROUP: Ip4Address = Ip4Address("239.1.2.3")


class TestIpcControlMembership(IpcControlTestCase):
    """
    The out-of-process membership control-mirror tests.
    """

    def test__ipc__control__membership_list_matches_in_process(self) -> None:
        """
        Ensure an out-of-process list_memberships returns the same group
        set the in-process API reports.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()

        self.assertEqual(
            client.membership.interface(self._ifindex).list_memberships(),
            stack.membership.interface(self._ifindex).list_memberships(),
            msg="A client list_memberships must match the in-process group set.",
        )

    def test__ipc__control__membership_join_reflected_in_process(self) -> None:
        """
        Ensure an out-of-process join adds the operator hold on the real
        daemon interface, visible to a subsequent in-process membership
        list.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()

        client.membership.interface(self._ifindex).join(group=_GROUP)

        self.assertIn(
            _GROUP,
            stack.membership.interface(self._ifindex).list_memberships(),
            msg="A client join must add the group to the daemon interface.",
        )

    def test__ipc__control__membership_leave_reflected_in_process(self) -> None:
        """
        Ensure an out-of-process leave drops the operator hold on the
        real daemon interface, removing the group from a subsequent
        in-process membership list.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()
        client.membership.interface(self._ifindex).join(group=_GROUP)

        client.membership.interface(self._ifindex).leave(group=_GROUP)

        self.assertNotIn(
            _GROUP,
            stack.membership.interface(self._ifindex).list_memberships(),
            msg="A client leave must drop the group from the daemon interface.",
        )
