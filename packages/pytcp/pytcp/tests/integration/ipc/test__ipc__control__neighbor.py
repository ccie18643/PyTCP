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
Integration tests for the out-of-process neighbor control mirror.

'NetworkTestCase' mocks the ARP / ND caches (for RX/TX testing), so this
fixture swaps real caches onto the boot interface — the neighbor control
API reads and writes them, and the mocks have no real entry store.

pytcp/tests/integration/ipc/test__ipc__control__neighbor.py

ver 3.0.10
"""

from typing import override

from net_addr import Ip4Address, MacAddress
from pytcp import stack
from pytcp.lib.neighbor import NudState
from pytcp.protocols.arp.arp__cache import ArpCache
from pytcp.protocols.icmp6.nd.nd__cache import NdCache
from pytcp.runtime.socket import AddressFamily
from pytcp.stack.neighbor import NeighborSnapshot
from pytcp.tests.lib.ipc_control_testcase import IpcControlTestCase

_IP: Ip4Address = Ip4Address("10.0.1.55")
_MAC: MacAddress = MacAddress("02:00:00:00:00:55")


class TestIpcControlNeighbor(IpcControlTestCase):
    """
    The out-of-process neighbor control-mirror tests.
    """

    @override
    def setUp(self) -> None:
        """
        Stand up the IPC fixture, then replace the harness's mocked ARP /
        ND caches on the boot interface with real (unstarted) caches so
        the neighbor control API has a real entry store to read and
        mutate.
        """

        super().setUp()

        self._packet_handler._arp_cache = ArpCache()
        self._packet_handler._nd_cache = NdCache()

    def test__ipc__control__neighbor_list_starts_empty_matching_in_process(self) -> None:
        """
        Ensure an out-of-process list_neighbors on a fresh cache returns
        the same (empty) result the in-process API reports.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()

        self.assertEqual(
            client.neighbor.interface(self._ifindex).list_neighbors(),
            stack.neighbor.interface(self._ifindex).list_neighbors(),
            msg="A client list_neighbors must match the in-process (empty) cache.",
        )

    def test__ipc__control__neighbor_add_reflected_in_process(self) -> None:
        """
        Ensure an out-of-process add installs a permanent entry in the
        real daemon cache, visible as a NeighborSnapshot to a subsequent
        in-process list — exercising the snapshot round-trip and the
        typed (ip, mac) arguments across the boundary.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()

        client.neighbor.interface(self._ifindex).add(ip=_IP, mac=_MAC)

        self.assertIn(
            NeighborSnapshot(address=_IP, mac_address=_MAC, state=NudState.PERMANENT),
            stack.neighbor.interface(self._ifindex).list_neighbors(family=AddressFamily.INET4),
            msg="A client neighbor add must install a permanent entry in the daemon cache.",
        )
