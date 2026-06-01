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
This module contains the client-side mirror of the neighbor control API.

'ClientNeighbor' marshals each neighbour operation across the IPC control
channel to the daemon's 'pytcp.stack.neighbor' API, mirroring its
'interface(ifindex)' selector and its add / remove / flush / list methods.

pytcp/client/client__neighbor.py

ver 3.0.8
"""

from typing import cast

from net_addr import Ip4Address, Ip6Address, MacAddress
from pytcp.client.client__base import _DeviceScopedProxy
from pytcp.runtime.socket import AddressFamily
from pytcp.stack.neighbor import NeighborSnapshot


class ClientNeighbor(_DeviceScopedProxy):
    """
    The client-side mirror of the neighbor control API.
    """

    _api_name = "neighbor"

    def add(self, *, ip: Ip4Address | Ip6Address, mac: MacAddress) -> None:
        """
        Install a permanent neighbour entry mapping 'ip' to 'mac'.
        """

        self._call("add", {"ip": ip, "mac": mac})

    def remove(self, *, ip: Ip4Address | Ip6Address) -> None:
        """
        Remove the neighbour entry for 'ip'.
        """

        self._call("remove", {"ip": ip})

    def flush(self, *, family: AddressFamily) -> None:
        """
        Flush the bound interface's neighbour cache for 'family'.
        """

        self._call("flush", {"family": family})

    def list_neighbors(self, *, family: AddressFamily | None = None) -> tuple[NeighborSnapshot, ...]:
        """
        List the bound interface's neighbour-cache entries.
        """

        return cast(tuple[NeighborSnapshot, ...], self._call("list_neighbors", {"family": family}))
