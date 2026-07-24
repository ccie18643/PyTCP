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
This module contains the client-side mirror of the link control API.

'ClientLink' marshals each link operation across the IPC control channel
to the daemon's 'pytcp.stack.link' API, mirroring its 'interface(ifindex)'
selector, its methods, and its per-interface read properties (carried as
zero-argument reads over the RPC).

pytcp/client/client__link.py

ver 3.0.9
"""

from typing import cast

from net_addr import MacAddress
from pytcp.client.client__base import _DeviceScopedProxy
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.stack.link import LinkFlag, LinkStats


class ClientLink(_DeviceScopedProxy):
    """
    The client-side mirror of the link control API.
    """

    _api_name = "link"

    def list_interfaces(self) -> tuple[int, ...]:
        """
        List the ifindexes of every registered interface.
        """

        return cast(tuple[int, ...], self._call("list_interfaces", {}))

    def set_mtu(self, *, mtu: int) -> None:
        """
        Set the bound interface's MTU.
        """

        self._call("set_mtu", {"mtu": mtu})

    def set_mac_address(self, *, mac_address: MacAddress) -> None:
        """
        Set the bound interface's MAC address.
        """

        self._call("set_mac_address", {"mac_address": mac_address})

    @property
    def mac_address(self) -> MacAddress | None:
        """
        Get the bound interface's MAC address.
        """

        return cast(MacAddress | None, self._call("mac_address", {}))

    @property
    def mtu(self) -> int:
        """
        Get the bound interface's MTU.
        """

        return cast(int, self._call("mtu", {}))

    @property
    def name(self) -> str | None:
        """
        Get the bound interface's name.
        """

        return cast(str | None, self._call("name", {}))

    @property
    def interface_layer(self) -> InterfaceLayer:
        """
        Get the bound interface's layer (L2 / L3).
        """

        return cast(InterfaceLayer, self._call("interface_layer", {}))

    @property
    def is_running(self) -> bool:
        """
        Get whether the bound interface is running.
        """

        return cast(bool, self._call("is_running", {}))

    @property
    def stats(self) -> LinkStats:
        """
        Get the bound interface's counter snapshot.
        """

        return cast(LinkStats, self._call("stats", {}))

    @property
    def flags(self) -> frozenset[LinkFlag]:
        """
        Get the bound interface's flags.
        """

        return cast(frozenset[LinkFlag], self._call("flags", {}))
