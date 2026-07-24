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
This module contains the client-side mirror of the address control API.

'ClientAddress' marshals each address operation across the IPC control
channel to the daemon's 'pytcp.stack.address' API. The in-process 'add'
accepts an optional 'dad_conflict_callback' — an in-process callback that
cannot cross the boundary — so the mirror omits it; the daemon performs
the add with the callback defaulted to None.

pytcp/client/client__address.py

ver 3.0.8
"""

from typing import cast

from net_addr import Ip4Address, Ip4IfAddr, Ip6Address, Ip6IfAddr
from pytcp.client.client__base import _DeviceScopedProxy
from pytcp.runtime.socket import AddressFamily

type _AnyIfAddr = Ip4IfAddr | Ip6IfAddr


class ClientAddress(_DeviceScopedProxy):
    """
    The client-side mirror of the address control API.
    """

    _api_name = "address"

    def add(self, *, ifaddr: _AnyIfAddr, dad: bool = True) -> None:
        """
        Assign an interface address to the bound interface. An IPv6
        address is run through Duplicate Address Detection before it is
        installed (RFC 4862 §5.4); pass 'dad=False' to install directly.
        Ignored for IPv4.
        """

        self._call("add", {"ifaddr": ifaddr, "dad": dad})

    def remove(self, *, address: Ip4Address | Ip6Address, abort_bound_sessions: bool = True) -> None:
        """
        Remove the interface address whose host part is 'address'.
        """

        self._call("remove", {"address": address, "abort_bound_sessions": abort_bound_sessions})

    def replace(
        self,
        *,
        old_address: Ip4Address | Ip6Address,
        new_ifaddr: _AnyIfAddr,
        abort_bound_sessions: bool = True,
    ) -> None:
        """
        Replace the interface address whose host part is 'old_address'.
        """

        self._call(
            "replace",
            {
                "old_address": old_address,
                "new_ifaddr": new_ifaddr,
                "abort_bound_sessions": abort_bound_sessions,
            },
        )

    def list_ifaddrs(self, *, family: AddressFamily | None = None) -> tuple[_AnyIfAddr, ...]:
        """
        List the bound interface's interface addresses.
        """

        return cast(tuple[_AnyIfAddr, ...], self._call("list_ifaddrs", {"family": family}))
