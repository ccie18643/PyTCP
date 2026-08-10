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
This module contains the client-side mirror of the route control API.

'ClientRoute' marshals each routing operation across the IPC control
channel to the daemon's 'pytcp.stack.route' API, mirroring its method
signatures. Routing is global (no interface scope), matching the
in-process 'RouteApi'.

pytcp/client/client__route.py

ver 3.0.9
"""

from typing import cast

from net_addr import Ip4Address, Ip4Network, Ip6Address, Ip6Network
from pytcp.client.client__base import _ClientApiProxy
from pytcp.runtime.fib import Route, RouteProtocol
from pytcp.runtime.socket import AddressFamily

type _AnyRoute = Route[Ip4Address, Ip4Network] | Route[Ip6Address, Ip6Network]


class ClientRoute(_ClientApiProxy):
    """
    The client-side mirror of the route control API.
    """

    _api_name = "route"

    def list_routes(self, *, family: AddressFamily | None = None) -> tuple[_AnyRoute, ...]:
        """
        List the installed routes, optionally filtered by address family.
        """

        return cast(tuple[_AnyRoute, ...], self._call("list_routes", {"family": family}))

    def add_route(self, *, route: _AnyRoute) -> None:
        """
        Install a route.
        """

        self._call("add_route", {"route": route})

    def remove_route(
        self,
        *,
        destination: Ip4Network | Ip6Network,
        gateway: Ip4Address | Ip6Address | None = None,
    ) -> int:
        """
        Remove the routes matching 'destination' (and optional gateway).
        """

        return cast(int, self._call("remove_route", {"destination": destination, "gateway": gateway}))

    def replace_default(
        self,
        *,
        gateway: Ip4Address | Ip6Address,
        protocol: RouteProtocol,
        oif: int | None = None,
    ) -> None:
        """
        Replace the default route for the gateway's address family.
        'oif' is the egress interface index the gateway is reachable
        on (rendered as the default's 'dev'); 'None' leaves it unset.
        """

        self._call("replace_default", {"gateway": gateway, "protocol": protocol, "oif": oif})

    def remove_default(self, *, family: AddressFamily) -> int:
        """
        Remove the default route for 'family'.
        """

        return cast(int, self._call("remove_default", {"family": family}))
