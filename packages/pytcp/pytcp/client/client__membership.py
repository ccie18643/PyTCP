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
This module contains the client-side mirror of the membership control API.

'ClientMembership' marshals each multicast-membership operation across the
IPC control channel to the daemon's 'pytcp.stack.membership' API,
mirroring its 'interface(ifindex)' selector and its join / leave / list
methods. The in-process 'set_socket_filter' / 'clear_socket_filter'
methods are daemon-internal socket plumbing (token-keyed, carrying an
'Ip4MulticastFilter') and are deliberately not mirrored.

pytcp/client/client__membership.py

ver 3.0.8
"""

from typing import cast

from net_addr import Ip4Address
from pytcp.client.client__base import _DeviceScopedProxy


class ClientMembership(_DeviceScopedProxy):
    """
    The client-side mirror of the membership control API.
    """

    _api_name = "membership"

    def join(self, *, group: Ip4Address) -> None:
        """
        Join the IPv4 multicast group 'group' on the bound interface.
        """

        self._call("join", {"group": group})

    def leave(self, *, group: Ip4Address) -> None:
        """
        Leave the IPv4 multicast group 'group' on the bound interface.
        """

        self._call("leave", {"group": group})

    def list_memberships(self) -> tuple[Ip4Address, ...]:
        """
        List the bound interface's IPv4 multicast group memberships.
        """

        return cast(tuple[Ip4Address, ...], self._call("list_memberships", {}))
