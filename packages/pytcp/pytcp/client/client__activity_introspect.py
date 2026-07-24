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
This module contains the client-side mirror of the activity introspection API.

'ClientActivityIntrospect' marshals the 'list_activity' call across the
IPC control channel to the daemon's 'pytcp.stack.activity' API, returning
the same read-only 'InterfaceActivity' tuple (per-interface DHCPv4 state +
DAD-in-progress IPv6 addresses). It backs 'ClientStack.activity'.

pytcp/client/client__activity_introspect.py

ver 3.0.8
"""

from typing import cast

from pytcp.client.client__base import _ClientApiProxy
from pytcp.stack.activity_introspect import InterfaceActivity


class ClientActivityIntrospect(_ClientApiProxy):
    """
    The client-side mirror of the activity introspection API.
    """

    _api_name = "activity_introspect"

    def list_activity(self) -> tuple[InterfaceActivity, ...]:
        """
        List each interface's ongoing autoconfig activity (DHCPv4 state,
        DAD-in-progress IPv6 addresses).
        """

        return cast(tuple[InterfaceActivity, ...], self._call("list_activity", {}))
