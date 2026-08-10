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
This module contains the client-side mirror of the socket introspection API.

'ClientSocketIntrospect' marshals the 'list_sockets' call across the IPC
control channel to the daemon's 'pytcp.stack.ss' API, returning the same
read-only 'SocketSnapshot' tuple (the Linux 'ss' surface). It backs
'ClientStack.ss'.

pytcp/client/client__socket_introspect.py

ver 3.0.9
"""

from typing import cast

from pytcp.client.client__base import _ClientApiProxy
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.stack.socket_introspect import SocketSnapshot


class ClientSocketIntrospect(_ClientApiProxy):
    """
    The client-side mirror of the socket introspection API.
    """

    _api_name = "socket_introspect"

    def list_sockets(
        self,
        *,
        family: AddressFamily | None = None,
        socket_type: SocketType | None = None,
        listening_only: bool = False,
    ) -> tuple[SocketSnapshot, ...]:
        """
        List the open sockets, optionally filtered by family / type /
        listening state — Linux 'ss'.
        """

        return cast(
            tuple[SocketSnapshot, ...],
            self._call(
                "list_sockets",
                {"family": family, "socket_type": socket_type, "listening_only": listening_only},
            ),
        )
