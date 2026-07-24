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
This module contains the shared base classes for the client API proxies.

'_ClientApiProxy' binds a proxy to an IPC client and an optional interface
scope, and provides '_call' — the one-line bridge from a mirrored method
to a control-plane RPC. '_DeviceScopedProxy' adds the 'interface(ifindex)'
chaining the device-scoped control APIs use, returning a fresh proxy of
the same flavour carrying the selected scope.

pytcp/client/client__base.py

ver 3.0.8
"""

from typing import Any, Self

from pytcp.ipc.ipc__client import IpcClient
from pytcp.ipc.ipc__rpc import control_call


class _ClientApiProxy:
    """
    The base for a client-side control-API proxy.
    """

    _api_name: str

    def __init__(self, client: IpcClient, ifindex: int | None = None, /) -> None:
        """
        Bind the proxy to an IPC client and an optional interface scope.
        """

        self._client = client
        self._ifindex = ifindex

    def _call(self, method: str, args: dict[str, Any], /) -> Any:
        """
        Issue a control-plane call for one of this API's methods.
        """

        return control_call(
            self._client,
            api=self._api_name,
            method=method,
            ifindex=self._ifindex,
            args=args,
        )


class _DeviceScopedProxy(_ClientApiProxy):
    """
    The base for a device-scoped client-side control-API proxy.
    """

    def interface(self, ifindex: int, /) -> Self:
        """
        Return a proxy bound to the interface registered under 'ifindex'.
        """

        return type(self)(self._client, ifindex)
