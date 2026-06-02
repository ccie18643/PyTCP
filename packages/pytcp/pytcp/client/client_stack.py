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
This module contains the 'ClientStack' — the client-side mirror of the
'pytcp.stack' control surface.

'ClientStack' owns one IPC control connection to the daemon and exposes
a per-plane proxy ('.sysctl', and — as later Phase-1 commits land —
'.route' / '.link' / '.address' / '.neighbor' / '.membership'). Each
proxy mirrors the in-process API's method signatures and marshals calls
across the boundary. 'connect()' is the entry point.

pytcp/client/client_stack.py

ver 3.0.8
"""

import time
from types import TracebackType
from typing import Self

from net_proto.lib.enums import EtherType, IpProto
from pytcp.client.client__activity_introspect import ClientActivityIntrospect
from pytcp.client.client__address import ClientAddress
from pytcp.client.client__datagram_socket import ClientRawSocket, ClientUdpSocket
from pytcp.client.client__link import ClientLink
from pytcp.client.client__membership import ClientMembership
from pytcp.client.client__neighbor import ClientNeighbor
from pytcp.client.client__packet_socket import ClientPacketSocket
from pytcp.client.client__resolver import ClientResolver
from pytcp.client.client__route import ClientRoute
from pytcp.client.client__socket_introspect import ClientSocketIntrospect
from pytcp.client.client__sysctl import ClientSysctl
from pytcp.client.client__tcp_socket import ClientTcpSocket
from pytcp.ipc.ipc__client import IpcClient
from pytcp.ipc.ipc__errors import IpcConnectionError
from pytcp.runtime.socket import ETH_P_ALL, AddressFamily, SocketType

IPC__CLIENT__READINESS_POLL__SEC: float = 0.05


class ClientStack:
    """
    The client-side mirror of the 'pytcp.stack' control surface.
    """

    def __init__(self, *, socket_path: str) -> None:
        """
        Open an IPC control connection and build the per-plane proxies.
        """

        self._client = IpcClient(socket_path=socket_path)
        self.sysctl = ClientSysctl(self._client)
        self.route = ClientRoute(self._client)
        self.link = ClientLink(self._client)
        self.address = ClientAddress(self._client)
        self.neighbor = ClientNeighbor(self._client)
        self.membership = ClientMembership(self._client)
        self.resolver = ClientResolver(self._client)
        self.ss = ClientSocketIntrospect(self._client)
        self.activity = ClientActivityIntrospect(self._client)

    def socket(
        self,
        family: AddressFamily = AddressFamily.INET4,
        type: SocketType = SocketType.STREAM,
        protocol: IpProto | EtherType | int | None = None,
    ) -> ClientTcpSocket | ClientUdpSocket | ClientRawSocket | ClientPacketSocket:
        """
        Open a socket on the daemon, returning a client shim whose data
        path is a real selectable descriptor. Mirrors the in-process
        'socket()' factory's family / type / protocol arguments: STREAM
        yields a 'ClientTcpSocket', DGRAM a 'ClientUdpSocket', RAW on an
        INET family a 'ClientRawSocket' (with an IANA next-header
        'protocol'), and RAW on the PACKET family a 'ClientPacketSocket'
        (with an ethertype filter, default capture-all).
        """

        match type:
            case SocketType.STREAM:
                return ClientTcpSocket(self._client, family=family)
            case SocketType.DGRAM:
                return ClientUdpSocket(self._client, family=family)
            case SocketType.RAW:
                if family is AddressFamily.PACKET:
                    if isinstance(protocol, IpProto):
                        raise ValueError("An AF_PACKET socket takes an ethertype, not an IpProto.")
                    return ClientPacketSocket(
                        self._client,
                        protocol=ETH_P_ALL if protocol is None else protocol,
                    )
                if not isinstance(protocol, IpProto):
                    raise ValueError("A raw IP socket requires an explicit IpProto next-header protocol.")
                return ClientRawSocket(self._client, family=family, protocol=protocol)

        raise ValueError(f"Unsupported socket type {type!r}.")

    def close(self) -> None:
        """
        Close the control connection to the daemon.
        """

        self._client.close()

    def __enter__(self) -> Self:
        """
        Enter the client-stack context, returning the connected stack.
        """

        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """
        Close the control connection on context exit.
        """

        self.close()


def connect(*, socket_path: str) -> ClientStack:
    """
    Connect to a PyTCP daemon and return a 'ClientStack' mirror.
    """

    return ClientStack(socket_path=socket_path)


def wait_for_daemon(*, socket_path: str, timeout: float = 5.0) -> None:
    """
    Block until the daemon's control socket accepts a connection, so a
    client that races the daemon's startup can wait for readiness before
    'connect()'. Raises 'IpcConnectionError' if the daemon does not become
    ready within 'timeout' seconds.
    """

    deadline = time.monotonic() + timeout
    while True:
        try:
            IpcClient(socket_path=socket_path).close()
            return
        except OSError:
            if time.monotonic() >= deadline:
                raise IpcConnectionError(
                    f"PyTCP daemon did not become ready on {socket_path!r} within {timeout}s.",
                ) from None
            time.sleep(IPC__CLIENT__READINESS_POLL__SEC)
