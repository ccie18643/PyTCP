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
This module contains the client-side mirror of the resolver control API.

'ClientResolver' marshals name resolution across the IPC control channel
to the daemon's 'pytcp.stack.resolver' API and shapes the result into the
stdlib name-resolution surface: 'resolve' returns the raw address tuple,
while 'gethostbyname' / 'getaddrinfo' present the Berkeley forms (an IPv4
string and a list of 5-tuples), with an IP-literal fast path and faithful
'socket.gaierror' on failure. The 'pytcp.socket' drop-in re-exports these
as 'socket.gethostbyname' / 'socket.getaddrinfo'.

pytcp/client/client__resolver.py

ver 3.0.9
"""

from typing import cast

from net_addr import Ip4Address, Ip6Address, NetAddrError
from pytcp.client.client__base import _ClientApiProxy
from pytcp.ipc.ipc__errors import IpcRemoteError
from pytcp.runtime.socket import AddressFamily, SocketType, gaierror

type _AnyAddress = Ip4Address | Ip6Address
type _SockAddr = tuple[str, int] | tuple[str, int, int, int]
type _AddrInfo = tuple[AddressFamily, SocketType, int, str, _SockAddr]


def _parse_literal(host: str, /) -> _AnyAddress | None:
    """
    Return the address if 'host' is an IPv4 / IPv6 literal, else None.
    """

    for address_type in (Ip4Address, Ip6Address):
        try:
            return address_type(host)
        except NetAddrError:
            continue
    return None


class ClientResolver(_ClientApiProxy):
    """
    The client-side mirror of the resolver control API.
    """

    _api_name = "resolver"

    def resolve(self, *, host: str, family: AddressFamily | None = None) -> tuple[_AnyAddress, ...]:
        """
        Resolve 'host' to addresses, optionally restricted to a family.
        """

        return cast(tuple[_AnyAddress, ...], self._call("resolve", {"host": host, "family": family}))

    def get_dns_server(self) -> _AnyAddress:
        """
        Get the daemon's configured upstream DNS server address.
        """

        return cast(_AnyAddress, self._call("get_dns_server", {}))

    def gethostbyname(self, hostname: str, /) -> str:
        """
        Resolve 'hostname' to its first IPv4 address, mirroring stdlib
        'socket.gethostbyname'.
        """

        if (literal := _parse_literal(hostname)) is not None and isinstance(literal, Ip4Address):
            return str(literal)

        try:
            addresses = self.resolve(host=hostname, family=AddressFamily.INET4)
        except IpcRemoteError as error:
            raise gaierror(f"Name resolution failed for {hostname!r}: {error}") from error

        if not addresses:
            raise gaierror(f"No IPv4 address found for {hostname!r}.")
        return str(addresses[0])

    def getaddrinfo(
        self,
        host: str,
        port: int | None = None,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[_AddrInfo]:
        """
        Resolve 'host' / 'port' into stdlib-shaped address-info 5-tuples,
        mirroring 'socket.getaddrinfo' (numeric ports only; an IP-literal
        host bypasses the daemon resolver).
        """

        _ = flags
        want_family = AddressFamily(family) if family else None
        resolved_port = port if port is not None else 0
        socket_type = SocketType(type) if type else SocketType.STREAM

        if (literal := _parse_literal(host)) is not None:
            addresses: tuple[_AnyAddress, ...] = (literal,)
            if want_family is not None and _family_of(literal) is not want_family:
                addresses = ()
        else:
            try:
                addresses = self.resolve(host=host, family=want_family)
            except IpcRemoteError as error:
                raise gaierror(f"Name resolution failed for {host!r}: {error}") from error

        if not addresses:
            raise gaierror(f"No address found for {host!r}.")

        return [
            (
                _family_of(address),
                socket_type,
                proto,
                "",
                _sockaddr(address, resolved_port),
            )
            for address in addresses
        ]


def _family_of(address: _AnyAddress, /) -> AddressFamily:
    """
    Return the address family of an IPv4 / IPv6 address.
    """

    return AddressFamily.INET4 if isinstance(address, Ip4Address) else AddressFamily.INET6


def _sockaddr(address: _AnyAddress, port: int, /) -> _SockAddr:
    """
    Build the stdlib socket-address tuple for an address (a 2-tuple for
    IPv4, a 4-tuple for IPv6).
    """

    if isinstance(address, Ip4Address):
        return (str(address), port)
    return (str(address), port, 0, 0)
