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
This module contains the DNS resolution control API.

'ResolverApi' is the stack's name-resolution control surface — the Linux
'getaddrinfo' analogue. It delegates to the daemon-side 'DnsResolver',
exposing a single 'resolve' method that turns a host name into a tuple of
resolved 'Ip4Address' / 'Ip6Address' values, optionally restricted to one
address family. It is reached out-of-process through the 'resolver'
control API (the client-facing stdlib 'getaddrinfo' / 'gethostbyname'
shims marshal to it over IPC).

pytcp/stack/resolver.py

ver 3.0.9
"""

from net_addr import Ip4Address, Ip6Address
from net_proto.protocols.dns.dns__enums import DnsRecordType
from pytcp.protocols.dns.dns__resolver import DnsResolver, DnsResolverError
from pytcp.runtime.socket import AddressFamily


class ResolverApi:
    """
    The DNS resolution control API (the Linux getaddrinfo analogue).
    """

    def __init__(self, *, resolver: DnsResolver) -> None:
        """
        Bind the control API to a configured DNS resolver.
        """

        self._resolver = resolver

    def resolve(
        self,
        *,
        host: str,
        family: AddressFamily | None = None,
    ) -> tuple[Ip4Address | Ip6Address, ...]:
        """
        Resolve 'host' to addresses, optionally restricted to a family.

        With 'family' unset both A and AAAA records are queried; a name
        that resolves under either family succeeds, and the lookup fails
        only when no family yields an address.
        """

        addresses: list[Ip4Address | Ip6Address] = []
        errors: list[DnsResolverError] = []

        for record_family, record_type in (
            (AddressFamily.INET4, DnsRecordType.A),
            (AddressFamily.INET6, DnsRecordType.AAAA),
        ):
            if family in (None, record_family):
                try:
                    addresses.extend(self._resolver.resolve(host, record_type))
                except DnsResolverError as error:
                    errors.append(error)

        if not addresses and errors:
            raise errors[0]

        return tuple(addresses)

    def get_dns_server(self) -> Ip4Address | Ip6Address:
        """
        Return the resolver's configured upstream DNS server address.
        """

        return self._resolver.server
