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
Integration tests for the out-of-process resolver control API.

These drive 'ClientStack.resolver' over a live IPC server against a
daemon-side 'stack.resolver' whose underlying 'DnsResolver' is replaced
with an autospec'd fake, so name resolution is exercised end to end
(control RPC + 'ResolverApi') without a live upstream.

pytcp/tests/integration/ipc/test__ipc__control__resolver.py

ver 3.0.9
"""

from typing import override
from unittest.mock import create_autospec

from net_addr import Ip4Address, Ip6Address
from net_proto.protocols.dns.dns__enums import DnsRecordType
from pytcp import stack
from pytcp.protocols.dns.dns__resolver import DnsResolver
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.stack.resolver import ResolverApi
from pytcp.tests.lib.ipc_control_testcase import IpcControlTestCase

_TABLE: dict[tuple[str, DnsRecordType], list[Ip4Address | Ip6Address]] = {
    ("example.com", DnsRecordType.A): [Ip4Address("93.184.216.34")],
    ("example.com", DnsRecordType.AAAA): [Ip6Address("2001:db8::1")],
}


class TestIpcControlResolver(IpcControlTestCase):
    """
    The out-of-process resolver control-API integration tests.
    """

    @override
    def setUp(self) -> None:
        """
        Replace the daemon's resolver with a table-driven fake so lookups
        resolve without a live upstream.
        """

        super().setUp()

        resolver = create_autospec(DnsResolver, spec_set=True)
        resolver.resolve.side_effect = lambda host, record_type: _TABLE.get((host, record_type), [])
        resolver.server = Ip4Address("9.9.9.9")
        stack.resolver = ResolverApi(resolver=resolver)

    def test__control_resolver__get_dns_server_returns_configured_server(self) -> None:
        """
        Ensure a 'get_dns_server' call over the control channel returns
        the daemon's configured upstream DNS server address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()

        self.assertEqual(
            client.resolver.get_dns_server(),
            Ip4Address("9.9.9.9"),
            msg="get_dns_server() over IPC must return the daemon's configured DNS server.",
        )

    def test__control_resolver__resolve_returns_addresses(self) -> None:
        """
        Ensure a 'resolve' call over the control channel returns the
        daemon-resolved addresses for the requested family.

        Reference: RFC 1035 §3.4.1 (A resource record).
        """

        client = self._connect()

        self.assertEqual(
            client.resolver.resolve(host="example.com", family=AddressFamily.INET4),
            (Ip4Address("93.184.216.34"),),
            msg="resolve() over IPC must return the daemon-resolved IPv4 address.",
        )

    def test__control_resolver__gethostbyname_returns_first_ipv4(self) -> None:
        """
        Ensure 'gethostbyname' over the control channel returns the first
        IPv4 address as a string.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        client = self._connect()

        self.assertEqual(
            client.resolver.gethostbyname("example.com"),
            "93.184.216.34",
            msg="gethostbyname() over IPC must return the first IPv4 address string.",
        )

    def test__control_resolver__getaddrinfo_returns_5_tuples(self) -> None:
        """
        Ensure 'getaddrinfo' over the control channel returns the
        stdlib-shaped 5-tuple for a resolved name.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        client = self._connect()

        self.assertEqual(
            client.resolver.getaddrinfo(
                "example.com",
                80,
                family=int(AddressFamily.INET4),
                type=int(SocketType.STREAM),
            ),
            [(AddressFamily.INET4, SocketType.STREAM, 0, "", ("93.184.216.34", 80))],
            msg="getaddrinfo() over IPC must return the stdlib-shaped 5-tuple.",
        )

    def test__control_resolver__getaddrinfo_ip_literal_bypasses_daemon(self) -> None:
        """
        Ensure an IP-literal host resolves locally without a daemon query,
        producing the 5-tuple directly.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()

        self.assertEqual(
            client.resolver.getaddrinfo("10.0.1.7", 53),
            [(AddressFamily.INET4, SocketType.STREAM, 0, "", ("10.0.1.7", 53))],
            msg="An IP-literal host must resolve locally without a daemon query.",
        )
