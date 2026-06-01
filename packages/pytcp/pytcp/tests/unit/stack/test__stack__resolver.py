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
This module contains tests for the DNS resolution control API.

pytcp/tests/unit/stack/test__stack__resolver.py

ver 3.0.8
"""

from typing import override
from unittest import TestCase
from unittest.mock import create_autospec

from net_addr import Ip4Address, Ip6Address
from net_proto.protocols.dns.dns__enums import DnsRecordType
from pytcp.protocols.dns.dns__resolver import DnsResolver, DnsResolverError
from pytcp.runtime.socket import AddressFamily
from pytcp.stack.resolver import ResolverApi

_A_TABLE: dict[tuple[str, DnsRecordType], list[Ip4Address | Ip6Address]] = {
    ("example.com", DnsRecordType.A): [Ip4Address("93.184.216.34")],
    ("example.com", DnsRecordType.AAAA): [Ip6Address("2001:db8::1")],
    ("ipv6only.example", DnsRecordType.A): [],
    ("ipv6only.example", DnsRecordType.AAAA): [Ip6Address("2001:db8::2")],
}


class TestResolverApi(TestCase):
    """
    The DNS resolution control API tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a ResolverApi over an autospec'd resolver driven by a table.
        """

        self._resolver = create_autospec(DnsResolver, spec_set=True)
        self._resolver.resolve.side_effect = lambda host, record_type: _A_TABLE.get((host, record_type), [])
        self._api = ResolverApi(resolver=self._resolver)

    def test__resolver_api__resolve_ipv4_family(self) -> None:
        """
        Ensure resolving with the IPv4 family returns only the A-record
        addresses.

        Reference: RFC 1035 §3.4.1 (A resource record).
        """

        self.assertEqual(
            self._api.resolve(host="example.com", family=AddressFamily.INET4),
            (Ip4Address("93.184.216.34"),),
            msg="Resolving with the IPv4 family must return only the A address.",
        )

    def test__resolver_api__resolve_ipv6_family(self) -> None:
        """
        Ensure resolving with the IPv6 family returns only the AAAA-record
        addresses.

        Reference: RFC 3596 §2.1 (AAAA resource record).
        """

        self.assertEqual(
            self._api.resolve(host="example.com", family=AddressFamily.INET6),
            (Ip6Address("2001:db8::1"),),
            msg="Resolving with the IPv6 family must return only the AAAA address.",
        )

    def test__resolver_api__resolve_unspecified_family_returns_both(self) -> None:
        """
        Ensure resolving without a family returns both the A and AAAA
        addresses.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        self.assertEqual(
            self._api.resolve(host="example.com"),
            (Ip4Address("93.184.216.34"), Ip6Address("2001:db8::1")),
            msg="Resolving without a family must return both A and AAAA addresses.",
        )

    def test__resolver_api__resolve_nodata_family_falls_through(self) -> None:
        """
        Ensure a name with no A record but a present AAAA record still
        resolves to the AAAA address when no family is specified.

        Reference: RFC 3596 §2.1 (AAAA resource record).
        """

        self.assertEqual(
            self._api.resolve(host="ipv6only.example"),
            (Ip6Address("2001:db8::2"),),
            msg="A name with only an AAAA record must resolve to the AAAA address.",
        )

    def test__resolver_api__resolve_propagates_failure(self) -> None:
        """
        Ensure a lookup that fails for every queried family propagates the
        resolver error.

        Reference: RFC 1035 §4.1.1 (RCODE 3 — name error).
        """

        self._resolver.resolve.side_effect = DnsResolverError("nxdomain", name_error=True)

        with self.assertRaises(DnsResolverError):
            self._api.resolve(host="nonexistent.example")
