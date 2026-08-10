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
This module contains tests for the daemon-side DNS stub resolver.

pytcp/tests/unit/protocols/dns/test__dns__resolver.py

ver 3.0.9
"""

from typing import override
from unittest import TestCase
from unittest.mock import patch

from net_addr import Ip4Address
from net_proto.protocols.dns.dns__enums import (
    DnsOpcode,
    DnsRecordClass,
    DnsRecordType,
    DnsResponseCode,
)
from net_proto.protocols.dns.dns__header import DnsHeader
from net_proto.protocols.dns.dns__question import DnsQuestion
from net_proto.protocols.dns.dns__resource_record import DnsResourceRecord
from pytcp.protocols.dns.dns__resolver import DnsResolver, DnsResolverError
from pytcp.runtime.socket import AddressFamily

_SERVER = Ip4Address("10.0.1.1")
_QUERY_ID = 0x1234


def _build_response(
    *,
    response_id: int,
    addresses: tuple[Ip4Address, ...],
    qname: str = "example.com",
    rcode: DnsResponseCode = DnsResponseCode.NOERROR,
    ttl: int = 300,
) -> bytes:
    """
    Build an uncompressed A-record response frame for the resolver tests.
    """

    header = DnsHeader(
        id=response_id,
        qr=True,
        opcode=DnsOpcode.QUERY,
        aa=False,
        tc=False,
        rd=True,
        ra=True,
        z=0,
        rcode=rcode,
        qdcount=1,
        ancount=len(addresses),
        nscount=0,
        arcount=0,
    )
    frame = bytearray(header)
    frame += bytearray(DnsQuestion(qname=qname, qtype=DnsRecordType.A, qclass=DnsRecordClass.IN))
    for address in addresses:
        frame += bytearray(
            DnsResourceRecord(
                name=qname,
                rtype=DnsRecordType.A,
                rclass=DnsRecordClass.IN,
                ttl=ttl,
                rdata=bytes(address),
            )
        )
    return bytes(frame)


class _FakeResolverSocket:
    """
    A state-driven datagram-socket double yielding one queued reply.
    """

    def __init__(self, reply: bytes | type[BaseException], /) -> None:
        """
        Hold the single reply (bytes to return, or an exception to raise).
        """

        self._reply = reply
        self.sent: list[tuple[bytes, tuple[str, int]]] = []
        self.closed = False

    def sendto(self, data: bytes, address: tuple[str, int], /) -> int:
        """
        Record the sent query and report it fully sent.
        """

        self.sent.append((data, address))
        return len(data)

    def recvfrom(self, bufsize: int, timeout: float, /) -> tuple[bytes, tuple[str, int]]:
        """
        Return the queued reply, or raise the queued exception.
        """

        _ = timeout
        if isinstance(self._reply, type):
            raise self._reply()
        return self._reply[:bufsize], (str(_SERVER), 53)

    def close(self) -> None:
        """
        Mark the socket closed.
        """

        self.closed = True


class _FakeSocketFactory:
    """
    A resolver socket factory dispensing one fake socket per query attempt.
    """

    def __init__(self, *replies: bytes | type[BaseException]) -> None:
        """
        Queue one reply per expected query attempt.
        """

        self._replies = list(replies)
        self.sockets: list[_FakeResolverSocket] = []

    def __call__(self, family: AddressFamily, /) -> _FakeResolverSocket:
        """
        Build the next fake socket for a query attempt.
        """

        _ = family
        sock = _FakeResolverSocket(self._replies.pop(0))
        self.sockets.append(sock)
        return sock


class TestDnsResolver(TestCase):
    """
    The daemon-side DNS stub resolver tests.
    """

    @override
    def setUp(self) -> None:
        """
        Pin the transaction id so crafted replies match the query.
        """

        self._id_source = lambda: _QUERY_ID

    def test__dns__resolver__resolves_a_addresses(self) -> None:
        """
        Ensure a successful A response is parsed into the resolved IPv4
        address list.

        Reference: RFC 1035 §4.1.1 (Header section format).
        """

        factory = _FakeSocketFactory(_build_response(response_id=_QUERY_ID, addresses=(Ip4Address("93.184.216.34"),)))
        resolver = DnsResolver(server=_SERVER, socket_factory=factory, id_source=self._id_source)

        self.assertEqual(
            resolver.resolve("example.com", DnsRecordType.A),
            [Ip4Address("93.184.216.34")],
            msg="The resolver must return the IPv4 address from a successful A response.",
        )

    def test__dns__resolver__caches_within_ttl(self) -> None:
        """
        Ensure a second lookup within the TTL is served from cache without
        a second query.

        Reference: RFC 1035 §3.2.1 (TTL — caching duration).
        """

        factory = _FakeSocketFactory(_build_response(response_id=_QUERY_ID, addresses=(Ip4Address("1.2.3.4"),)))
        resolver = DnsResolver(server=_SERVER, socket_factory=factory, id_source=self._id_source)

        resolver.resolve("example.com", DnsRecordType.A)
        resolver.resolve("example.com", DnsRecordType.A)

        self.assertEqual(
            len(factory.sockets),
            1,
            msg="A cached lookup within the TTL must not issue a second query.",
        )

    def test__dns__resolver__requeries_after_ttl_expiry(self) -> None:
        """
        Ensure a lookup after the cached entry's TTL has elapsed issues a
        fresh query.

        Reference: RFC 1035 §3.2.1 (TTL — caching duration).
        """

        factory = _FakeSocketFactory(
            _build_response(response_id=_QUERY_ID, addresses=(Ip4Address("1.2.3.4"),), ttl=300),
            _build_response(response_id=_QUERY_ID, addresses=(Ip4Address("5.6.7.8"),), ttl=300),
        )
        resolver = DnsResolver(server=_SERVER, socket_factory=factory, id_source=self._id_source)

        clock = {"now": 0.0}
        with patch("pytcp.protocols.dns.dns__resolver.time.monotonic", side_effect=lambda: clock["now"]):
            resolver.resolve("example.com", DnsRecordType.A)
            clock["now"] = 301.0
            second = resolver.resolve("example.com", DnsRecordType.A)

        self.assertEqual(
            (len(factory.sockets), second),
            (2, [Ip4Address("5.6.7.8")]),
            msg="A lookup after TTL expiry must re-query and return the fresh address.",
        )

    def test__dns__resolver__retries_on_id_mismatch(self) -> None:
        """
        Ensure a response whose transaction id does not match the query is
        ignored and the query retried.

        Reference: RFC 5452 §9 (Query id matching).
        """

        factory = _FakeSocketFactory(
            _build_response(response_id=0x9999, addresses=(Ip4Address("9.9.9.9"),)),
            _build_response(response_id=_QUERY_ID, addresses=(Ip4Address("1.2.3.4"),)),
        )
        resolver = DnsResolver(server=_SERVER, socket_factory=factory, id_source=self._id_source)

        self.assertEqual(
            resolver.resolve("example.com", DnsRecordType.A),
            [Ip4Address("1.2.3.4")],
            msg="A transaction-id mismatch must be ignored and the query retried.",
        )

    def test__dns__resolver__raises_on_timeout_exhaustion(self) -> None:
        """
        Ensure exhausting all retries on receive timeout raises a resolver
        error.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        factory = _FakeSocketFactory(TimeoutError, TimeoutError, TimeoutError)
        resolver = DnsResolver(server=_SERVER, socket_factory=factory, id_source=self._id_source, retries=2)

        with self.assertRaises(DnsResolverError):
            resolver.resolve("example.com", DnsRecordType.A)

    def test__dns__resolver__raises_name_error_on_nxdomain(self) -> None:
        """
        Ensure an NXDOMAIN response raises a resolver error flagged as a
        name error.

        Reference: RFC 1035 §4.1.1 (RCODE 3 — name error).
        """

        factory = _FakeSocketFactory(
            _build_response(response_id=_QUERY_ID, addresses=(), rcode=DnsResponseCode.NXDOMAIN)
        )
        resolver = DnsResolver(server=_SERVER, socket_factory=factory, id_source=self._id_source)

        with self.assertRaises(DnsResolverError) as raised:
            resolver.resolve("nonexistent.example", DnsRecordType.A)

        self.assertTrue(
            raised.exception.name_error,
            msg="An NXDOMAIN response must raise a resolver error flagged as a name error.",
        )
