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
This module contains the daemon-side DNS stub resolver.

'DnsResolver' answers A / AAAA lookups by sending a recursive query to a
configured upstream server over an in-process UDP socket (so the query
traverses the running stack), matching the response by transaction id,
extracting the addresses, and caching them for the answer TTL. It is the
stack-internal worker behind the 'resolve' control op (the client-facing
'getaddrinfo' / 'gethostbyname' surface marshals to it over IPC).

The UDP socket and the transaction-id source are injected so the resolver
is unit-testable without a live upstream; the defaults open a real
'pytcp.runtime.socket' datagram socket and draw a random 16-bit id.

pytcp/protocols/dns/dns__resolver.py

ver 3.0.9
"""

import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, cast

from net_addr import Ip4Address, Ip6Address
from net_proto.protocols.dns.dns__assembler import DnsAssembler
from net_proto.protocols.dns.dns__enums import (
    DnsRecordClass,
    DnsRecordType,
    DnsResponseCode,
)
from net_proto.protocols.dns.dns__parser import DnsParser
from net_proto.protocols.dns.dns__question import DnsQuestion
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.runtime.socket import socket as pytcp_socket

# RFC 1035 §4.2.1 — a classic (non-EDNS) DNS UDP message is at most 512
# octets, the receive bound for a stub resolver that does not advertise
# EDNS0.
DNS__RESOLVER__RECV_LEN = 512

DNS__RESOLVER__DEFAULT_PORT = 53
DNS__RESOLVER__DEFAULT_TIMEOUT__SEC = 2.0
DNS__RESOLVER__DEFAULT_RETRIES = 2

type DnsAddress = Ip4Address | Ip6Address


class DnsResolverError(Exception):
    """
    Exception raised when a DNS lookup cannot be resolved.
    """

    def __init__(self, message: str, /, *, name_error: bool = False) -> None:
        """
        Record the failure message and whether the name does not exist.
        """

        super().__init__(message)
        self.name_error = name_error


class ResolverSocket(Protocol):
    """
    The datagram-socket surface the resolver depends on (the in-stack
    'UdpSocket' subset, whose 'recvfrom' takes a per-call timeout).
    """

    def sendto(self, data: bytes, address: tuple[str, int], /) -> int:
        """
        Send a datagram to an address.
        """

        ...

    def recvfrom(self, bufsize: int, timeout: float, /) -> tuple[bytes, tuple[str, int]]:
        """
        Receive a datagram with its sender address, timing out after
        'timeout' seconds.
        """

        ...

    def close(self) -> None:
        """
        Close the socket.
        """


@dataclass(frozen=True, kw_only=True, slots=True)
class _CacheEntry:
    """
    A cached resolution result with its monotonic expiry deadline.
    """

    addresses: tuple[DnsAddress, ...]
    expires_at: float


def _default_socket_factory(family: AddressFamily, /) -> ResolverSocket:
    """
    Open a real in-stack datagram socket of the given family.
    """

    return cast(ResolverSocket, pytcp_socket(family=family, type=SocketType.DGRAM))


def _default_id_source() -> int:
    """
    Draw a random 16-bit DNS transaction id.
    """

    return secrets.randbelow(0x10000)


class DnsResolver:
    """
    A caching DNS stub resolver over an in-stack UDP socket.
    """

    def __init__(
        self,
        *,
        server: DnsAddress,
        port: int = DNS__RESOLVER__DEFAULT_PORT,
        timeout: float = DNS__RESOLVER__DEFAULT_TIMEOUT__SEC,
        retries: int = DNS__RESOLVER__DEFAULT_RETRIES,
        socket_factory: Callable[[AddressFamily], ResolverSocket] = _default_socket_factory,
        id_source: Callable[[], int] = _default_id_source,
    ) -> None:
        """
        Configure the resolver against an upstream server.
        """

        self._server = server
        self._family = AddressFamily.INET4 if isinstance(server, Ip4Address) else AddressFamily.INET6
        self._port = port
        self._timeout = timeout
        self._retries = retries
        self._socket_factory = socket_factory
        self._id_source = id_source
        self._cache: dict[tuple[str, DnsRecordType], _CacheEntry] = {}
        self._lock = threading.Lock()

    @property
    def server(self) -> DnsAddress:
        """
        Get the configured upstream DNS server address.
        """

        return self._server

    def resolve(self, name: str, record_type: DnsRecordType, /) -> list[DnsAddress]:
        """
        Resolve 'name' to a list of addresses of the given record type,
        serving from cache when a fresh entry exists.
        """

        if (cached := self._cache_lookup(name, record_type)) is not None:
            return list(cached)

        addresses, ttl = self._query(name, record_type)
        if addresses:
            self._cache_store(name, record_type, addresses, ttl)
        return addresses

    def _cache_lookup(self, name: str, record_type: DnsRecordType, /) -> tuple[DnsAddress, ...] | None:
        """
        Return the cached addresses for a key if present and unexpired.
        """

        key = (name, record_type)
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            if entry.expires_at <= time.monotonic():
                del self._cache[key]
                return None
            return entry.addresses

    def _cache_store(self, name: str, record_type: DnsRecordType, addresses: list[DnsAddress], ttl: int, /) -> None:
        """
        Cache a resolution result until its TTL elapses.
        """

        with self._lock:
            self._cache[(name, record_type)] = _CacheEntry(
                addresses=tuple(addresses),
                expires_at=time.monotonic() + ttl,
            )

    def _query(self, name: str, record_type: DnsRecordType, /) -> tuple[list[DnsAddress], int]:
        """
        Send the query (with retries) and return the resolved addresses and
        the answer TTL to cache them for.
        """

        question = DnsQuestion(qname=name, qtype=record_type, qclass=DnsRecordClass.IN)
        last_error: Exception | None = None

        for _ in range(self._retries + 1):
            query_id = self._id_source() & 0xFFFF
            payload = bytes(DnsAssembler(dns__id=query_id, dns__questions=(question,)))
            sock = self._socket_factory(self._family)
            try:
                sock.sendto(payload, (str(self._server), self._port))
                data, _address = sock.recvfrom(DNS__RESOLVER__RECV_LEN, self._timeout)
            except (TimeoutError, OSError) as error:
                last_error = error
                continue
            finally:
                sock.close()

            response = DnsParser(memoryview(data))
            if response.id != query_id:
                last_error = DnsResolverError(f"The response id {response.id} does not match the query {query_id}.")
                continue
            if response.rcode == DnsResponseCode.NXDOMAIN:
                raise DnsResolverError(f"The name {name!r} does not exist.", name_error=True)
            if response.rcode != DnsResponseCode.NOERROR:
                last_error = DnsResolverError(f"The server returned {response.rcode} for {name!r}.")
                continue

            addresses = [
                answer.address
                for answer in response.answers
                if answer.rtype == record_type and answer.address is not None
            ]
            ttl = min((answer.ttl for answer in response.answers if answer.address is not None), default=0)
            return addresses, ttl

        raise DnsResolverError(f"The name {name!r} could not be resolved: {last_error}")
