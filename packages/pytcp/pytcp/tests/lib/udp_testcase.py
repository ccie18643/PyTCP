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


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
This module contains the 'UdpTestCase' base class used by the UDP
integration tests, layering UDP socket plumbing and probe helpers
on top of 'NetworkTestCase'.

pytcp/tests/lib/udp_testcase.py

ver 3.0.8
"""

from dataclasses import dataclass
from typing import Any, override

from net_addr import Ip4Address, Ip6Address, IpVersion
from net_proto.lib.enums import EtherType, IpProto
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.ethernet.ethernet__parser import EthernetParser
from net_proto.protocols.ip4.ip4__parser import Ip4Parser
from net_proto.protocols.ip6.ip6__parser import Ip6Parser
from net_proto.protocols.udp.udp__parser import UdpParser
from pytcp import stack
from pytcp.protocols.icmp.icmp__error_emitter import IcmpErrorRateLimiter
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.runtime.socket.udp__socket import UdpSocket
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__IP6_ADDRESS,
    STACK__IP4_HOST,
    STACK__IP6_HOST,
    NetworkTestCase,
)

# Canonical UDP ports used by 95%+ of UDP integration tests. Tests
# with non-default ports pass overrides as kwargs to
# '_bind_udp_socket'. Distinct from
# 'tcp_testcase._DEFAULT_LOCAL_PORT' so a future combined
# UDP+TCP socket test cannot accidentally bind both onto the same
# port number.
_DEFAULT_LOCAL_PORT = 4444
_DEFAULT_REMOTE_PORT = 5555


@dataclass(frozen=True, slots=True)
class UdpProbe:
    """
    Decoded snapshot of a single Ethernet/IP/UDP frame produced by
    the stack under test, used by 'UdpTestCase' assertions.
    """

    ip_ver: IpVersion
    ip_src: Ip6Address | Ip4Address
    ip_dst: Ip6Address | Ip4Address
    # RFC 791 §3.1 IPv4 TTL / RFC 8200 §3 IPv6 Hop Limit.
    ip_ttl: int
    # RFC 3168 §5 IP ECN field — 0=Not-ECT, 1=ECT(1), 2=ECT(0), 3=CE.
    ip_ecn: int
    # RFC 2474 §3 DSCP (6 high bits of the TOS / Traffic Class byte).
    ip_dscp: int
    # IPv4 options block as raw bytes; 'b""' for an IPv4 frame
    # without options and for every IPv6 frame.
    ip4_options: bytes
    sport: int
    dport: int
    payload: bytes


class UdpTestCase(NetworkTestCase):
    """
    Base class for UDP integration tests. Snapshots the stack-global
    socket / PMTU-cache / ICMP-error-rate-limiter state so per-test
    socket registrations and PMTU updates do not leak across tests,
    plus helpers to bind a UDP socket onto the canonical fixture
    addresses, drive RX frames into the packet handler, and parse
    TX frames back into a 'UdpProbe' for fluent assertions.
    """

    _sockets_prior: dict[Any, Any]
    _pmtu_cache_prior: dict[Any, Any]
    _pmtu_state_prior: dict[Any, Any]
    _icmp4_error_rate_limiter_prior: IcmpErrorRateLimiter
    _icmp6_error_rate_limiter_prior: IcmpErrorRateLimiter

    @override
    def setUp(self) -> None:
        """
        Snapshot the stack-global mutable state UDP tests routinely
        touch ('stack.sockets', 'stack.pmtu_cache', and the IPv4 /
        IPv6 ICMP error rate limiters), start each test from a
        cleared / fresh copy, and arrange for 'tearDown' to restore.

        Phase 3: the 'stack.sockets' / 'stack.pmtu_cache' / ICMP
        rate-limiter snapshot pattern is duplicated with
        'IcmpTestCase' and 'TcpTestCase'. When a fourth
        socket-touching harness lands, extract a shared
        '_SocketsAwareNetworkTestCase' intermediate base.
        """

        super().setUp()

        # 'stack.sockets' is a module-level dict that accumulates
        # registrations across tests if not cleared. Snapshot the
        # prior contents, then start each test with an empty dict;
        # tearDown restores so unrelated tests outside this class
        # are unaffected.
        self._sockets_prior = dict(stack.sockets)
        stack.sockets.clear()

        # 'stack.pmtu_cache' is the per-destination Path-MTU dict
        # populated by the ICMP PMTUD callbacks. Snapshot+clear so
        # a UDP test that triggers a PMTUD update cannot leak its
        # per-destination MTU into an unrelated test (especially
        # the IP_MTU getsockopt tests).
        self._pmtu_cache_prior = dict(stack.pmtu_cache)
        stack.pmtu_cache.clear()

        # 'stack.pmtu_state' is the unified PLPMTUD engine registry
        # added by Phase 2 of the PLPMTUD plan; snapshot/clear
        # alongside the legacy pmtu_cache.
        self._pmtu_state_prior = dict(stack.pmtu_state)
        stack.pmtu_state.clear()

        # ICMP error rate limiters: snapshot+replace with fresh
        # instances so a UDP test that triggers ICMP error
        # delivery (notify_unreachable / notify_pmtu /
        # notify_time_exceeded) starts each case with a full
        # burst quota.
        self._icmp4_error_rate_limiter_prior = stack.icmp4_error_rate_limiter
        stack.icmp4_error_rate_limiter = IcmpErrorRateLimiter()
        self._icmp6_error_rate_limiter_prior = stack.icmp6_error_rate_limiter
        stack.icmp6_error_rate_limiter = IcmpErrorRateLimiter()

    @override
    def tearDown(self) -> None:
        """
        Restore the stack-global state captured in 'setUp', then
        defer to the parent teardown so module-level patches are
        rolled back too.
        """

        stack.sockets.clear()
        stack.sockets.update(self._sockets_prior)

        stack.pmtu_cache.clear()
        stack.pmtu_cache.update(self._pmtu_cache_prior)

        stack.pmtu_state.clear()
        stack.pmtu_state.update(self._pmtu_state_prior)

        stack.icmp4_error_rate_limiter = self._icmp4_error_rate_limiter_prior
        stack.icmp6_error_rate_limiter = self._icmp6_error_rate_limiter_prior

        super().tearDown()

    def _bind_udp_socket(
        self,
        *,
        family: AddressFamily = AddressFamily.INET4,
        local_ip: Ip4Address | Ip6Address | None = None,
        local_port: int = _DEFAULT_LOCAL_PORT,
        remote_ip: Ip4Address | Ip6Address | None = None,
        remote_port: int = 0,
    ) -> UdpSocket:
        """
        Build a 'UdpSocket' on the canonical fixture addressing
        ('STACK__IP4_HOST.address:4444' for IPv4, the IPv6
        equivalent for AF_INET6) and register it in
        'stack.sockets'. Supply 'local_ip' / 'local_port' to
        override.

        When 'remote_ip' / 'remote_port' are non-default the
        socket is also "connected" (i.e. its '_remote_ip_address'
        / '_remote_port' are populated), suitable for tests that
        need a connected socket without going through the full
        BSD 'connect()' validation path.
        """

        if local_ip is None:
            local_ip = STACK__IP4_HOST.address if family is AddressFamily.INET4 else STACK__IP6_HOST.address

        sock = UdpSocket(family=family, type=SocketType.DGRAM, protocol=IpProto.UDP)
        sock._local_ip_address = local_ip
        sock._local_port = local_port

        if remote_ip is not None:
            sock._remote_ip_address = remote_ip
        if remote_port:
            sock._remote_port = remote_port

        stack.sockets[sock.socket_id] = sock
        return sock  # pyright: ignore[reportReturnType]  # factory __new__ divergence; mypy-clean

    def _drive_udp_rx(self, *, frame: bytes) -> list[bytes]:
        """
        Feed 'frame' into 'PacketHandler._phrx_ethernet' and return
        the list of TX frames the stack produced as a direct result.
        Mirrors 'TcpTestCase._drive_rx' /
        'IcmpTestCase._drive_rx' for the UDP family.
        """

        before = len(self._frames_tx)
        self._packet_handler._phrx_ethernet(PacketRx(frame))
        return list(self._frames_tx[before:])

    def _recvmsg(
        self,
        sock: UdpSocket,
        *,
        bufsize: int | None = None,
        ancbufsize: int = 256,
        timeout: float = 0.5,
    ) -> tuple[bytes, list[tuple[int, int, bytes]], int, tuple[str, int] | tuple[str, int, int, int]]:
        """
        Convenience wrapper over 'UdpSocket.recvmsg' with the
        defaults UDP integration tests use ('ancbufsize=256' so
        every emitted cmsg fits; 'timeout=0.5' so a missing-RX bug
        is surfaced quickly instead of hanging the suite).
        """

        return sock.recvmsg(bufsize=bufsize, ancbufsize=ancbufsize, timeout=timeout)

    def _recvfrom(
        self,
        sock: UdpSocket,
        *,
        bufsize: int | None = None,
        timeout: float = 0.5,
    ) -> tuple[bytes, tuple[str, int]]:
        """
        Convenience wrapper over 'UdpSocket.recvfrom' with the
        standard test-suite timeout.
        """

        return sock.recvfrom(bufsize=bufsize, timeout=timeout)

    def _parse_tx(self, frame: bytes, /) -> UdpProbe:
        """
        Parse a TX frame back into a 'UdpProbe' covering the IP
        and UDP fields the UDP integration tests need to assert
        on. Strips the Ethernet header and identifies the IP
        version from the EtherType.
        """

        packet_rx = PacketRx(frame)
        EthernetParser(packet_rx)

        if packet_rx.ethernet.type is EtherType.IP4:
            Ip4Parser(packet_rx)
            ip_ttl = packet_rx.ip4.ttl
            ip4_options_bytes = bytes(packet_rx.ip4.options)
        elif packet_rx.ethernet.type is EtherType.IP6:
            Ip6Parser(packet_rx)
            ip_ttl = packet_rx.ip6.hop
            ip4_options_bytes = b""
        else:
            raise AssertionError(f"Unexpected EtherType in TX frame: {packet_rx.ethernet.type!r}")

        UdpParser(packet_rx)

        return UdpProbe(
            ip_ver=packet_rx.ip.ver,
            ip_src=packet_rx.ip.src,
            ip_dst=packet_rx.ip.dst,
            ip_ttl=ip_ttl,
            ip_ecn=packet_rx.ip.ecn,
            ip_dscp=packet_rx.ip.dscp,
            ip4_options=ip4_options_bytes,
            sport=packet_rx.udp.sport,
            dport=packet_rx.udp.dport,
            payload=bytes(packet_rx.udp.payload),
        )


# Re-export the canonical fixtures so UDP integration tests can
# import addresses + ports from one place without round-tripping
# through 'network_testcase'.
__all__ = [
    "HOST_A__IP4_ADDRESS",
    "HOST_A__IP6_ADDRESS",
    "STACK__IP4_HOST",
    "STACK__IP6_HOST",
    "UdpProbe",
    "UdpTestCase",
    "_DEFAULT_LOCAL_PORT",
    "_DEFAULT_REMOTE_PORT",
]
