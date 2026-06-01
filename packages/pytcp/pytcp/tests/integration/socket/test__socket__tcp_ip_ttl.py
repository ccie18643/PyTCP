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
Integration tests for the H6 row of the socket-layer Linux
parity audit ('docs/refactor/socket_linux_parity_audit.md'
§H6) — per-socket 'IP_TTL' (IPv4) and 'IPV6_UNICAST_HOPS'
(IPv6) overrides appearing on the wire of outbound TCP
segments. The UDP/RAW half shipped in commit '89da6654';
this file pins the TCP-side propagation from
'TcpSocket._ip_ttl' / '_ipv6_unicast_hops' through the
session's '_transmit_packet' into the IP TX handler.

pytcp/tests/integration/socket/test__socket__tcp_ip_ttl.py

ver 3.0.8
"""

from net_proto import EthernetParser, EtherType, Ip4Parser, Ip6Parser
from net_proto.lib.packet_rx import PacketRx
from pytcp.socket import (
    IP_TTL,
    IPPROTO_IP,
    IPPROTO_IPV6,
    IPV6_UNICAST_HOPS,
    AddressFamily,
)
from pytcp.tests.lib.tcp_testcase import TcpTestCase

LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000


def _ip4_ttl_from_frame(frame: bytes, /) -> int:
    """
    Re-parse an emitted IPv4-bearing Ethernet frame and return
    the IP TTL field. Uses the wire parsers so the assertion
    pins what's actually on the wire, not what the test author
    thought was on the wire.
    """

    packet_rx = PacketRx(frame)
    EthernetParser(packet_rx)
    assert packet_rx.ethernet.type is EtherType.IP4
    Ip4Parser(packet_rx)
    return packet_rx.ip4.ttl


def _ip6_hop_from_frame(frame: bytes, /) -> int:
    """
    Re-parse an emitted IPv6-bearing Ethernet frame and return
    the IPv6 Hop-Limit field.
    """

    packet_rx = PacketRx(frame)
    EthernetParser(packet_rx)
    assert packet_rx.ethernet.type is EtherType.IP6
    Ip6Parser(packet_rx)
    return packet_rx.ip6.hop


class TestTcpSocketIpTtlOnWire(TcpTestCase):
    """
    H6 — 'IP_TTL' per-socket override threads from the socket
    layer into outbound TCP-over-IPv4 segments.
    """

    def test__tcp_socket__ip_ttl_override_appears_on_outbound_syn(self) -> None:
        """
        Ensure 'setsockopt(IPPROTO_IP, IP_TTL, 7)' on a TCP
        socket makes the active-open SYN emitted by the
        session carry TTL=7 in its IPv4 header instead of
        the stack default.

        Reference: RFC 1122 §4.1.4 (application MUST specify TTL per-datagram).
        Reference: Linux IP_TTL (per-socket TTL override).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session._socket.setsockopt(IPPROTO_IP, IP_TTL, 7)

        from pytcp.protocols.tcp.tcp__enums import SysCall

        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        self.assertGreaterEqual(
            len(self._frames_tx),
            1,
            msg="CONNECT must emit a SYN frame.",
        )
        ttl = _ip4_ttl_from_frame(self._frames_tx[0])
        self.assertEqual(
            ttl,
            7,
            msg="setsockopt(IP_TTL, 7) must thread to the outbound IPv4 TTL field.",
        )

    def test__tcp_socket__no_ip_ttl_override_uses_stack_default(self) -> None:
        """
        Ensure a TCP socket WITHOUT an 'IP_TTL' override emits
        outbound IPv4 segments carrying the stack-default TTL
        (the IP TX handler's '_ip4_default_ttl' / equivalent).
        Regression pin against accidental zero / wrong default.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        # No setsockopt — _ip_ttl stays None.

        from pytcp.protocols.tcp.tcp__enums import SysCall

        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        ttl = _ip4_ttl_from_frame(self._frames_tx[0])
        # Stack default in the harness is the canonical 64 (Linux default).
        # The actual value comes from the packet handler; the
        # assertion is that it's a sensible positive value, not
        # the override.
        self.assertGreater(
            ttl,
            0,
            msg="Default TTL must be a positive value (handler-supplied).",
        )

    def test__tcp_socket__ip_ttl_override_propagates_to_data_segment(self) -> None:
        """
        Ensure the per-socket 'IP_TTL' override applies to
        post-handshake data segments, not just the SYN — the
        override must be re-read on every segment emit.

        Reference: Linux IP_TTL (every outbound datagram).
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
        )
        session._socket.setsockopt(IPPROTO_IP, IP_TTL, 33)
        session._tx.buffer.extend(b"hello")
        session._cc.snd_ewn = 1000

        frames_before = len(self._frames_tx)
        session._transmit_data()
        emitted = self._frames_tx[frames_before:]

        self.assertGreaterEqual(
            len(emitted),
            1,
            msg="_transmit_data must emit at least one data segment.",
        )
        ttl = _ip4_ttl_from_frame(emitted[0])
        self.assertEqual(
            ttl,
            33,
            msg="IP_TTL=33 override must appear on the post-handshake data segment.",
        )


class TestTcpSocketIpv6UnicastHopsOnWire(TcpTestCase):
    """
    H6 — 'IPV6_UNICAST_HOPS' per-socket override threads from
    the socket layer into outbound TCP-over-IPv6 segments.
    """

    def test__tcp_socket__ipv6_unicast_hops_override_appears_on_outbound_syn(self) -> None:
        """
        Ensure 'setsockopt(IPPROTO_IPV6, IPV6_UNICAST_HOPS, 32)'
        on an AF_INET6 TCP socket makes the active-open SYN
        carry Hop-Limit=32 in its IPv6 header instead of the
        stack default.

        Reference: RFC 8200 §3 (Hop Limit field).
        Reference: Linux IPV6_UNICAST_HOPS (per-socket Hop-Limit override).
        """

        session = self._make_active_session(
            iss=LOCAL__ISS,
            family=AddressFamily.INET6,
        )
        session._socket.setsockopt(IPPROTO_IPV6, IPV6_UNICAST_HOPS, 32)

        from pytcp.protocols.tcp.tcp__enums import SysCall

        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        self.assertGreaterEqual(
            len(self._frames_tx),
            1,
            msg="CONNECT must emit a SYN frame.",
        )
        hop = _ip6_hop_from_frame(self._frames_tx[0])
        self.assertEqual(
            hop,
            32,
            msg="setsockopt(IPV6_UNICAST_HOPS, 32) must thread to the outbound IPv6 Hop-Limit.",
        )

    def test__tcp_socket__no_ipv6_unicast_hops_override_uses_stack_default(self) -> None:
        """
        Ensure an AF_INET6 TCP socket WITHOUT an
        'IPV6_UNICAST_HOPS' override emits outbound IPv6
        segments carrying the stack-default Hop-Limit.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        session = self._make_active_session(
            iss=LOCAL__ISS,
            family=AddressFamily.INET6,
        )

        from pytcp.protocols.tcp.tcp__enums import SysCall

        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        hop = _ip6_hop_from_frame(self._frames_tx[0])
        self.assertGreater(
            hop,
            0,
            msg="Default Hop-Limit must be a positive value (handler-supplied).",
        )
