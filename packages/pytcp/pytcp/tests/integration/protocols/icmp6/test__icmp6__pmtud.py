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
Integration tests for the ICMPv6 Packet-Too-Big → PMTUD path added
in Phase 4 of the ICMP demux + PMTUD refactor. Exercises the full
RX flow: ICMPv6 Type 2 frame in, embedded-header demux to a matching
UdpSocket, pmtu_cache update + 'notify_pmtu' callback + RX-stat
bumps observable on the packet handler.

pytcp/tests/integration/protocols/icmp6/test__icmp6__pmtud.py

ver 3.0.8
"""

from net_proto import (
    Icmp6Assembler,
    Icmp6MessagePacketTooBig,
    Ip6Assembler,
    UdpAssembler,
)
from net_proto.lib.enums import IpProto
from pytcp import stack
from pytcp.socket import AddressFamily, SocketType
from pytcp.socket.udp__socket import UdpSocket
from pytcp.tests.lib.icmp_testcase import IcmpTestCase
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP6_ADDRESS,
    STACK__IP6_HOST,
)

_LOCAL_PORT = 12345
_REMOTE_PORT = 54321
_NEXT_HOP_MTU = 1300


def _build_packet_too_big_frame(*, mtu: int) -> bytes:
    """
    Construct an Ethernet/IPv6/ICMPv6 Type 2 (Packet Too Big) frame
    whose embedded data is an IPv6+UDP header for the
    (HOST_A → STACK : _LOCAL_PORT → _REMOTE_PORT) flow.
    """

    embedded_udp = bytes(
        Ip6Assembler(
            ip6__src=STACK__IP6_HOST.address,
            ip6__dst=HOST_A__IP6_ADDRESS,
            ip6__payload=UdpAssembler(
                udp__sport=_LOCAL_PORT,
                udp__dport=_REMOTE_PORT,
            ),
        )
    )
    icmp = Icmp6Assembler(
        icmp6__message=Icmp6MessagePacketTooBig(
            mtu=mtu,
            data=embedded_udp,
        ),
    )
    ip6 = bytes(
        Ip6Assembler(
            ip6__src=HOST_A__IP6_ADDRESS,
            ip6__dst=STACK__IP6_HOST.address,
            ip6__hop=64,
            ip6__payload=icmp,
        )
    )
    return b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd" + ip6


class TestIcmp6Pmtud__PtbWithMatchingUdpSocket(IcmpTestCase):
    """
    ICMPv6 Packet-Too-Big → PMTUD callback when a UDP socket matches
    the embedded 4-tuple.
    """

    def setUp(self) -> None:
        """
        Bind a UdpSocket on the stack so the embedded 4-tuple matches.
        """

        super().setUp()
        self._socket = UdpSocket(family=AddressFamily.INET6, type=SocketType.DGRAM, protocol=IpProto.UDP)
        self._socket._local_ip_address = STACK__IP6_HOST.address
        self._socket._local_port = _LOCAL_PORT
        self._socket._remote_ip_address = HOST_A__IP6_ADDRESS
        self._socket._remote_port = _REMOTE_PORT
        stack.sockets[self._socket.socket_id] = self._socket

    def test__icmp6__pmtud__ptb__updates_pmtu_cache(self) -> None:
        """
        Ensure an ICMPv6 Packet Too Big for a 4-tuple matching an
        installed UDP socket updates 'stack.pmtu_cache' with the
        advertised next-hop MTU keyed by the remote address.

        Reference: RFC 8201 §4 (IPv6 PMTUD per-destination MTU cache).
        """

        self._drive_rx(frame=_build_packet_too_big_frame(mtu=_NEXT_HOP_MTU))

        self.assertEqual(
            stack.pmtu_cache.get(HOST_A__IP6_ADDRESS),
            _NEXT_HOP_MTU,
            msg="ICMPv6 Packet Too Big must update stack.pmtu_cache for the remote address.",
        )

    def test__icmp6__pmtud__ptb__bumps_packet_stats(self) -> None:
        """
        Ensure both the generic 'icmp6__packet_too_big' counter and
        the notify-pmtu specific counter bump on the matched-socket
        path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_build_packet_too_big_frame(mtu=_NEXT_HOP_MTU))

        stats = self._packet_handler.packet_stats_rx
        self.assertEqual(
            stats.icmp6__packet_too_big,
            1,
            msg="Packet Too Big counter must bump.",
        )
        self.assertEqual(
            stats.icmp6__packet_too_big__notify_pmtu,
            1,
            msg="Packet Too Big notify-pmtu counter must bump on a matched-socket path.",
        )


class TestIcmp6Pmtud__PtbWithoutSocket(IcmpTestCase):
    """
    ICMPv6 Packet Too Big when no UDP socket matches the embedded
    4-tuple — pmtu_cache MUST NOT be updated.
    """

    def test__icmp6__pmtud__no_socket__pmtu_cache_unchanged(self) -> None:
        """
        Ensure no entry is inserted into 'stack.pmtu_cache' when no
        UDP socket matches.

        Reference: RFC 5927 §3 (ICMP attack-surface considerations).
        """

        self._drive_rx(frame=_build_packet_too_big_frame(mtu=_NEXT_HOP_MTU))

        self.assertNotIn(
            HOST_A__IP6_ADDRESS,
            stack.pmtu_cache,
            msg="pmtu_cache must not be updated when no UDP socket matches the PTB 4-tuple.",
        )

    def test__icmp6__pmtud__no_socket__notify_pmtu_counter_zero(self) -> None:
        """
        Ensure the notify-pmtu counter stays at zero on the
        no-matching-socket path even though the generic counter
        still bumps.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_build_packet_too_big_frame(mtu=_NEXT_HOP_MTU))

        stats = self._packet_handler.packet_stats_rx
        self.assertEqual(
            stats.icmp6__packet_too_big,
            1,
            msg="Generic Packet Too Big counter must still bump.",
        )
        self.assertEqual(
            stats.icmp6__packet_too_big__notify_pmtu,
            0,
            msg="notify-pmtu counter must stay zero when no socket matches.",
        )
