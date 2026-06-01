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
Integration tests for the ICMPv4 Frag-Needed → PMTUD path added in
Phase 4 of the ICMP demux + PMTUD refactor. Exercises the full RX
flow: ICMPv4 Type 3 Code 4 frame in, embedded-header demux to a
matching UdpSocket, pmtu_cache update + 'notify_pmtu' callback +
RX-stat bumps observable on the packet handler.

pytcp/tests/integration/protocols/icmp4/test__icmp4__pmtud.py

ver 3.0.8
"""

from net_proto import (
    Icmp4Assembler,
    Icmp4DestinationUnreachableCode,
    Icmp4MessageDestinationUnreachable,
    Ip4Assembler,
    UdpAssembler,
)
from net_proto.lib.enums import IpProto
from pytcp import stack
from pytcp.socket import AddressFamily, SocketType
from pytcp.socket.udp__socket import UdpSocket
from pytcp.tests.lib.icmp_testcase import IcmpTestCase
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)

# Local addressing for the UDP socket bound on the stack.
_LOCAL_PORT = 12345
_REMOTE_PORT = 54321
# Next-hop MTU advertised by the synthetic ICMPv4 Frag-Needed.
_NEXT_HOP_MTU = 1400


def _build_frag_needed_frame(*, mtu: int) -> bytes:
    """
    Construct an Ethernet/IPv4/ICMPv4 Type 3 Code 4 (Fragmentation
    Needed and DF Set) frame whose embedded data is an IPv4+UDP
    header for the (HOST_A → STACK : _LOCAL_PORT → _REMOTE_PORT)
    flow. The MTU advertised in the Frag-Needed extension is
    'mtu'.
    """

    embedded_udp = bytes(
        Ip4Assembler(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=HOST_A__IP4_ADDRESS,
            ip4__payload=UdpAssembler(
                udp__sport=_LOCAL_PORT,
                udp__dport=_REMOTE_PORT,
            ),
        )
    )
    icmp = Icmp4Assembler(
        icmp4__message=Icmp4MessageDestinationUnreachable(
            code=Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED,
            mtu=mtu,
            data=embedded_udp,
        ),
    )
    ip4 = bytes(
        Ip4Assembler(
            ip4__src=HOST_A__IP4_ADDRESS,
            ip4__dst=STACK__IP4_HOST.address,
            ip4__payload=icmp,
        )
    )
    return b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00" + ip4


class TestIcmp4Pmtud__FragNeededWithMatchingUdpSocket(IcmpTestCase):
    """
    ICMPv4 Frag-Needed → PMTUD callback when a UDP socket matches
    the embedded 4-tuple.
    """

    def setUp(self) -> None:
        """
        Bind a UdpSocket on the stack so the embedded 4-tuple matches.
        """

        super().setUp()
        self._socket = UdpSocket(family=AddressFamily.INET4, type=SocketType.DGRAM, protocol=IpProto.UDP)
        self._socket._local_ip_address = STACK__IP4_HOST.address
        self._socket._local_port = _LOCAL_PORT
        self._socket._remote_ip_address = HOST_A__IP4_ADDRESS
        self._socket._remote_port = _REMOTE_PORT
        stack.sockets[self._socket.socket_id] = self._socket

    def test__icmp4__pmtud__frag_needed__updates_pmtu_cache(self) -> None:
        """
        Ensure an ICMPv4 Frag-Needed for a 4-tuple matching an
        installed UDP socket updates 'stack.pmtu_cache' with the
        advertised next-hop MTU keyed by the remote address.

        Reference: RFC 1191 §3 (Path MTU Discovery on the host).
        """

        self._drive_rx(frame=_build_frag_needed_frame(mtu=_NEXT_HOP_MTU))

        self.assertEqual(
            stack.pmtu_cache.get(HOST_A__IP4_ADDRESS),
            _NEXT_HOP_MTU,
            msg="ICMPv4 Frag-Needed must update stack.pmtu_cache for the remote address.",
        )

    def test__icmp4__pmtud__frag_needed__notifies_socket(self) -> None:
        """
        Ensure the UDP socket's PMTUD callback fires by observing the
        cache mutation through the socket's own 'remote_ip_address'.
        Indirect proof — Phase 4 'notify_pmtu' is a thin shim that
        only mutates the cache, so checking the cache after one drive
        is sufficient.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_build_frag_needed_frame(mtu=_NEXT_HOP_MTU))

        self.assertIn(
            self._socket._remote_ip_address,
            stack.pmtu_cache,
            msg="UdpSocket.notify_pmtu must update stack.pmtu_cache keyed by the socket's remote address.",
        )

    def test__icmp4__pmtud__frag_needed__bumps_packet_stats(self) -> None:
        """
        Ensure both the generic 'icmp4__destination_unreachable'
        counter and the Phase-4 PMTUD-specific counters
        ('__fragmentation_needed', '__fragmentation_needed__notify_pmtu')
        bump on the matched-socket path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_build_frag_needed_frame(mtu=_NEXT_HOP_MTU))

        stats = self._packet_handler.packet_stats_rx
        self.assertEqual(
            stats.icmp4__destination_unreachable,
            1,
            msg="Generic Destination Unreachable counter must bump.",
        )
        self.assertEqual(
            stats.icmp4__destination_unreachable__fragmentation_needed,
            1,
            msg="Frag-Needed-specific counter must bump.",
        )
        self.assertEqual(
            stats.icmp4__destination_unreachable__fragmentation_needed__notify_pmtu,
            1,
            msg="Frag-Needed notify-pmtu counter must bump on a matched-socket path.",
        )


class TestIcmp4Pmtud__FragNeededWithoutSocket(IcmpTestCase):
    """
    ICMPv4 Frag-Needed when no UDP socket matches the embedded
    4-tuple — pmtu_cache MUST NOT be updated and notify_pmtu MUST NOT
    fire.
    """

    def test__icmp4__pmtud__no_socket__pmtu_cache_unchanged(self) -> None:
        """
        Ensure no entry is inserted into 'stack.pmtu_cache' when no
        UDP socket matches — PMTUD updates are scoped to active
        sockets and cannot be triggered by a forged ICMP error
        targeting an unbound 4-tuple.

        Reference: RFC 5927 §3 (ICMP attack-surface considerations).
        """

        self._drive_rx(frame=_build_frag_needed_frame(mtu=_NEXT_HOP_MTU))

        self.assertNotIn(
            HOST_A__IP4_ADDRESS,
            stack.pmtu_cache,
            msg="pmtu_cache must not be updated when no UDP socket matches the Frag-Needed 4-tuple.",
        )

    def test__icmp4__pmtud__no_socket__notify_pmtu_counter_zero(self) -> None:
        """
        Ensure the notify-pmtu counter stays at zero on the
        no-matching-socket path even though the generic +
        Frag-Needed counters still bump.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_build_frag_needed_frame(mtu=_NEXT_HOP_MTU))

        stats = self._packet_handler.packet_stats_rx
        self.assertEqual(
            stats.icmp4__destination_unreachable,
            1,
            msg="Generic Destination Unreachable counter must still bump.",
        )
        self.assertEqual(
            stats.icmp4__destination_unreachable__fragmentation_needed,
            1,
            msg="Frag-Needed-specific counter must bump even without a socket match.",
        )
        self.assertEqual(
            stats.icmp4__destination_unreachable__fragmentation_needed__notify_pmtu,
            0,
            msg="notify-pmtu counter must stay zero when no socket matches.",
        )
