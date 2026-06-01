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
End-to-end integration tests for the RFC 3376 §3.1 data-plane source-
delivery filter (Linux 'ip_mc_sf_allow') applied to RAW sockets — an
inbound IPv4 multicast datagram reaches a RAW socket only if the socket's
per-(interface, group) source filter admits the datagram's source. Linux
gates both UDP and RAW multicast delivery through the same filter
(net/ipv4/raw.c::raw_v4_input).

pytcp/tests/integration/protocols/igmp/test__igmp__source_data_filter__raw.py

ver 3.0.8
"""

from typing import override

from net_addr import Ip4Address, MacAddress
from net_proto import EthernetAssembler, Ip4Assembler, IpProto
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.raw.raw__assembler import RawAssembler
from pytcp import stack
from pytcp.runtime.socket import (
    IP_ADD_MEMBERSHIP,
    IP_ADD_SOURCE_MEMBERSHIP,
    IP_BLOCK_SOURCE,
    IPPROTO_IP,
    AddressFamily,
    SocketType,
)
from pytcp.runtime.socket.raw__socket import RawSocket
from pytcp.tests.lib.udp_testcase import HOST_A__IP4_ADDRESS, UdpTestCase

_GROUP = Ip4Address("239.1.1.1")
_GROUP_MAC = MacAddress("01:00:5e:01:01:01")
_HOST_A_MAC = MacAddress("02:00:00:00:00:91")
_ALLOWED = HOST_A__IP4_ADDRESS
_OTHER = Ip4Address("10.0.1.99")

# An IP protocol with no transport handler so the datagram is delivered
# via the IPv4 RAW-socket path rather than a transport demux.
_PROTO = IpProto.IP4


def _raw_mcast_frame(*, source: Ip4Address, payload: bytes = b"data") -> bytes:
    """Build an Ethernet/IPv4 multicast datagram (proto IP-in-IP) from 'source' to the test group."""

    return bytes(
        EthernetAssembler(
            ethernet__src=_HOST_A_MAC,
            ethernet__dst=_GROUP_MAC,
            ethernet__payload=Ip4Assembler(
                ip4__src=source,
                ip4__dst=_GROUP,
                ip4__payload=RawAssembler(raw__payload=payload, ip_proto=_PROTO),
            ),
        )
    )


class TestRawMulticastSourceDataFilter(UdpTestCase):
    """
    The RFC 3376 §3.1 data-plane multicast source-delivery filter tests
    for RAW sockets.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness and register a RAW socket bound to the test
        group so an inbound multicast datagram on the RAW protocol is a
        candidate for delivery.
        """

        super().setUp()
        self._sock = RawSocket(family=AddressFamily.INET4, type=SocketType.RAW, protocol=_PROTO)
        self._sock._local_ip_address = _GROUP
        stack.sockets[self._sock.socket_id] = self._sock

    def _drive(self, *, source: Ip4Address, payload: bytes = b"data") -> None:
        """Feed a multicast frame from 'source' into the RX path."""

        self._packet_handler._phrx_ethernet(PacketRx(_raw_mcast_frame(source=source, payload=payload)))

    def test__include_filter__delivers_listed_source(self) -> None:
        """
        Ensure a multicast datagram from a source in the RAW socket's
        INCLUDE list is delivered.

        Reference: RFC 3376 §3.1 (INCLUDE delivers listed sources).
        """

        self._sock.setsockopt(
            IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, bytes(_GROUP) + bytes(_ALLOWED) + bytes(Ip4Address())
        )

        self._drive(source=_ALLOWED, payload=b"hello")

        self.assertEqual(
            len(self._sock._packet_rx_md),
            1,
            msg="A datagram from an included source must be delivered to the RAW socket.",
        )

    def test__include_filter__drops_unlisted_source(self) -> None:
        """
        Ensure a multicast datagram from a source not in the RAW socket's
        INCLUDE list is not delivered and bumps the source-filter drop
        counter.

        Reference: RFC 3376 §3.1 (INCLUDE delivers only listed sources).
        """

        self._sock.setsockopt(
            IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, bytes(_GROUP) + bytes(_ALLOWED) + bytes(Ip4Address())
        )

        before = self._packet_handler.packet_stats_rx.raw__multicast_source_filtered__drop
        self._drive(source=_OTHER)

        self.assertEqual(
            len(self._sock._packet_rx_md),
            0,
            msg="A datagram from an unlisted INCLUDE source must not be delivered to the RAW socket.",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_rx.raw__multicast_source_filtered__drop,
            before + 1,
            msg="A filtered multicast source must bump raw__multicast_source_filtered__drop.",
        )

    def test__exclude_filter__drops_blocked_source(self) -> None:
        """
        Ensure a multicast datagram from a source blocked on an any-source
        (EXCLUDE) RAW membership is not delivered, while an unblocked
        source is.

        Reference: RFC 3376 §3.1 (EXCLUDE delivers all but listed sources).
        """

        self._sock.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, bytes(_GROUP) + bytes(Ip4Address()))
        self._sock.setsockopt(IPPROTO_IP, IP_BLOCK_SOURCE, bytes(_GROUP) + bytes(_OTHER) + bytes(Ip4Address()))

        self._drive(source=_OTHER)
        self.assertEqual(
            len(self._sock._packet_rx_md),
            0,
            msg="A datagram from a blocked EXCLUDE source must not be delivered to the RAW socket.",
        )

        self._drive(source=_ALLOWED, payload=b"ok")
        self.assertEqual(
            len(self._sock._packet_rx_md),
            1,
            msg="A datagram from an unblocked EXCLUDE source must be delivered to the RAW socket.",
        )
