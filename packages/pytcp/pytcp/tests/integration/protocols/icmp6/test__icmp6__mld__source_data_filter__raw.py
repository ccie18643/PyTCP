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
Integration tests for the RFC 3810 §4.1 data-plane multicast
source-delivery filter over IPv6 RAW sockets (the IPv6 analogue of Linux
'ip_mc_sf_allow' in 'raw6_local_deliver'): a matched RAW socket whose
source filter rejects the datagram's source is skipped.

pytcp/tests/integration/protocols/icmp6/test__icmp6__mld__source_data_filter__raw.py

ver 3.0.10
"""

import struct
from typing import override

from net_addr import Ip6Address
from net_proto import EthernetAssembler, Ip6Assembler, IpProto
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.raw.raw__assembler import RawAssembler
from pytcp import stack
from pytcp.runtime.socket import (
    IPPROTO_IPV6,
    IPV6_JOIN_GROUP,
    MCAST_BLOCK_SOURCE,
    MCAST_JOIN_SOURCE_GROUP,
    AddressFamily,
    SocketType,
)
from pytcp.runtime.socket.raw__socket import RawSocket
from pytcp.tests.lib.network_testcase import HOST_A__MAC_ADDRESS
from pytcp.tests.lib.udp_testcase import HOST_A__IP6_ADDRESS, UdpTestCase

_GROUP = Ip6Address("ff15::1234")
_ALLOWED = HOST_A__IP6_ADDRESS
_OTHER = Ip6Address("2001:db8:0:1::99")

# An IPv6 next-header with no transport handler so the datagram is
# delivered via the IPv6 RAW-socket path rather than a transport demux.
_PROTO = IpProto.IP6


def _ipv6_mreq(group: Ip6Address) -> bytes:
    """Pack a 20-byte 'ipv6_mreq' (group + ifindex=0)."""

    return bytes(group) + struct.pack("@I", 0)


def _group_source_req(group: Ip6Address, source: Ip6Address) -> bytes:
    """Pack a 264-byte 'group_source_req' (group + source, ifindex=0)."""

    gsr = bytearray(264)
    struct.pack_into("@H", gsr, 8, 10)  # AF_INET6
    gsr[16:32] = bytes(group)
    struct.pack_into("@H", gsr, 136, 10)
    gsr[144:160] = bytes(source)
    return bytes(gsr)


def _raw_mcast_frame(*, source: Ip6Address, payload: bytes = b"data") -> bytes:
    """Build an Ethernet/IPv6 multicast datagram from 'source' to the test group."""

    return bytes(
        EthernetAssembler(
            ethernet__src=HOST_A__MAC_ADDRESS,
            ethernet__dst=_GROUP.multicast_mac,
            ethernet__payload=Ip6Assembler(
                ip6__src=source,
                ip6__dst=_GROUP,
                ip6__payload=RawAssembler(raw__payload=payload, ip_proto=_PROTO),
            ),
        )
    )


class TestMldRawSourceDataFilter(UdpTestCase):
    """
    The RFC 3810 §4.1 data-plane IPv6 multicast source-delivery filter
    tests for RAW sockets.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness and register an IPv6 RAW socket bound to the
        test group so an inbound multicast datagram on the RAW protocol is
        a candidate for delivery.
        """

        super().setUp()
        self._sock = RawSocket(family=AddressFamily.INET6, type=SocketType.RAW, protocol=_PROTO)
        # 'RawSocket.__init__' registers under the unspecified local
        # address; drop that and re-register bound to the test group (a
        # plain 'bind' rejects a multicast local address).
        stack.sockets.unregister(self._sock)
        self._sock._local_ip_address = _GROUP
        stack.sockets[self._sock.socket_id] = self._sock

    def _drive(self, *, source: Ip6Address, payload: bytes = b"data") -> None:
        """Feed a multicast frame from 'source' into the RX path."""

        self._packet_handler._phrx_ethernet(PacketRx(_raw_mcast_frame(source=source, payload=payload)))

    def test__include_filter__delivers_listed_source(self) -> None:
        """
        Ensure a multicast datagram from a source in the RAW socket's
        INCLUDE list is delivered.

        Reference: RFC 3810 §4.1 (INCLUDE delivers listed sources).
        """

        self._sock.setsockopt(IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, _group_source_req(_GROUP, _ALLOWED))

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

        Reference: RFC 3810 §4.1 (INCLUDE delivers only listed sources).
        """

        self._sock.setsockopt(IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, _group_source_req(_GROUP, _ALLOWED))

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
        (EXCLUDE) membership is not delivered to the RAW socket, while an
        unblocked source is.

        Reference: RFC 3810 §4.1 (EXCLUDE delivers all but listed sources).
        """

        self._sock.setsockopt(IPPROTO_IPV6, IPV6_JOIN_GROUP, _ipv6_mreq(_GROUP))
        self._sock.setsockopt(IPPROTO_IPV6, MCAST_BLOCK_SOURCE, _group_source_req(_GROUP, _OTHER))

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
