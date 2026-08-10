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
source-delivery filter over IPv6 UDP (the IPv6 analogue of Linux
'ip_mc_sf_allow' in 'ip6_mc_input'): an inbound IPv6 multicast UDP
datagram is delivered to a socket only if the socket's per-(interface,
group) source filter admits the datagram's source.

pytcp/tests/integration/protocols/icmp6/test__icmp6__mld__source_data_filter.py

ver 3.0.10
"""

import struct
from typing import override

from net_addr import Ip6Address
from net_proto import EthernetAssembler, Ip6Assembler, UdpAssembler
from pytcp.runtime.socket import (
    IPPROTO_IPV6,
    IPV6_JOIN_GROUP,
    MCAST_BLOCK_SOURCE,
    MCAST_JOIN_SOURCE_GROUP,
    AddressFamily,
)
from pytcp.tests.lib.network_testcase import HOST_A__MAC_ADDRESS
from pytcp.tests.lib.udp_testcase import HOST_A__IP6_ADDRESS, UdpTestCase

_GROUP = Ip6Address("ff15::1234")
_ALLOWED = HOST_A__IP6_ADDRESS
_OTHER = Ip6Address("2001:db8:0:1::99")
_LOCAL_PORT = 4444
_REMOTE_PORT = 5555


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


def _udp_mcast_frame(*, source: Ip6Address, payload: bytes = b"data") -> bytes:
    """Build an Ethernet/IPv6/UDP multicast datagram from 'source' to the test group."""

    return bytes(
        EthernetAssembler(
            ethernet__src=HOST_A__MAC_ADDRESS,
            ethernet__dst=_GROUP.multicast_mac,
            ethernet__payload=Ip6Assembler(
                ip6__src=source,
                ip6__dst=_GROUP,
                ip6__payload=UdpAssembler(
                    udp__sport=_REMOTE_PORT,
                    udp__dport=_LOCAL_PORT,
                    udp__payload=payload,
                ),
            ),
        )
    )


class TestMldSourceDataFilter(UdpTestCase):
    """
    The RFC 3810 §4.1 data-plane IPv6 multicast source-delivery filter tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness and bind an IPv6 UDP socket to the multicast
        group and port so an inbound datagram to the group is a candidate
        for delivery.
        """

        super().setUp()
        self._sock = self._bind_udp_socket(
            local_ip=_GROUP,
            local_port=_LOCAL_PORT,
            family=AddressFamily.INET6,
        )

    def test__include_filter__delivers_listed_source(self) -> None:
        """
        Ensure a datagram from a source in the socket's INCLUDE list is
        delivered.

        Reference: RFC 3810 §4.1 (INCLUDE delivers listed sources).
        """

        self._sock.setsockopt(IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, _group_source_req(_GROUP, _ALLOWED))

        self._drive_udp_rx(frame=_udp_mcast_frame(source=_ALLOWED, payload=b"hello"))

        data, addr = self._recvfrom(self._sock, timeout=0.5)
        self.assertEqual(data, b"hello", msg="A datagram from an included source must be delivered.")
        self.assertEqual(addr, (str(_ALLOWED), _REMOTE_PORT), msg="recvfrom must report the sender address.")

    def test__include_filter__drops_unlisted_source(self) -> None:
        """
        Ensure a datagram from a source not in the socket's INCLUDE list
        is not delivered and bumps the source-filter drop counter.

        Reference: RFC 3810 §4.1 (INCLUDE delivers only listed sources).
        """

        self._sock.setsockopt(IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, _group_source_req(_GROUP, _ALLOWED))

        before = self._packet_handler.packet_stats_rx.udp__multicast_source_filtered__drop
        self._drive_udp_rx(frame=_udp_mcast_frame(source=_OTHER))

        self.assertEqual(
            len(self._sock._packet_rx_md),
            0,
            msg="A datagram from an unlisted INCLUDE source must not be delivered.",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_rx.udp__multicast_source_filtered__drop,
            before + 1,
            msg="A filtered multicast source must bump udp__multicast_source_filtered__drop.",
        )

    def test__exclude_filter__drops_blocked_source(self) -> None:
        """
        Ensure a datagram from a source blocked on an any-source (EXCLUDE)
        membership is not delivered, while an unblocked source is.

        Reference: RFC 3810 §4.1 (EXCLUDE delivers all but listed sources).
        """

        self._sock.setsockopt(IPPROTO_IPV6, IPV6_JOIN_GROUP, _ipv6_mreq(_GROUP))
        self._sock.setsockopt(IPPROTO_IPV6, MCAST_BLOCK_SOURCE, _group_source_req(_GROUP, _OTHER))

        # The blocked source is dropped.
        self._drive_udp_rx(frame=_udp_mcast_frame(source=_OTHER))
        self.assertEqual(
            len(self._sock._packet_rx_md),
            0,
            msg="A datagram from a blocked EXCLUDE source must not be delivered.",
        )

        # An unblocked source is delivered.
        self._drive_udp_rx(frame=_udp_mcast_frame(source=_ALLOWED, payload=b"ok"))
        data, _ = self._recvfrom(self._sock, timeout=0.5)
        self.assertEqual(data, b"ok", msg="A datagram from an unblocked EXCLUDE source must be delivered.")
