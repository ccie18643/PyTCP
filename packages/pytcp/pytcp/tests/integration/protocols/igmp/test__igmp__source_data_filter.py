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
delivery filter (Linux 'ip_mc_sf_allow') — an inbound IPv4 multicast UDP
datagram reaches a socket only if the socket's per-(interface, group)
source filter admits the datagram's source address.

pytcp/tests/integration/protocols/igmp/test__igmp__source_data_filter.py

ver 3.0.10
"""

from typing import override

from net_addr import Ip4Address, MacAddress
from net_proto import EthernetAssembler, Ip4Assembler, UdpAssembler
from pytcp.runtime.socket import (
    IP_ADD_MEMBERSHIP,
    IP_ADD_SOURCE_MEMBERSHIP,
    IP_BLOCK_SOURCE,
    IPPROTO_IP,
)
from pytcp.tests.lib.udp_testcase import HOST_A__IP4_ADDRESS, UdpTestCase

_GROUP = Ip4Address("239.1.1.1")
_GROUP_MAC = MacAddress("01:00:5e:01:01:01")
_HOST_A_MAC = MacAddress("02:00:00:00:00:91")
_ALLOWED = HOST_A__IP4_ADDRESS
_OTHER = Ip4Address("10.0.1.99")
_LOCAL_PORT = 4444
_REMOTE_PORT = 5555


def _udp_mcast_frame(*, source: Ip4Address, payload: bytes = b"data") -> bytes:
    """Build an Ethernet/IPv4/UDP multicast datagram from 'source' to the test group."""

    return bytes(
        EthernetAssembler(
            ethernet__src=_HOST_A_MAC,
            ethernet__dst=_GROUP_MAC,
            ethernet__payload=Ip4Assembler(
                ip4__src=source,
                ip4__dst=_GROUP,
                ip4__payload=UdpAssembler(
                    udp__sport=_REMOTE_PORT,
                    udp__dport=_LOCAL_PORT,
                    udp__payload=payload,
                ),
            ),
        )
    )


class TestIgmpSourceDataFilter(UdpTestCase):
    """
    The RFC 3376 §3.1 data-plane multicast source-delivery filter tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness and bind a UDP socket to the multicast group
        and port so an inbound datagram to the group is a candidate for
        delivery.
        """

        super().setUp()
        self._sock = self._bind_udp_socket(local_ip=_GROUP, local_port=_LOCAL_PORT)

    def test__include_filter__delivers_listed_source(self) -> None:
        """
        Ensure a datagram from a source in the socket's INCLUDE list is
        delivered.

        Reference: RFC 3376 §3.1 (INCLUDE delivers listed sources).
        """

        self._sock.setsockopt(
            IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, bytes(_GROUP) + bytes(_ALLOWED) + bytes(Ip4Address())
        )

        self._drive_udp_rx(frame=_udp_mcast_frame(source=_ALLOWED, payload=b"hello"))

        data, addr = self._recvfrom(self._sock, timeout=0.5)
        self.assertEqual(data, b"hello", msg="A datagram from an included source must be delivered.")
        self.assertEqual(addr, (str(_ALLOWED), _REMOTE_PORT), msg="recvfrom must report the sender address.")

    def test__include_filter__drops_unlisted_source(self) -> None:
        """
        Ensure a datagram from a source not in the socket's INCLUDE list
        is not delivered and bumps the source-filter drop counter.

        Reference: RFC 3376 §3.1 (INCLUDE delivers only listed sources).
        """

        self._sock.setsockopt(
            IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, bytes(_GROUP) + bytes(_ALLOWED) + bytes(Ip4Address())
        )

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
        Ensure a datagram from a source blocked on an any-source
        (EXCLUDE) membership is not delivered, while an unblocked source
        is.

        Reference: RFC 3376 §3.1 (EXCLUDE delivers all but listed sources).
        """

        self._sock.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, bytes(_GROUP) + bytes(Ip4Address()))
        self._sock.setsockopt(IPPROTO_IP, IP_BLOCK_SOURCE, bytes(_GROUP) + bytes(_OTHER) + bytes(Ip4Address()))

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
