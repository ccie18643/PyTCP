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
This module contains integration tests for outbound UDP datagram
fragmentation over IPv4.

pytcp/tests/integration/protocols/udp/test__udp__fragmentation.py

ver 3.0.10
"""

from typing import override

from net_addr import Ip4Address
from pytcp.runtime.socket import (
    IP_TOS,
    IPPROTO_IP,
    IPPROTO_IPV6,
    IPV6_TCLASS,
    AddressFamily,
)
from pytcp.tests.lib.udp_testcase import (
    HOST_A__IP6_ADDRESS,
    STACK__IP6_HOST,
    UdpTestCase,
)

_STACK_IP4 = Ip4Address("10.0.1.7")
_HOST_A_IP4 = Ip4Address("10.0.1.91")
_HOST_B_IP4 = Ip4Address("10.0.1.92")  # on-link, ARP cache miss
_LOCAL_PORT = 4444
_REMOTE_PORT = 5555

# Interface MTU pinned by the NetworkTestCase fixture.
_MTU = 1500
# Ethernet (14) + minimum IPv4 header (20, no options).
_ETH_IP4_HDR = 34


class TestUdpIp4Fragmentation(UdpTestCase):
    """
    A UDP datagram larger than the link MTU is fragmented, not
    silently dropped.
    """

    @override
    def setUp(self) -> None:
        """
        Bind an IPv4 UdpSocket on the canonical fixture address so
        'sendto' has a stack-known local address / port to source
        from.
        """

        super().setUp()
        self._socket = self._bind_udp_socket(
            family=AddressFamily.INET4,
            local_ip=_STACK_IP4,
            local_port=_LOCAL_PORT,
        )

    def test__udp__ip4__oversized_datagram_is_fragmented(self) -> None:
        """
        Ensure a UDP 'sendto' whose datagram exceeds the link MTU
        is IPv4-fragmented and emitted on the wire, with the full
        payload length reported to the caller, instead of being
        silently discarded with a zero return.

        Reference: RFC 791 §2.3 (Fragmentation and reassembly).
        Reference: RFC 1122 §3.3.3 (Fragmentation - host MUST be
        able to send a datagram larger than the link MTU).
        """

        payload = b"M" * 4000

        sent = self._socket.sendto(payload, (str(_HOST_A_IP4), _REMOTE_PORT))

        self.assertEqual(
            sent,
            len(payload),
            msg="sendto() must report the full payload length, not 0, "
            "for an over-MTU datagram (it must fragment, not drop).",
        )

        self.assertGreaterEqual(
            len(self._frames_tx),
            2,
            msg="An over-MTU UDP datagram must be split into multiple "
            "IPv4 fragments, not dropped (0 frames) or sent oversized.",
        )

        self.assertLessEqual(
            max(len(frame) for frame in self._frames_tx),
            _MTU + 14,
            msg="Every emitted fragment must fit within the link MTU.",
        )

        total_ip_payload = sum(len(frame) - _ETH_IP4_HDR for frame in self._frames_tx)
        self.assertEqual(
            total_ip_payload,
            len(payload) + 8,
            msg="The fragments must together carry exactly the original "
            "UDP datagram (payload + 8-byte UDP header), losing no bytes.",
        )


class TestUdpFragmentationDscp(UdpTestCase):
    """
    A per-socket DSCP / ECN marking is preserved on every IP fragment
    of an over-MTU datagram, not zeroed on the second and later
    fragments.
    """

    def test__udp__ip4__dscp_ecn_preserved_on_every_fragment(self) -> None:
        """
        Ensure an over-MTU IPv4 UDP datagram from a socket carrying
        IP_TOS keeps the DSCP (high 6 bits) and ECN (low 2 bits) on
        every emitted fragment, not just the first.

        Reference: RFC 2474 §3 (DS field marking preserved per fragment).
        Reference: RFC 791 §2.3 (each fragment is an independent datagram).
        """

        sock = self._bind_udp_socket(
            family=AddressFamily.INET4,
            local_ip=_STACK_IP4,
            local_port=_LOCAL_PORT,
        )
        sock.setsockopt(IPPROTO_IP, IP_TOS, (46 << 2) | 2)

        sock.sendto(b"M" * 4000, (str(_HOST_A_IP4), _REMOTE_PORT))

        self.assertGreaterEqual(len(self._frames_tx), 2, msg="Datagram must fragment into 2+ frames.")
        for index, frame in enumerate(self._frames_tx):
            # IPv4 TOS byte: Ethernet(14) + IPv4 byte 1.
            tos = frame[15]
            self.assertEqual(
                tos >> 2,
                46,
                msg=f"Fragment {index} must carry DSCP 46 in its IPv4 TOS byte.",
            )
            self.assertEqual(
                tos & 0x03,
                2,
                msg=f"Fragment {index} must carry ECN 2 in its IPv4 TOS byte.",
            )

    def test__udp__ip6__dscp_ecn_preserved_on_every_fragment(self) -> None:
        """
        Ensure an over-MTU IPv6 UDP datagram from a socket carrying
        IPV6_TCLASS keeps the DSCP and ECN on the outer IPv6 header of
        every emitted fragment.

        Reference: RFC 2474 §3 (DS field marking preserved per fragment).
        Reference: RFC 8200 §4.5 (IPv6 fragmentation).
        """

        sock = self._bind_udp_socket(
            family=AddressFamily.INET6,
            local_ip=STACK__IP6_HOST.address,
            local_port=_LOCAL_PORT,
        )
        sock.setsockopt(IPPROTO_IPV6, IPV6_TCLASS, (46 << 2) | 2)

        sock.sendto(b"M" * 4000, (str(HOST_A__IP6_ADDRESS), _REMOTE_PORT))

        self.assertGreaterEqual(len(self._frames_tx), 2, msg="Datagram must fragment into 2+ frames.")
        for index, frame in enumerate(self._frames_tx):
            # IPv6 Traffic Class: Ethernet(14) + low nibble of byte 0
            # and high nibble of byte 1.
            tclass = ((frame[14] & 0x0F) << 4) | (frame[15] >> 4)
            self.assertEqual(
                tclass >> 2,
                46,
                msg=f"Fragment {index} must carry DSCP 46 in its IPv6 Traffic Class.",
            )
            self.assertEqual(
                tclass & 0x03,
                2,
                msg=f"Fragment {index} must carry ECN 2 in its IPv6 Traffic Class.",
            )


class TestUdpSendtoArpQueued(UdpTestCase):
    """
    'sendto' reports success when the datagram is queued
    pending ARP resolution (not just when it hits the wire).
    """

    @override
    def setUp(self) -> None:
        """
        Bind an IPv4 UdpSocket on the canonical fixture address.
        """

        super().setUp()
        self._socket = self._bind_udp_socket(
            family=AddressFamily.INET4,
            local_ip=_STACK_IP4,
            local_port=_LOCAL_PORT,
        )

    def test__udp__sendto_reports_success_when_arp_queued(self) -> None:
        """
        Ensure 'sendto' to a destination whose MAC is not yet
        resolved returns the full payload length — the datagram
        is accepted into the per-neighbour pending queue and
        delivered on ARP resolution, so the caller must see
        success, not a zero (failed) return.

        Reference: RFC 1122 §2.3.2.2 (save unresolved packets, transmit on resolution).
        """

        sent = self._socket.sendto(b"hello", (str(_HOST_B_IP4), _REMOTE_PORT))

        self.assertEqual(
            sent,
            len(b"hello"),
            msg="sendto() must report the full length once the datagram is " "accepted (queued pending ARP), not 0.",
        )
