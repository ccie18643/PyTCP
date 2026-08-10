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
This module contains integration tests for the Packet Handler Ethernet RX operations.

pytcp/tests/integration/protocols/ethernet/test__ethernet__rx.py

ver 3.0.10
"""

from typing import override

from net_proto.lib.packet_rx import PacketRx
from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx
from pytcp.tests.lib.ethernet_testcase import EthernetTestCase
from pytcp.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Ethernet - dst unknown",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:99:99:99 (not in our table)
                #   Source MAC      : 52:54:00:df:85:37
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 14 bytes (header-only)
                #
                # Summary: Header-only Ethernet II frame with EtherType 0x0800 (IPv4)
                #          to an unknown MAC; classifier drops it before dispatch.
                b"\x02\x00\x00\x99\x99\x99\x52\x54\x00\xdf\x85\x37\x08\x00",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unknown__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet - malformed header",
            "_frames_rx": [
                # Ethernet II (truncated)
                #   Destination MAC : 02:00:00:77:77:77
                #   Source MAC      : 52:54:00:df:85:37
                #   Captured length : 13 bytes (shorter than mandatory 14-byte header)
                #
                # Summary: Short Ethernet header without an Ethertype field; parsing fails.
                b"\x02\x00\x00\x77\x77\x77\x52\x54\x00\xdf\x85\x37\x0a",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__failed_parse__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet - dst is our stack unicast MAC, unsupported ethertype dropped",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:07 (stack unicast)
                #   Source MAC      : 52:54:00:df:85:37
                #   Ethertype       : 0x88b5 (IEEE Std 802 - Local Experimental — no dispatch)
                #   Frame length    : 14 bytes (header-only)
                #
                # Summary: Header-only frame to our unicast MAC with an ethertype the
                #          stack does not dispatch. Bumps 'dst_unicast' (classifier) and
                #          'no_proto_support__drop' (default match arm).
                b"\x02\x00\x00\x00\x00\x07\x52\x54\x00\xdf\x85\x37\x88\xb5",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ethernet__no_proto_support__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet - dst is our solicited-node multicast MAC, unsupported ethertype dropped",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 33:33:ff:00:00:07 (solicited-node multicast for 2001:db8:0:1::7)
                #   Source MAC      : 52:54:00:df:85:37
                #   Ethertype       : 0x88b5 (IEEE Std 802 - Local Experimental — no dispatch)
                #   Frame length    : 14 bytes (header-only)
                #
                # Summary: Header-only frame to a multicast MAC the stack has joined.
                #          Bumps 'dst_multicast' (classifier) and 'no_proto_support__drop'.
                b"\x33\x33\xff\x00\x00\x07\x52\x54\x00\xdf\x85\x37\x88\xb5",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_multicast=1,
                ethernet__no_proto_support__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet - dst is broadcast MAC, unsupported ethertype dropped",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : ff:ff:ff:ff:ff:ff (broadcast)
                #   Source MAC      : 52:54:00:df:85:37
                #   Ethertype       : 0x88b5 (IEEE Std 802 - Local Experimental — no dispatch)
                #   Frame length    : 14 bytes (header-only)
                #
                # Summary: Header-only broadcast frame with an ethertype the stack
                #          does not dispatch. Bumps 'dst_broadcast' (classifier) and
                #          'no_proto_support__drop'.
                b"\xff\xff\xff\xff\xff\xff\x52\x54\x00\xdf\x85\x37\x88\xb5",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                ethernet__no_proto_support__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
    ]
)
class TestPacketHandlerEthernetRx(EthernetTestCase):
    """
    Test the Packet Handler Ethernet RX operations.
    """

    _description: str
    _frames_rx: list[bytes]
    _expected__frames_tx: list[bytes]
    _expected__packet_stats_rx: PacketStatsRx
    _expected__packet_stats_tx: PacketStatsTx

    _frames_tx: list[bytes]

    def test__packet_handler__ethernet__rx(self) -> None:
        """
        Ensure the Packet Handler processes the received Ethernet
        frames as expected for each parametrized case.

        Reference: RFC 894 (Ethernet II RX dispatch).
        """

        for frame_rx in self._frames_rx:
            self._packet_handler._phrx_ethernet(PacketRx(frame_rx))

        self.assertEqual(
            self._frames_tx,
            self._expected__frames_tx,
            msg=f"Unexpected TX frames for case: {self._description}",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_rx,
            self._expected__packet_stats_rx,
            msg=f"Unexpected RX packet stats for case: {self._description}",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_tx,
            self._expected__packet_stats_tx,
            msg=f"Unexpected TX packet stats for case: {self._description}",
        )


class TestPacketHandlerEthernetRxNoIp4Support(EthernetTestCase):
    """
    Test the Packet Handler Ethernet RX dispatch when IPv4 protocol
    support is disabled — ARP and IPv4 frames must fall into the
    no-protocol-support drop arm instead of dispatching upward.
    """

    @override
    def setUp(self) -> None:
        """
        Build the standard mock stack, then disable IPv4 protocol
        support on the packet handler.
        """

        super().setUp()
        self._packet_handler._ip4_support = False
        # The link-layer dispatch registry caches the support policy at
        # construction; rebuild it so the disabled-IPv4 membership (no
        # ARP, no IPv4) takes effect.
        self._packet_handler._build_ethertype_registry()

    def test__packet_handler__ethernet__rx__arp_dropped_when_ip4_disabled(self) -> None:
        """
        Ensure an ARP frame to our unicast MAC is classified, then
        dropped via 'ethernet__no_proto_support__drop' because the
        ARP dispatch arm is gated on '_ip4_support'.

        Reference: RFC 894 (Ethernet II RX dispatch).
        """

        # Ethernet II
        #   Destination MAC : 02:00:00:00:00:07 (stack unicast)
        #   Source MAC      : 52:54:00:df:85:37
        #   Ethertype       : 0x0806 (ARP)
        #   Frame length    : 14 bytes (header-only — payload would never be parsed)
        #
        # Summary: ARP arriving at our unicast MAC while IPv4 support is off.
        #          Classifier bumps 'dst_unicast'; dispatch falls through the
        #          ARP arm (gated on '_ip4_support') and the IP4 arm (likewise),
        #          landing in 'case _:' which bumps 'no_proto_support__drop'.
        frame_rx = b"\x02\x00\x00\x00\x00\x07\x52\x54\x00\xdf\x85\x37\x08\x06"

        self._packet_handler._phrx_ethernet(PacketRx(frame_rx))

        self.assertEqual(
            self._frames_tx,
            [],
            msg="No frame must be emitted when IPv4 support gates the ARP dispatch.",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_rx,
            PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ethernet__no_proto_support__drop=1,
            ),
            msg="ARP must drop into 'no_proto_support__drop' when IPv4 is disabled.",
        )


class TestPacketHandlerEthernetRxNoIp6Support(EthernetTestCase):
    """
    Test the Packet Handler Ethernet RX dispatch when IPv6 protocol
    support is disabled — IPv6 frames must fall into the
    no-protocol-support drop arm.
    """

    @override
    def setUp(self) -> None:
        """
        Build the standard mock stack, then disable IPv6 protocol
        support on the packet handler.
        """

        super().setUp()
        self._packet_handler._ip6_support = False
        # The link-layer dispatch registry caches the support policy at
        # construction; rebuild it so the disabled-IPv6 membership
        # (no IPv6) takes effect.
        self._packet_handler._build_ethertype_registry()

    def test__packet_handler__ethernet__rx__ip6_dropped_when_ip6_disabled(self) -> None:
        """
        Ensure an IPv6 frame to our unicast MAC is classified, then
        dropped via 'ethernet__no_proto_support__drop' because the
        IPv6 dispatch arm is gated on '_ip6_support'.

        Reference: RFC 894 (Ethernet II RX dispatch).
        """

        # Ethernet II
        #   Destination MAC : 02:00:00:00:00:07 (stack unicast)
        #   Source MAC      : 52:54:00:df:85:37
        #   Ethertype       : 0x86dd (IPv6)
        #   Frame length    : 14 bytes (header-only — payload would never be parsed)
        #
        # Summary: IPv6 frame arriving while IPv6 support is off. Classifier bumps
        #          'dst_unicast'; the IP6 dispatch arm's '_ip6_support' guard fails,
        #          dropping into 'case _:' which bumps 'no_proto_support__drop'.
        frame_rx = b"\x02\x00\x00\x00\x00\x07\x52\x54\x00\xdf\x85\x37\x86\xdd"

        self._packet_handler._phrx_ethernet(PacketRx(frame_rx))

        self.assertEqual(
            self._frames_tx,
            [],
            msg="No frame must be emitted when IPv6 support gates the IP6 dispatch.",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_rx,
            PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ethernet__no_proto_support__drop=1,
            ),
            msg="IPv6 must drop into 'no_proto_support__drop' when IPv6 is disabled.",
        )
