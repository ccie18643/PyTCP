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
This module contains integration tests for the Packet Handler Ethernet 802.3 RX operations.

pytcp/tests/integration/protocols/ethernet_802_3/test__ethernet_802_3__rx.py

ver 3.0.10
"""

from net_proto.lib.packet_rx import PacketRx
from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx
from pytcp.tests.lib.ethernet_802_3_testcase import Ethernet8023TestCase
from pytcp.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Ethernet 802.3 - dst unknown",
            "_frames_rx": [
                # Ethernet 802.3
                #   Destination MAC : 02:00:00:99:99:99 (foreign)
                #   Source MAC      : 52:54:00:df:85:37
                #   Length          : 0x0000 (no LLC payload — header-only frame)
                #
                # Summary: Header-only 802.3 frame addressed to an unknown MAC; parser
                #          accepts the frame, classifier drops it as unknown-dst.
                b"\x02\x00\x00\x99\x99\x99\x52\x54\x00\xdf\x85\x37\x00\x00",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet_802_3__pre_parse=1,
                ethernet_802_3__dst_unknown__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet 802.3 - malformed header",
            "_frames_rx": [
                # Ethernet 802.3
                #   Destination MAC : 02:00:00:77:77:77 (foreign)
                #   Source MAC      : 52:54:00:df:85:37
                #   Length          : <missing byte> (frame too short)
                #
                # Summary: Malformed Ethernet 802.3 header (length field truncated) triggers parse drop.
                b"\x02\x00\x00\x77\x77\x77\x52\x54\x00\xdf\x85\x37\x00",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet_802_3__pre_parse=1,
                ethernet_802_3__failed_parse__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet 802.3 - dst is our stack unicast MAC, accepted; LLC parse fails on empty payload",
            "_frames_rx": [
                # Ethernet 802.3
                #   Destination MAC : 02:00:00:00:00:07 (stack unicast)
                #   Source MAC      : 52:54:00:df:85:37
                #   Length          : 0x0000 (no LLC payload — header-only frame)
                #
                # Summary: Header-only 802.3 frame addressed to the stack unicast MAC.
                #          MAC filter accepts; LLC parser then fails on the empty
                #          payload (no room for the 3-byte LLC header).
                b"\x02\x00\x00\x00\x00\x07\x52\x54\x00\xdf\x85\x37\x00\x00",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet_802_3__pre_parse=1,
                ethernet_802_3__dst_unicast=1,
                ethernet_802_3__llc_failed_parse__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet 802.3 - dst is solicited-node multicast MAC; LLC fails on empty payload",
            "_frames_rx": [
                # Ethernet 802.3
                #   Destination MAC : 33:33:ff:00:00:07 (solicited-node multicast for 2001:db8:0:1::7)
                #   Source MAC      : 52:54:00:df:85:37
                #   Length          : 0x0000 (no LLC payload — header-only frame)
                #
                # Summary: Header-only 802.3 frame addressed to a multicast MAC the
                #          stack has joined. MAC filter accepts; LLC parser then
                #          fails on the empty payload.
                b"\x33\x33\xff\x00\x00\x07\x52\x54\x00\xdf\x85\x37\x00\x00",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet_802_3__pre_parse=1,
                ethernet_802_3__dst_multicast=1,
                ethernet_802_3__llc_failed_parse__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet 802.3 - dst is a multicast MAC we have not joined, drop",
            "_frames_rx": [
                # Ethernet 802.3
                #   Destination MAC : 33:33:00:00:00:02 (IPv6 all-routers — not joined by stack)
                #   Source MAC      : 52:54:00:df:85:37
                #   Length          : 0x0000 (no LLC payload — header-only frame)
                #
                # Summary: Multicast frame for a group the stack is not a member of.
                #          Falls into the unknown-dst path (multicast MAC not in '_mac_multicast').
                b"\x33\x33\x00\x00\x00\x02\x52\x54\x00\xdf\x85\x37\x00\x00",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet_802_3__pre_parse=1,
                ethernet_802_3__dst_unknown__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet 802.3 - dst is broadcast MAC, accepted; LLC parse fails on empty payload",
            "_frames_rx": [
                # Ethernet 802.3
                #   Destination MAC : ff:ff:ff:ff:ff:ff (broadcast)
                #   Source MAC      : 52:54:00:df:85:37
                #   Length          : 0x0000 (no LLC payload — header-only frame)
                #
                # Summary: Header-only 802.3 broadcast frame. MAC filter accepts; LLC
                #          parser then fails on the empty payload.
                b"\xff\xff\xff\xff\xff\xff\x52\x54\x00\xdf\x85\x37\x00\x00",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet_802_3__pre_parse=1,
                ethernet_802_3__dst_broadcast=1,
                ethernet_802_3__llc_failed_parse__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
    ]
)
class TestPacketHandlerEthernet8023Rx(Ethernet8023TestCase):
    """
    Test the Packet Handler Ethernet 802.3 RX operations.
    """

    _description: str
    _frames_rx: list[bytes]
    _expected__frames_tx: list[bytes]
    _expected__packet_stats_rx: PacketStatsRx
    _expected__packet_stats_tx: PacketStatsTx

    _frames_tx: list[bytes]

    def test__packet_handler__ethernet_802_3__rx(self) -> None:
        """
        Ensure the Packet Handler processes the received Ethernet
        802.3 frames as expected for each parametrized case.

        Reference: IEEE 802.3 §3 (802.3 RX dispatch).
        """

        for frame_rx in self._frames_rx:
            self._packet_handler._phrx_ethernet_802_3(PacketRx(frame_rx))

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
