#!/usr/bin/env python3


############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


#
# tests/udp_phtx.py -  tests specific for UDP phtx module
#
# ver 2.7
#


from testslide import TestCase

from pytcp.misc.packet_stats import PacketStatsTx
from pytcp.misc.tx_status import TxStatus
from tests.unit.mock_network import (
    MockNetworkSettings,
    patch_config,
    setup_mock_packet_handler,
)

TEST_FRAME_DIR = "tests/unit/test_frames/udp_phtx/"


class TestUdpPhtx(TestCase):
    """
    UDP packet handler TX unit test class.
    """

    def setUp(self) -> None:
        """
        Set up the test environment.
        """
        super().setUp()
        self.mns = MockNetworkSettings()
        patch_config(self)
        setup_mock_packet_handler(self)

    # Test name format: 'test_name__test_description__optional_condition'

    def test_udp_phtx__ip4_udp_packet(self) -> None:
        """
        Test sending the IPv4/UDP packet with no data.
        """

        tx_status = self.packet_handler._phtx_udp(
            ip_src=self.mns.stack_ip4_host.address,
            ip_dst=self.mns.host_a_ip4_address,
            udp_sport=1000,
            udp_dport=2000,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                udp__pre_assemble=1,
                udp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_udp_packet.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_udp_phtx__ip4_udp_packet__data(self) -> None:
        """Test sending IPv4/UDP packet with data"""

        tx_status = self.packet_handler._phtx_udp(
            ip_src=self.mns.stack_ip4_host.address,
            ip_dst=self.mns.host_a_ip4_address,
            udp_sport=1000,
            udp_dport=2000,
            udp_data=b"01234567890ABCDEF" * 50,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                udp__pre_assemble=1,
                udp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_udp_packet__data.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_udp_phtx__ip4_udp_packet__ip6_src(self) -> None:
        """Test sending IPv4/UDP packet with src set to ip6 address"""

        tx_status = self.packet_handler._phtx_udp(
            ip_src=self.mns.stack_ip6_host.address,
            ip_dst=self.mns.host_a_ip4_address,
            udp_sport=1000,
            udp_dport=2000,
        )
        self.assertEqual(tx_status, TxStatus.DROPED__UDP__UNKNOWN)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                udp__pre_assemble=1,
                udp__unknown__drop=1,
            ),
        )

    def test_udp_phtx__ip4_udp_packet__ip6_dst(self) -> None:
        """Test sending IPv6/UDP packet with dst set to ip4 address"""

        tx_status = self.packet_handler._phtx_udp(
            ip_src=self.mns.stack_ip4_host.address,
            ip_dst=self.mns.host_a_ip6_address,
            udp_sport=1000,
            udp_dport=2000,
        )
        self.assertEqual(tx_status, TxStatus.DROPED__UDP__UNKNOWN)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                udp__pre_assemble=1,
                udp__unknown__drop=1,
            ),
        )

    def test_udp_phtx__ip6_udp_packet(self) -> None:
        """Test sending IPv6/UDP packet with no data"""

        tx_status = self.packet_handler._phtx_udp(
            ip_src=self.mns.stack_ip6_host.address,
            ip_dst=self.mns.host_a_ip6_address,
            udp_sport=1000,
            udp_dport=2000,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                udp__pre_assemble=1,
                udp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip6_lookup=1,
                ether__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_udp_packet.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_udp_phtx__ip6_udp_packet__data(self) -> None:
        """Test sending IPv6/UDP packet with data"""

        tx_status = self.packet_handler._phtx_udp(
            ip_src=self.mns.stack_ip6_host.address,
            ip_dst=self.mns.host_a_ip6_address,
            udp_sport=1000,
            udp_dport=2000,
            udp_data=b"01234567890ABCDEF" * 50,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                udp__pre_assemble=1,
                udp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip6_lookup=1,
                ether__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_udp_packet__data.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_udp_phtx__ip6_udp_packet__ip4_src(self) -> None:
        """Test sending IPv6/UDP packet with src set to ip4 address"""

        tx_status = self.packet_handler._phtx_udp(
            ip_src=self.mns.stack_ip4_host.address,
            ip_dst=self.mns.host_a_ip6_address,
            udp_sport=1000,
            udp_dport=2000,
        )
        self.assertEqual(tx_status, TxStatus.DROPED__UDP__UNKNOWN)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                udp__pre_assemble=1,
                udp__unknown__drop=1,
            ),
        )

    def test_udp_phtx__ip6_udp_packet__ip4_dst(self) -> None:
        """Test sending IPv6/UDP packet with dst set to ip4 address"""

        tx_status = self.packet_handler._phtx_udp(
            ip_src=self.mns.stack_ip6_host.address,
            ip_dst=self.mns.host_a_ip4_address,
            udp_sport=1000,
            udp_dport=2000,
        )
        self.assertEqual(tx_status, TxStatus.DROPED__UDP__UNKNOWN)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                udp__pre_assemble=1,
                udp__unknown__drop=1,
            ),
        )


# TODO: Need to test sending UDP packets with all-zeroes
# TODO: src ipv4 address for DHCP
