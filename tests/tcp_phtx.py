#!/usr/bin/env python3


############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-2021  Sebastian Majewski                             #
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

from __future__ import annotations  # Required by Python ver < 3.10

from testslide import TestCase

from pytcp.misc.packet_stats import PacketStatsTx
from pytcp.misc.tx_status import TxStatus
from tests.mock_network import (
    MockNetworkSettings,
    patch_config,
    setup_mock_packet_handler,
)

TEST_FRAME_DIR = "tests/test_frames/tcp_phtx/"


class TestUdpPhtx(TestCase):
    def setUp(self):
        super().setUp()

        self.mns = MockNetworkSettings()
        patch_config(self)
        setup_mock_packet_handler(self)

    # Test name format: 'test_name__test_description__optional_condition'

    def test_tcp_phtx__ip4_tcp_packet(self):
        """Test sending IPv4/TCP packet"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip4_host.address,
            ip_dst=self.mns.host_a_ip4_address,
            tcp_sport=1000,
            tcp_dport=2000,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip4_tcp_packet__seq(self):
        """Test sending IPv4/TCP packet with set seq field"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip4_host.address,
            ip_dst=self.mns.host_a_ip4_address,
            tcp_sport=1000,
            tcp_dport=2000,
            tcp_seq=12345,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__seq.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip4_tcp_packet__ack(self):
        """Test sending IPv4/TCP packet with set ack field"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip4_host.address,
            ip_dst=self.mns.host_a_ip4_address,
            tcp_sport=1000,
            tcp_dport=2000,
            tcp_ack=12345,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__ack.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip4_tcp_packet__ns(self):
        """Test sending IPv4/TCP packet with set flag_ns field"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip4_host.address,
            ip_dst=self.mns.host_a_ip4_address,
            tcp_sport=1000,
            tcp_dport=2000,
            tcp_flag_ns=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_ns=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__flag_ns.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip4_tcp_packet__flag_crw(self):
        """Test sending IPv4/TCP packet with set flag_crw field"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip4_host.address,
            ip_dst=self.mns.host_a_ip4_address,
            tcp_sport=1000,
            tcp_dport=2000,
            tcp_flag_crw=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_crw=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__flag_crw.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip4_tcp_packet__flag_ece(self):
        """Test sending IPv4/TCP packet with set flag_ece field"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip4_host.address,
            ip_dst=self.mns.host_a_ip4_address,
            tcp_sport=1000,
            tcp_dport=2000,
            tcp_flag_ece=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_ece=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__flag_ece.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip4_tcp_packet__flag_urg(self):
        """Test sending IPv4/TCP packet with set flag_urg field"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip4_host.address,
            ip_dst=self.mns.host_a_ip4_address,
            tcp_sport=1000,
            tcp_dport=2000,
            tcp_flag_urg=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_urg=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__flag_urg.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip4_tcp_packet__flag_ack(self):
        """Test sending IPv4/TCP packet with set flag_ack field"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip4_host.address,
            ip_dst=self.mns.host_a_ip4_address,
            tcp_sport=1000,
            tcp_dport=2000,
            tcp_flag_ack=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_ack=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__flag_ack.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip4_tcp_packet__flag_psh(self):
        """Test sending IPv4/TCP packet with set flag_psh field"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip4_host.address,
            ip_dst=self.mns.host_a_ip4_address,
            tcp_sport=1000,
            tcp_dport=2000,
            tcp_flag_psh=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_psh=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__flag_psh.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip4_tcp_packet__flag_rst(self):
        """Test sending IPv4/TCP packet with set flag_rst field"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip4_host.address,
            ip_dst=self.mns.host_a_ip4_address,
            tcp_sport=1000,
            tcp_dport=2000,
            tcp_flag_rst=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_rst=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__flag_rst.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip4_tcp_packet__flag_syn(self):
        """Test sending IPv4/TCP packet with set flag_syn field"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip4_host.address,
            ip_dst=self.mns.host_a_ip4_address,
            tcp_sport=1000,
            tcp_dport=2000,
            tcp_flag_syn=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_syn=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__flag_syn.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip4_tcp_packet__win(self):
        """Test sending IPv4/TCP packet with set win field"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip4_host.address,
            ip_dst=self.mns.host_a_ip4_address,
            tcp_sport=1000,
            tcp_dport=2000,
            tcp_win=12345,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__win.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip4_tcp_packet__urp(self):
        """Test sending IPv4/TCP packet with set urp field"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip4_host.address,
            ip_dst=self.mns.host_a_ip4_address,
            tcp_sport=1000,
            tcp_dport=2000,
            tcp_urp=12345,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__urp.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_udp_phtx__ip4_tcp_packet__data(self):
        """Test sending IPv4/TCPP packet with data"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip4_host.address, ip_dst=self.mns.host_a_ip4_address, tcp_sport=1000, tcp_dport=2000, tcp_data=b"01234567890ABCDEF" * 50
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__data.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet(self):
        """Test sending IPv6/TCP packet"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip6_host.address,
            ip_dst=self.mns.host_a_ip6_address,
            tcp_sport=1000,
            tcp_dport=2000,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip6_lookup=1,
                ether__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet__seq(self):
        """Test sending IPv6/TCP packet with set seq field"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip6_host.address,
            ip_dst=self.mns.host_a_ip6_address,
            tcp_sport=1000,
            tcp_dport=2000,
            tcp_seq=12345,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip6_lookup=1,
                ether__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet__seq.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet__ack(self):
        """Test sending IPv6/TCP packet with set ack field"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip6_host.address,
            ip_dst=self.mns.host_a_ip6_address,
            tcp_sport=1000,
            tcp_dport=2000,
            tcp_ack=12345,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip6_lookup=1,
                ether__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet__ack.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet__ns(self):
        """Test sending IPv6/TCP packet with set flag_ns field"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip6_host.address,
            ip_dst=self.mns.host_a_ip6_address,
            tcp_sport=1000,
            tcp_dport=2000,
            tcp_flag_ns=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_ns=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip6_lookup=1,
                ether__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet__flag_ns.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet__flag_crw(self):
        """Test sending IPv6/TCP packet with set flag_crw field"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip6_host.address,
            ip_dst=self.mns.host_a_ip6_address,
            tcp_sport=1000,
            tcp_dport=2000,
            tcp_flag_crw=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_crw=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip6_lookup=1,
                ether__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet__flag_crw.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet__flag_ece(self):
        """Test sending IPv6/TCP packet with set flag_ece field"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip6_host.address,
            ip_dst=self.mns.host_a_ip6_address,
            tcp_sport=1000,
            tcp_dport=2000,
            tcp_flag_ece=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_ece=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip6_lookup=1,
                ether__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet__flag_ece.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet__flag_urg(self):
        """Test sending IPv6/TCP packet with set flag_urg field"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip6_host.address,
            ip_dst=self.mns.host_a_ip6_address,
            tcp_sport=1000,
            tcp_dport=2000,
            tcp_flag_urg=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_urg=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip6_lookup=1,
                ether__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet__flag_urg.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet__flag_ack(self):
        """Test sending IPv6/TCP packet with set flag_ack field"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip6_host.address,
            ip_dst=self.mns.host_a_ip6_address,
            tcp_sport=1000,
            tcp_dport=2000,
            tcp_flag_ack=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_ack=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip6_lookup=1,
                ether__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet__flag_ack.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet__flag_psh(self):
        """Test sending IPv6/TCP packet with set flag_psh field"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip6_host.address,
            ip_dst=self.mns.host_a_ip6_address,
            tcp_sport=1000,
            tcp_dport=2000,
            tcp_flag_psh=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_psh=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip6_lookup=1,
                ether__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet__flag_psh.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet__flag_rst(self):
        """Test sending IPv6/TCP packet with set flag_rst field"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip6_host.address,
            ip_dst=self.mns.host_a_ip6_address,
            tcp_sport=1000,
            tcp_dport=2000,
            tcp_flag_rst=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_rst=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip6_lookup=1,
                ether__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet__flag_rst.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet__flag_syn(self):
        """Test sending IPv6/TCP packet with set flag_syn field"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip6_host.address,
            ip_dst=self.mns.host_a_ip6_address,
            tcp_sport=1000,
            tcp_dport=2000,
            tcp_flag_syn=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_syn=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip6_lookup=1,
                ether__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet__flag_syn.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet__win(self):
        """Test sending IPv6/TCP packet with set win field"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip6_host.address,
            ip_dst=self.mns.host_a_ip6_address,
            tcp_sport=1000,
            tcp_dport=2000,
            tcp_win=12345,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip6_lookup=1,
                ether__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet__win.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet__urp(self):
        """Test sending IPv6/TCP packet with set urp field"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip6_host.address,
            ip_dst=self.mns.host_a_ip6_address,
            tcp_sport=1000,
            tcp_dport=2000,
            tcp_urp=12345,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip6_lookup=1,
                ether__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet__urp.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_udp_phtx__ip6_tcp_packet__data(self):
        """Test sending IPv6/TCP packet with data"""

        tx_status = self.packet_handler._phtx_tcp(
            ip_src=self.mns.stack_ip6_host.address, ip_dst=self.mns.host_a_ip6_address, tcp_sport=1000, tcp_dport=2000, tcp_data=b"01234567890ABCDEF" * 50
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip6_lookup=1,
                ether__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet__data.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)
