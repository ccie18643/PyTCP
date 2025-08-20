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
# tests/tcp_phtx.py -  tests specific for TCP phtx module
#
# ver 3.0.2
#


from tests__legacy.unit.mock_network import (
    MockNetworkSettings,
    patch_config,
    setup_mock_packet_handler,
)
from testslide import TestCase

from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus

TEST_FRAME_DIR = "tests__legacy/unit/test_frames/tcp_phtx/"


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
        self.frame_tx: bytearray

    # Test name format: 'test_name__test_description__optional_condition'

    def test_tcp_phtx__ip4_tcp_packet(self) -> None:
        """
        Test sending the IPv4/TCP packet.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip4_host.address,
            ip__dst=self.mns.host_a_ip4_address,
            tcp__sport=1000,
            tcp__dport=2000,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip4_tcp_packet__seq(self) -> None:
        """
        Test sending the IPv4/TCP packet with set 'seq' field.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip4_host.address,
            ip__dst=self.mns.host_a_ip4_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__seq=12345,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__seq.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip4_tcp_packet__ack(self) -> None:
        """
        Test sending the IPv4/TCP packet with set 'ack' field.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip4_host.address,
            ip__dst=self.mns.host_a_ip4_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__ack=12345,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__ack.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip4_tcp_packet__ns(self) -> None:
        """
        Test sending Ithe Pv4/TCP packet with set 'flag_ns' field.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip4_host.address,
            ip__dst=self.mns.host_a_ip4_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__flag_ns=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_ns=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__flag_ns.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip4_tcp_packet__flag_cwr(self) -> None:
        """
        Test sending the IPv4/TCP packet with set 'flag_cwr' field.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip4_host.address,
            ip__dst=self.mns.host_a_ip4_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__flag_cwr=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_cwr=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__flag_cwr.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip4_tcp_packet__flag_ece(self) -> None:
        """
        Test sending the IPv4/TCP packet with set 'flag_ece' field.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip4_host.address,
            ip__dst=self.mns.host_a_ip4_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__flag_ece=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_ece=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__flag_ece.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip4_tcp_packet__flag_urg(self) -> None:
        """
        Test sending the IPv4/TCP packet with set 'flag_urg' field.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip4_host.address,
            ip__dst=self.mns.host_a_ip4_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__flag_urg=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_urg=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__flag_urg.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip4_tcp_packet__flag_ack(self) -> None:
        """
        Test sending the IPv4/TCP packet with set 'flag_ack' field.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip4_host.address,
            ip__dst=self.mns.host_a_ip4_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__flag_ack=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_ack=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__flag_ack.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip4_tcp_packet__flag_psh(self) -> None:
        """
        Test sending the IPv4/TCP packet with set 'flag_psh' field.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip4_host.address,
            ip__dst=self.mns.host_a_ip4_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__flag_psh=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_psh=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__flag_psh.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip4_tcp_packet__flag_rst(self) -> None:
        """
        Test sending the IPv4/TCP packet with set 'flag_rst' field.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip4_host.address,
            ip__dst=self.mns.host_a_ip4_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__flag_rst=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_rst=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__flag_rst.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip4_tcp_packet__flag_syn(self) -> None:
        """
        Test sending the IPv4/TCP packet with set 'flag_syn' field.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip4_host.address,
            ip__dst=self.mns.host_a_ip4_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__flag_syn=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_syn=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__flag_syn.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip4_tcp_packet__win(self) -> None:
        """
        Test sending the IPv4/TCP packet with set 'win' field.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip4_host.address,
            ip__dst=self.mns.host_a_ip4_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__win=12345,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__win.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip4_tcp_packet__urg(self) -> None:
        """
        Test sending the IPv4/TCP packet with set 'urg' field.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip4_host.address,
            ip__dst=self.mns.host_a_ip4_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__urg=12345,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__urg.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_udp_phtx__ip4_tcp_packet__data(self) -> None:
        """
        Test sending the IPv4/TCPP packet with data.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip4_host.address,
            ip__dst=self.mns.host_a_ip4_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__payload=b"01234567890ABCDEF" * 50,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__data.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip4_tcp_packet__ip6_src(self) -> None:
        """Test sending IPv4/tcp packet with src set to ip6 address"""

        with self.assertRaises(ValueError) as error:
            self.packet_handler._phtx_tcp(
                ip__src=self.mns.stack_ip6_host.address,
                ip__dst=self.mns.host_a_ip4_address,
                tcp__sport=1000,
                tcp__dport=2000,
            )

        self.assertEqual(
            str(error.exception),
            (
                "Invalid IP address version combination: "
                f"{self.mns.stack_ip6_host.address} -> {self.mns.host_a_ip4_address}"
            ),
        )

    def test_tcp_phtx__ip4_tcp_packet__ip6_dst(self) -> None:
        """Test sending IPv4/tcp packet with dst set to ip6 address"""

        with self.assertRaises(ValueError) as error:
            self.packet_handler._phtx_tcp(
                ip__src=self.mns.stack_ip4_host.address,
                ip__dst=self.mns.host_a_ip6_address,
                tcp__sport=1000,
                tcp__dport=2000,
            )

        self.assertEqual(
            str(error.exception),
            (
                "Invalid IP address version combination: "
                f"{self.mns.stack_ip4_host.address} -> {self.mns.host_a_ip6_address}"
            ),
        )

    def test_tcp_phtx__ip4_tcp_packet__mss(self) -> None:
        """
        Test sending Ithe Pv4/TCP packet with 'MSS' option.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip4_host.address,
            ip__dst=self.mns.host_a_ip4_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__mss=12345,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__opt_mss=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__mss.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip4_tcp_packet__wscale(self) -> None:
        """
        Test sending the IPv4/TCP packet with 'WSCALE' option.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip4_host.address,
            ip__dst=self.mns.host_a_ip4_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__wscale=14,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__opt_nop=1,
                tcp__opt_wscale=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_tcp_packet__wscale.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet(self) -> None:
        """
        Test sending the IPv6/TCP packet.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip6_host.address,
            ip__dst=self.mns.host_a_ip6_address,
            tcp__sport=1000,
            tcp__dport=2000,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet__seq(self) -> None:
        """
        Test sending the IPv6/TCP packet with set 'seq' field.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip6_host.address,
            ip__dst=self.mns.host_a_ip6_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__seq=12345,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet__seq.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet__ack(self) -> None:
        """
        Test sending the IPv6/TCP packet with set 'ack' field.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip6_host.address,
            ip__dst=self.mns.host_a_ip6_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__ack=12345,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet__ack.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet__ns(self) -> None:
        """
        Test sending the IPv6/TCP packet with set 'flag_ns' field.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip6_host.address,
            ip__dst=self.mns.host_a_ip6_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__flag_ns=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_ns=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet__flag_ns.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet__flag_cwr(self) -> None:
        """
        Test sending the IPv6/TCP packet with set 'flag_cwr' field.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip6_host.address,
            ip__dst=self.mns.host_a_ip6_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__flag_cwr=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_cwr=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet__flag_cwr.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet__flag_ece(self) -> None:
        """
        Test sending the IPv6/TCP packet with set 'flag_ece' field.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip6_host.address,
            ip__dst=self.mns.host_a_ip6_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__flag_ece=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_ece=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet__flag_ece.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet__flag_urg(self) -> None:
        """
        Test sending the IPv6/TCP packet with set 'flag_urg' field.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip6_host.address,
            ip__dst=self.mns.host_a_ip6_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__flag_urg=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_urg=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet__flag_urg.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet__flag_ack(self) -> None:
        """
        Test sending the IPv6/TCP packet with set 'flag_ack' field.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip6_host.address,
            ip__dst=self.mns.host_a_ip6_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__flag_ack=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_ack=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet__flag_ack.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet__flag_psh(self) -> None:
        """
        Test sending the IPv6/TCP packet with set 'flag_psh' field.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip6_host.address,
            ip__dst=self.mns.host_a_ip6_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__flag_psh=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_psh=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet__flag_psh.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet__flag_rst(self) -> None:
        """
        Test sending the IPv6/TCP packet with set 'flag_rst' field.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip6_host.address,
            ip__dst=self.mns.host_a_ip6_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__flag_rst=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_rst=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet__flag_rst.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet__flag_syn(self) -> None:
        """
        Test sending the IPv6/TCP packet with set 'flag_syn' field.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip6_host.address,
            ip__dst=self.mns.host_a_ip6_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__flag_syn=True,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_syn=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet__flag_syn.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet__win(self) -> None:
        """
        Test sending the IPv6/TCP packet with set 'win' field.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip6_host.address,
            ip__dst=self.mns.host_a_ip6_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__win=12345,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet__win.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet__urg(self) -> None:
        """
        Test sending the IPv6/TCP packet with set 'urg' field.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip6_host.address,
            ip__dst=self.mns.host_a_ip6_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__urg=12345,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet__urg.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet__data(self) -> None:
        """
        Test sending the IPv6/TCP packet with data.
        """
        tx_status = self.packet_handler._phtx_tcp(
            ip__src=self.mns.stack_ip6_host.address,
            ip__dst=self.mns.host_a_ip6_address,
            tcp__sport=1000,
            tcp__dport=2000,
            tcp__payload=b"01234567890ABCDEF" * 50,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_tcp_packet__data.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_tcp_phtx__ip6_tcp_packet__ip4_src(self) -> None:
        """Test sending IPv6/tcp packet with src set to ip4 address"""

        with self.assertRaises(ValueError) as error:
            self.packet_handler._phtx_tcp(
                ip__src=self.mns.stack_ip4_host.address,
                ip__dst=self.mns.host_a_ip6_address,
                tcp__sport=1000,
                tcp__dport=2000,
            )

        self.assertEqual(
            str(error.exception),
            (
                "Invalid IP address version combination: "
                f"{self.mns.stack_ip4_host.address} -> {self.mns.host_a_ip6_address}"
            ),
        )

    def test_tcp_phtx__ip6_tcp_packet__ip4_dst(self) -> None:
        """Test sending IPv6/tcp packet with dst set to ip4 address"""

        with self.assertRaises(ValueError) as error:
            self.packet_handler._phtx_tcp(
                ip__src=self.mns.stack_ip6_host.address,
                ip__dst=self.mns.host_a_ip4_address,
                tcp__sport=1000,
                tcp__dport=2000,
            )

        self.assertEqual(
            str(error.exception),
            (
                "Invalid IP address version combination: "
                f"{self.mns.stack_ip6_host.address} -> {self.mns.host_a_ip4_address}"
            ),
        )
