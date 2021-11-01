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
# tests/icmp6_phtx.py -  tests specific for ICMPv6 phtx module
#


from testslide import TestCase

from pytcp.misc.packet_stats import PacketStatsTx
from pytcp.misc.tx_status import TxStatus
from pytcp.protocols.icmp6.fpa import Icmp6NdOptSLLA
from pytcp.protocols.icmp6.ps import (
    ICMP6_ECHO_REPLY,
    ICMP6_ECHO_REQUEST,
    ICMP6_ND_ROUTER_SOLICITATION,
    ICMP6_UNREACHABLE,
    ICMP6_UNREACHABLE__PORT,
)
from tests.mock_network import (
    MockNetworkSettings,
    patch_config,
    setup_mock_packet_handler,
)

TEST_FRAME_DIR = "tests/test_frames/icmp6_phtx/"


class TestIcmp6Phtx(TestCase):
    def setUp(self):
        super().setUp()

        self.mns = MockNetworkSettings()
        patch_config(self)
        setup_mock_packet_handler(self)

    # Test name format: 'test_name__test_description__optional_condition'

    def test_icmp6_phtx__ip6_icmp6_echo_request(self):
        """Test sending IPv6/ICMPv6 Echo request packet"""

        tx_status = self.packet_handler._phtx_icmp6(
            ip6_src=self.mns.stack_ip6_host.address,
            ip6_dst=self.mns.host_a_ip6_address,
            icmp6_type=ICMP6_ECHO_REQUEST,
            icmp6_ec_id=12345,
            icmp6_ec_seq=54320,
            icmp6_ec_data=b"0123456789ABCDEF" * 20,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                icmp6__pre_assemble=1,
                icmp6__echo_request__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip6_lookup=1,
                ether__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_icmp6_echo_request.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_icmp6_phtx__ip6_icmp6_echo_reply(self):
        """Test sending IPv6/ICMPv6 Echo reply packet"""

        tx_status = self.packet_handler._phtx_icmp6(
            ip6_src=self.mns.stack_ip6_host.address,
            ip6_dst=self.mns.host_a_ip6_address,
            icmp6_type=ICMP6_ECHO_REPLY,
            icmp6_ec_id=12345,
            icmp6_ec_seq=54320,
            icmp6_ec_data=b"0123456789ABCDEF" * 20,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                icmp6__pre_assemble=1,
                icmp6__echo_reply__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip6_lookup=1,
                ether__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_icmp6_echo_reply.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_icmp6_phtx__ip6_icmp6_unreachable_port(self):
        """Test sending IPv6/ICMPv6 unreachable port packet"""

        tx_status = self.packet_handler._phtx_icmp6(
            ip6_src=self.mns.stack_ip6_host.address,
            ip6_dst=self.mns.host_a_ip6_address,
            icmp6_type=ICMP6_UNREACHABLE,
            icmp6_code=ICMP6_UNREACHABLE__PORT,
            icmp6_un_data=b"0123456789ABCDEF" * 100,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                icmp6__pre_assemble=1,
                icmp6__unreachable_port__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip6_lookup=1,
                ether__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_icmp6_unreachable_port.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_icmp6_phtx__ip6_icmp6_nd_router_solicitation(self):
        """Test sending IPv6/ICMPv6 ND Router Solicitation packet"""

        tx_status = self.packet_handler._phtx_icmp6(
            ip6_src=self.mns.stack_ip6_host.address,
            ip6_dst=self.mns.ip6_multicast_all_routers,
            ip6_hop=255,
            icmp6_type=ICMP6_ND_ROUTER_SOLICITATION,
            icmp6_nd_options=[Icmp6NdOptSLLA(self.mns.stack_mac_address)],
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                icmp6__pre_assemble=1,
                icmp6__nd_router_solicitation__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip6_lookup=1,
                ether__dst_unspec__ip6_lookup__multicast__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_icmp6_nd_router_solicitation.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)


# ND Router Advertisement test needed

# ND Neighbor Solicitation test needed

# ND Neighbor Advertisement test needed
