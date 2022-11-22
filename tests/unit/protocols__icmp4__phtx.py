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
# tests/icmp4_phtx.py -  tests specific for ICMPv4 phtx module
#
# ver 2.7
#


from testslide import TestCase

from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.icmp4.ps import (
    ICMP4_ECHO_REPLY,
    ICMP4_ECHO_REQUEST,
    ICMP4_UNREACHABLE,
    ICMP4_UNREACHABLE__PORT,
)
from tests.unit.mock_network import (
    MockNetworkSettings,
    patch_config,
    setup_mock_packet_handler,
)

TEST_FRAME_DIR = "tests/unit/test_frames/icmp4_phtx/"


class TestIcmp4Phtx(TestCase):
    """
    ICMPv4 packet handler TX unit test class.
    """

    def setUp(self) -> None:
        """
        Test setup.
        """
        super().setUp()
        self.mns = MockNetworkSettings()
        patch_config(self)
        setup_mock_packet_handler(self)

    # Test name format: 'test_name__test_description__optional_condition'

    def test_icmp4_phtx__ip4_icmp4_echo_request(self) -> None:
        """
        Test sending the IPv4/ICMPv4 'Echo Request' packet.
        """

        tx_status = self.packet_handler._phtx_icmp4(
            ip4_src=self.mns.stack_ip4_host.address,
            ip4_dst=self.mns.host_a_ip4_address,
            icmp4_type=ICMP4_ECHO_REQUEST,
            icmp4_ec_id=12345,
            icmp4_ec_seq=54320,
            icmp4_ec_data=b"0123456789ABCDEF" * 20,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                icmp4__pre_assemble=1,
                icmp4__echo_request__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_icmp4_echo_request.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_icmp4_phtx__ip4_icmp4_echo_reply(self) -> None:
        """
        Test sending the IPv4/ICMPv4 'Echo Reply' packet.
        """
        tx_status = self.packet_handler._phtx_icmp4(
            ip4_src=self.mns.stack_ip4_host.address,
            ip4_dst=self.mns.host_a_ip4_address,
            icmp4_type=ICMP4_ECHO_REPLY,
            icmp4_ec_id=12345,
            icmp4_ec_seq=54320,
            icmp4_ec_data=b"0123456789ABCDEF" * 20,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                icmp4__pre_assemble=1,
                icmp4__echo_reply__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_icmp4_echo_reply.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_icmp4_phtx__ip4_icmp4_unreachable_port(self) -> None:
        """
        Test sending the IPv4/ICMPv4 'Unreachable Port' packet.
        """
        tx_status = self.packet_handler._phtx_icmp4(
            ip4_src=self.mns.stack_ip4_host.address,
            ip4_dst=self.mns.host_a_ip4_address,
            icmp4_type=ICMP4_UNREACHABLE,
            icmp4_code=ICMP4_UNREACHABLE__PORT,
            icmp4_un_data=b"0123456789ABCDEF" * 100,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                icmp4__pre_assemble=1,
                icmp4__unreachable_port__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip4_icmp4_unreachable_port.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)
