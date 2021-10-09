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
# tests/arp_phtx.py -  tests specific for ARP phtx module
#


from testslide import TestCase

from pytcp.misc.packet_stats import PacketStatsTx
from pytcp.misc.tx_status import TxStatus
from pytcp.protocols.arp.ps import ARP_OP_REPLY, ARP_OP_REQUEST
from tests.mock_network import (
    MockNetworkSettings,
    patch_config,
    setup_mock_packet_handler,
)

TEST_FRAME_DIR = "tests/test_frames/arp_phtx/"


class TestArpPhtx(TestCase):
    def setUp(self):
        super().setUp()

        self.mns = MockNetworkSettings()
        patch_config(self)
        setup_mock_packet_handler(self)

    # Test name format: 'test_name__test_description__optional_condition'

    def test_arp_phtx__arp_request(self):
        """Test sending ARP request packet"""

        tx_status = self.packet_handler._phtx_arp(
            ether_src=self.mns.stack_mac_address,
            ether_dst=self.mns.mac_broadcast,
            arp_oper=ARP_OP_REQUEST,
            arp_sha=self.mns.stack_mac_address,
            arp_spa=self.mns.stack_ip4_host.address,
            arp_tha=self.mns.mac_unspecified,
            arp_tpa=self.mns.host_a_ip4_address,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                arp__pre_assemble=1,
                arp__op_request__send=1,
                ether__pre_assemble=1,
                ether__src_spec=1,
                ether__dst_spec__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "arp_request.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_arp_phtx__arp_reply(self):
        """Test sending ARP request packet"""

        tx_status = self.packet_handler._phtx_arp(
            ether_src=self.mns.stack_mac_address,
            ether_dst=self.mns.host_a_mac_address,
            arp_oper=ARP_OP_REPLY,
            arp_sha=self.mns.stack_mac_address,
            arp_spa=self.mns.stack_ip4_host.address,
            arp_tha=self.mns.host_a_mac_address,
            arp_tpa=self.mns.host_a_ip4_address,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                arp__pre_assemble=1,
                arp__op_reply__send=1,
                ether__pre_assemble=1,
                ether__src_spec=1,
                ether__dst_spec__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "arp_reply.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)
