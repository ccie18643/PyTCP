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
# tests/unit/arp_phtx.py -  Tests specific for ARP PHTX module.
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
from net_proto import ArpOperation


class TestArpPhtx(TestCase):
    """
    Test ARP phtx module.
    """

    frame_tx: bytearray

    def setUp(self) -> None:
        """
        Setup test environment.
        """

        super().setUp()

        self.mns = MockNetworkSettings()

        patch_config(self)
        setup_mock_packet_handler(self)

    def test__arp_phtx__arp_request(self) -> None:
        """
        Validate that sending ARP request packet works as expected.
        """

        expected_frame_tx = (
            b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x07\x08\x06\x00\x01"
            b"\x08\x00\x06\x04\x00\x01\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
            b"\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x5b"
        )

        tx_status = self.packet_handler._phtx_arp(
            ethernet__src=self.mns.stack_mac_address,
            ethernet__dst=self.mns.mac_broadcast,
            arp__oper=ArpOperation.REQUEST,
            arp__sha=self.mns.stack_mac_address,
            arp__spa=self.mns.stack_ip4_host.address,
            arp__tha=self.mns.mac_unspecified,
            arp__tpa=self.mns.host_a_ip4_address,
        )

        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                arp__pre_assemble=1,
                arp__op_request__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_spec__send=1,
            ),
        )
        self.assertEqual(
            self.frame_tx[: len(expected_frame_tx)], expected_frame_tx
        )

    def test__arp_phtx__arp_reply(self) -> None:
        """
        Validate that sending ARP request packet works as expected.
        """

        expected_frame_tx = (
            b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x06\x00\x01"
            b"\x08\x00\x06\x04\x00\x02\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
            b"\x02\x00\x00\x00\x00\x91\x0a\x00\x01\x5b"
        )

        tx_status = self.packet_handler._phtx_arp(
            ethernet__src=self.mns.stack_mac_address,
            ethernet__dst=self.mns.host_a_mac_address,
            arp__oper=ArpOperation.REPLY,
            arp__sha=self.mns.stack_mac_address,
            arp__spa=self.mns.stack_ip4_host.address,
            arp__tha=self.mns.host_a_mac_address,
            arp__tpa=self.mns.host_a_ip4_address,
        )

        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                arp__pre_assemble=1,
                arp__op_reply__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_spec__send=1,
            ),
        )
        self.assertEqual(
            self.frame_tx[: len(expected_frame_tx)], expected_frame_tx
        )
