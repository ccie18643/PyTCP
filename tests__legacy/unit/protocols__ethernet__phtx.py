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
# tests/unit/ethernet_phtx.py -  Tests specific for Ethernet PHTX module.
#
# ver 3.0.2
#

#
# Had to use IP packets in most test here because a lot of ether/phtx
# operations revolve around resolving destination IP address into
# proper destination MAC address
#


from tests__legacy.unit.mock_network import (
    MockNetworkSettings,
    patch_config,
    setup_mock_packet_handler,
)
from testslide import TestCase

from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.subsystems.packet_handler import PacketHandler

TEST_FRAME_DIR = "tests__legacy/unit/test_frames/ethernet_phtx/"


class TestEthernetPhtx(TestCase):
    """
    Ethernet packet handler TX unit test class.
    """

    frame_tx: bytearray
    packet_handler: PacketHandler

    def setUp(self) -> None:
        """
        Setup test environment.
        """

        super().setUp()

        self.mns = MockNetworkSettings()

        patch_config(self)
        setup_mock_packet_handler(self)

    def test__ehternet_phtx__ip4_packet_to_unicast_address_on_local_network(
        self,
    ) -> None:
        """
        Validate that sending IPv4 packet to unicast address on local network
        works as expected.
        """

        expected_frame_tx = (
            b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
            b"\x00\x14\x00\x00\x00\x00\x40\xFF\x63\x8A\x0A\x00\x01\x07\x0A\x00"
            b"\x01\x5B"
        )

        tx_status = self.packet_handler._phtx_ip4(
            ip4__src=self.mns.stack_ip4_host.address,
            ip4__dst=self.mns.host_a_ip4_address,
        )

        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        self.assertEqual(
            self.frame_tx[: len(expected_frame_tx)], expected_frame_tx
        )

    def test__ethernet_phtx__ip4_packet_to_multicast_address(self) -> None:
        """
        Validate that sending IPv4 packet to the multicast address
        works as expected.
        """

        expected_frame_tx = (
            b"\x01\x00\x5E\x00\x00\x01\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
            b"\x00\x14\x00\x00\x00\x00\x40\xFF\x8E\xE3\x0A\x00\x01\x07\xE0\x00"
            b"\x00\x01"
        )

        tx_status = self.packet_handler._phtx_ip4(
            ip4__src=self.mns.stack_ip4_host.address,
            ip4__dst=self.mns.ip4_multicast_all_nodes,
        )

        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__multicast__send=1,
            ),
        )
        self.assertEqual(
            self.frame_tx[: len(expected_frame_tx)], expected_frame_tx
        )

    def test__ethernet_phtx__ip4_packet_to_limited_broadcast_address(
        self,
    ) -> None:
        """
        Validate that sending IPv4 packet to the limited broadcast address
        works as expected.
        """

        expected_frame_tx = (
            b"\xFF\xFF\xFF\xFF\xFF\xFF\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
            b"\x00\x14\x00\x00\x00\x00\x40\xFF\x6E\xE5\x0A\x00\x01\x07\xFF\xFF"
            b"\xFF\xFF"
        )

        tx_status = self.packet_handler._phtx_ip4(
            ip4__src=self.mns.stack_ip4_host.address,
            ip4__dst=self.mns.ip4_limited_broadcast,
        )

        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__limited_broadcast__send=1,
            ),
        )
        self.assertEqual(
            self.frame_tx[: len(expected_frame_tx)], expected_frame_tx
        )

    def test__ethernet_phtx__ip4_packet_to_local_network_broadcast_address(
        self,
    ) -> None:
        """
        Validate that sending IPv4 packet to the broadcast address
        of local network works as expected.
        """

        expected_frame_tx = (
            b"\xFF\xFF\xFF\xFF\xFF\xFF\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
            b"\x00\x14\x00\x00\x00\x00\x40\xFF\x62\xE6\x0A\x00\x01\x07\x0A\x00"
            b"\x01\xFF"
        )

        tx_status = self.packet_handler._phtx_ip4(
            ip4__src=self.mns.stack_ip4_host.address,
            ip4__dst=self.mns.stack_ip4_host.network.broadcast,
        )

        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__network_broadcast__send=1,
            ),
        )
        self.assertEqual(
            self.frame_tx[: len(expected_frame_tx)], expected_frame_tx
        )

    def test__ethernet_phtx__ip4_packet_to_local_network_network_address(
        self,
    ) -> None:
        """
        Validate that sending IPv4 packet to the network address
        of local network works as expected.
        """

        expected_frame_tx = (
            b"\xFF\xFF\xFF\xFF\xFF\xFF\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
            b"\x00\x14\x00\x00\x00\x00\x40\xFF\x63\xE5\x0A\x00\x01\x07\x0A\x00"
            b"\x01\x00"
        )

        tx_status = self.packet_handler._phtx_ip4(
            ip4__src=self.mns.stack_ip4_host.address,
            ip4__dst=self.mns.stack_ip4_host.network.address,
        )

        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__network_broadcast__send=1,
            ),
        )
        self.assertEqual(
            self.frame_tx[: len(expected_frame_tx)], expected_frame_tx
        )

    def test__ethernet_phtx__ip4_packet_to_unicast_address_on_local_network__arp_cache_miss(
        self,
    ) -> None:
        """
        Validate that sending IPv4 packet to unicast address on local
        network with arp cache miss works as expected.
        """

        tx_status = self.packet_handler._phtx_ip4(
            ip4__src=self.mns.stack_ip4_host.address,
            ip4__dst=self.mns.host_b_ip4_address,
        )

        self.assertEqual(
            tx_status, TxStatus.DROPED__ETHERNET__DST_ARP_CACHE_FAIL
        )
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_miss__drop=1,
            ),
        )

    def test__ethernet_phtx__ip4_packet_to_unicast_address_on_external_network(
        self,
    ) -> None:
        """
        Validate that sending IPv4 packet to unicast address on
        external network works as expected.
        """

        expected_frame_tx = (
            b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
            b"\x00\x14\x00\x00\x00\x00\x40\xFF\x62\xB3\x0A\x00\x01\x07\x0A\x00"
            b"\x02\x32"
        )

        tx_status = self.packet_handler._phtx_ip4(
            ip4__src=self.mns.stack_ip4_host.address,
            ip4__dst=self.mns.host_c_ip4_address,
        )

        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__extnet__gw_arp_cache_hit__send=1,
            ),
        )
        self.assertEqual(
            self.frame_tx[: len(expected_frame_tx)], expected_frame_tx
        )

    def test__ethernet_phtx__ip4_packet_to_unicast_address_on_external_network__no_gateway(
        self,
    ) -> None:
        """
        Validate that sending IPv4 packet to unicast address on external
        network with no gateway set works as expected.
        """

        self.mns.stack_ip4_host.gateway = None

        tx_status = self.packet_handler._phtx_ip4(
            ip4__src=self.mns.stack_ip4_host.address,
            ip4__dst=self.mns.host_c_ip4_address,
        )

        self.assertEqual(str(tx_status), "DROPED__ETHERNET__DST_NO_GATEWAY_IP4")
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__extnet__no_gw__drop=1,
            ),
        )

    def test__ethernet_phtx__ip4_packet_to_unicast_address_on_external_network__gateway_arp_cache_miss(
        self,
    ) -> None:
        """
        Validate that sending IPv4 packet to unicast address on external
        network with gateway ARP cache miss works as expected.
        """

        self.mns.stack_ip4_host.gateway = self.mns.host_b_ip4_address

        tx_status = self.packet_handler._phtx_ip4(
            ip4__src=self.mns.stack_ip4_host.address,
            ip4__dst=self.mns.host_c_ip4_address,
        )

        self.assertEqual(
            tx_status, TxStatus.DROPED__ETHERNET__DST_GATEWAY_ARP_CACHE_FAIL
        )
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__extnet__gw_arp_cache_miss__drop=1,
            ),
        )

    def test__ehternet_phtx__ip6_packet_to_unicast_address_on_local_network(
        self,
    ) -> None:
        """
        Validate that sending IPv6 packet to unicast address on local network
        works as expected.
        """

        expected_frame_tx = (
            b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xDD\x60\x00"
            b"\x00\x00\x00\x00\xFF\x40\x20\x01\x0D\xB8\x00\x00\x00\x01\x00\x00"
            b"\x00\x00\x00\x00\x00\x07\x20\x01\x0D\xB8\x00\x00\x00\x01\x00\x00"
            b"\x00\x00\x00\x00\x00\x91"
        )

        tx_status = self.packet_handler._phtx_ip6(
            ip6__src=self.mns.stack_ip6_host.address,
            ip6__dst=self.mns.host_a_ip6_address,
        )

        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        self.assertEqual(
            self.frame_tx[: len(expected_frame_tx)], expected_frame_tx
        )

    def test__ethernet_phtx__ip6_packet_to_multicast_address(self) -> None:
        """
        Verify that sending IPv6 packet to the multicast address
        works as expected.
        """

        expected_frame_tx = (
            b"\x33\x33\x00\x00\x00\x01\x02\x00\x00\x00\x00\x07\x86\xDD\x60\x00"
            b"\x00\x00\x00\x00\xFF\x40\x20\x01\x0D\xB8\x00\x00\x00\x01\x00\x00"
            b"\x00\x00\x00\x00\x00\x07\xFF\x01\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x01"
        )

        tx_status = self.packet_handler._phtx_ip6(
            ip6__src=self.mns.stack_ip6_host.address,
            ip6__dst=self.mns.ip6_multicast_all_nodes,
        )

        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__multicast__send=1,
            ),
        )
        self.assertEqual(
            self.frame_tx[: len(expected_frame_tx)], expected_frame_tx
        )

    def test__ethernet_phtx__ip6_packet_to_unicast_address_on_local_network__nd_cache_miss(
        self,
    ) -> None:
        """
        Verify that sending IPv6 packet to unicast address on local
        network with ND cache miss works as expected.
        """

        tx_status = self.packet_handler._phtx_ip6(
            ip6__src=self.mns.stack_ip6_host.address,
            ip6__dst=self.mns.host_b_ip6_address,
        )

        self.assertEqual(
            tx_status, TxStatus.DROPED__ETHERNET__DST_ND_CACHE_FAIL
        )
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_miss__drop=1,
            ),
        )

    def test__ethernet_phtx__ip6_packet_to_unicast_address_on_external_network(
        self,
    ) -> None:
        """
        Verify that sending IPv6 packet to unicast address on external network
        works as expected.
        """

        expected_frame_tx = (
            b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x07\x86\xDD\x60\x00"
            b"\x00\x00\x00\x00\xFF\x40\x20\x01\x0D\xB8\x00\x00\x00\x01\x00\x00"
            b"\x00\x00\x00\x00\x00\x07\x20\x01\x0D\xB8\x00\x00\x00\x02\x00\x00"
            b"\x00\x00\x00\x00\x00\x50"
        )

        tx_status = self.packet_handler._phtx_ip6(
            ip6__src=self.mns.stack_ip6_host.address,
            ip6__dst=self.mns.host_c_ip6_address,
        )

        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__extnet__gw_nd_cache_hit__send=1,
            ),
        )
        self.assertEqual(
            self.frame_tx[: len(expected_frame_tx)], expected_frame_tx
        )

    def test__ethernet_phtx__ip6_packet_to_unicast_address_on_external_network__no_gateway(
        self,
    ) -> None:
        """
        Verify that sending IPv6 packet to unicast address on external
        network with no gateway set works as expected.
        """

        self.mns.stack_ip6_host.gateway = None

        tx_status = self.packet_handler._phtx_ip6(
            ip6__src=self.mns.stack_ip6_host.address,
            ip6__dst=self.mns.host_c_ip6_address,
        )

        self.assertEqual(
            tx_status, TxStatus.DROPED__ETHERNET__DST_NO_GATEWAY_IP6
        )
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__extnet__no_gw__drop=1,
            ),
        )

    def test__ethernet_phtx__ip6_packet_to_unicast_address_on_external_network__gateway_nd_cache_miss(
        self,
    ) -> None:
        """
        Verify that sending IPv6 packet to unicast address on external
        network with gateway ND cache miss works as expected.
        """

        self.mns.stack_ip6_host.gateway = self.mns.router_b_ip6_address

        tx_status = self.packet_handler._phtx_ip6(
            ip6__src=self.mns.stack_ip6_host.address,
            ip6__dst=self.mns.host_c_ip6_address,
        )

        self.assertEqual(
            tx_status, TxStatus.DROPED__ETHERNET__DST_GATEWAY_ND_CACHE_FAIL
        )
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__extnet__gw_nd_cache_miss__drop=1,
            ),
        )

    def test__ethernet_phtx__ethernet_packet_with_specified_source_mac_address(
        self,
    ) -> None:
        """
        Verify that sending Ethernet packet with specified source MAC address
        works as expected.
        """

        expected_frame_tx = (
            b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\xFF\xFF"
        )

        tx_status = self.packet_handler._phtx_ethernet(
            ethernet__src=self.mns.stack_mac_address,
            ethernet__dst=self.mns.host_a_mac_address,
        )

        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_spec__send=1,
            ),
        )
        self.assertEqual(
            self.frame_tx[: len(expected_frame_tx)], expected_frame_tx
        )

    def test__ethernet_phtx__ethernet_packet_with_unspecified_source_mac_address(
        self,
    ) -> None:
        """
        Send Ethernet packet with unspecified source MAC address.
        """

        expected_frame_tx = (
            b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\xFF\xFF"
        )

        tx_status = self.packet_handler._phtx_ethernet(
            ethernet__src=self.mns.mac_unspecified,
            ethernet__dst=self.mns.host_a_mac_address,
        )

        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_spec__send=1,
            ),
        )
        self.assertEqual(
            self.frame_tx[: len(expected_frame_tx)], expected_frame_tx
        )

    def test__ethernet_phtx__ethernet_packet_with_unspecified_destination_mac_address(
        self,
    ) -> None:
        """
        Validate that sending Ethernet packet with unspecified destination
        MAC address works as expected.
        """

        tx_status = self.packet_handler._phtx_ethernet(
            ethernet__src=self.mns.stack_mac_address,
            ethernet__dst=self.mns.mac_unspecified,
        )

        self.assertEqual(
            tx_status, TxStatus.DROPED__ETHERNET__DST_RESOLUTION_FAIL
        )
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_unspec__drop=1,
            ),
        )
