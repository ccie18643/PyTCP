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
# tests/ether_phtx.py -  tests specific for Ethernet phtx module
#
# ver 2.7
#

#
# Had to use IP packets in most test here because a lot of ether/phtx
# operations revolve around resolving destination IP address into
# proper destination MAC address
#


from testslide import TestCase

from pytcp.misc.packet_stats import PacketStatsTx
from pytcp.misc.tx_status import TxStatus
from tests.unit.mock_network import (
    MockNetworkSettings,
    patch_config,
    setup_mock_packet_handler,
)

TEST_FRAME_DIR = "tests/unit/test_frames/ether_phtx/"


class TestEtherPhtx(TestCase):
    """
    Ethernet packet handler TX unit test class.
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

    def test_ehter_phtx__ip4_packet_to_unicast_address_on_local_network(
        self,
    ) -> None:
        """
        Test sending IPv4 packet to unicast address on local network.
        """
        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=self.mns.stack_ip4_host.address,
            ip4_dst=self.mns.host_a_ip4_address,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(
            TEST_FRAME_DIR
            + "ip4_packet_to_unicast_address_on_local_network.tx",
            "rb",
        ) as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ether_phtx__ip4_packet_to_multicast_address(self) -> None:
        """
        Test sending IPv4 packet to the multicast address.
        """
        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=self.mns.stack_ip4_host.address,
            ip4_dst=self.mns.ip4_multicast_all_nodes,
        )
        with open(
            TEST_FRAME_DIR + "ip4_packet_to_multicast_address.tx", "wb"
        ) as _:
            _.write(self.frame_tx[:34])
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__multicast__send=1,
            ),
        )
        with open(
            TEST_FRAME_DIR + "ip4_packet_to_multicast_address.tx", "rb"
        ) as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ether_phtx__ip4_packet_to_limited_broadcast_address(self) -> None:
        """
        Test sending IPv4 packet to the limited broadcast address.
        """
        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=self.mns.stack_ip4_host.address,
            ip4_dst=self.mns.ip4_limited_broadcast,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__limited_broadcast__send=1,
            ),
        )
        with open(
            TEST_FRAME_DIR + "ip4_packet_to_limited_broadcast_address.tx", "rb"
        ) as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ether_phtx__ip4_packet_to_local_network_broadcast_address(
        self,
    ) -> None:
        """
        Test sending IPv4 packet to the broadcast address of local network.
        """
        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=self.mns.stack_ip4_host.address,
            ip4_dst=self.mns.stack_ip4_host.network.broadcast,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__network_broadcast__send=1,
            ),
        )
        with open(
            TEST_FRAME_DIR + "ip4_packet_to_local_network_broadcast_address.tx",
            "rb",
        ) as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ether_phtx__ip4_packet_to_local_network_network_address(
        self,
    ) -> None:
        """
        Test sending IPv4 packet to the network address of local network.
        """
        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=self.mns.stack_ip4_host.address,
            ip4_dst=self.mns.stack_ip4_host.network.address,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__network_broadcast__send=1,
            ),
        )
        with open(
            TEST_FRAME_DIR + "ip4_packet_to_local_network_network_address.tx",
            "rb",
        ) as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ether_phtx__ip4_packet_to_unicast_address_on_local_network__arp_cache_miss(
        self,
    ):
        """
        Test sending IPv4 packet to unicast address on local network / arp
        cache miss.
        """
        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=self.mns.stack_ip4_host.address,
            ip4_dst=self.mns.host_b_ip4_address,
        )
        self.assertEqual(tx_status, TxStatus.DROPED__ETHER__DST_ARP_CACHE_FAIL)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_miss__drop=1,
            ),
        )

    def test_ether_phtx__ip4_packet_to_unicast_address_on_external_network(
        self,
    ):
        """
        Test sending IPv4 packet to unicast address on external network.
        """
        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=self.mns.stack_ip4_host.address,
            ip4_dst=self.mns.host_c_ip4_address,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__extnet__gw_arp_cache_hit__send=1,
            ),
        )
        with open(
            TEST_FRAME_DIR
            + "ip4_packet_to_unicast_address_on_external_network.tx",
            "rb",
        ) as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ether_phtx__ip4_packet_to_unicast_address_on_external_network__no_gateway(
        self,
    ):
        """
        Test sending IPv4 packet to unicast address on external
        network / no gateway set.
        """
        self.mns.stack_ip4_host.gateway = None

        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=self.mns.stack_ip4_host.address,
            ip4_dst=self.mns.host_c_ip4_address,
        )
        self.assertEqual(str(tx_status), "DROPED__ETHER__DST_NO_GATEWAY_IP4")
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__extnet__no_gw__drop=1,
            ),
        )

    def test_ether_phtx__ip4_packet_to_unicast_address_on_external_network__gateway_arp_cache_miss(
        self,
    ):
        """
        Test sending IPv4 packet to unicast address on external
        network / gateway ARP cache miss.
        """
        self.mns.stack_ip4_host.gateway = self.mns.host_b_ip4_address

        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=self.mns.stack_ip4_host.address,
            ip4_dst=self.mns.host_c_ip4_address,
        )
        self.assertEqual(
            tx_status, TxStatus.DROPED__ETHER__DST_GATEWAY_ARP_CACHE_FAIL
        )
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__extnet__gw_arp_cache_miss__drop=1,
            ),
        )

    def test_ehter_phtx__ip6_packet_to_unicast_address_on_local_network(
        self,
    ) -> None:
        """
        Test sending IPv6 packet to unicast address on local network.
        """
        tx_status = self.packet_handler._phtx_ip6(
            ip6_src=self.mns.stack_ip6_host.address,
            ip6_dst=self.mns.host_a_ip6_address,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip6_lookup=1,
                ether__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(
            TEST_FRAME_DIR
            + "ip6_packet_to_unicast_address_on_local_network.tx",
            "rb",
        ) as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ether_phtx__ip6_packet_to_multicast_address(self) -> None:
        """
        Test sending IPv6 packet to the multicast address.
        """
        tx_status = self.packet_handler._phtx_ip6(
            ip6_src=self.mns.stack_ip6_host.address,
            ip6_dst=self.mns.ip6_multicast_all_nodes,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        with open(
            TEST_FRAME_DIR + "ip6_packet_to_multicast_address.tx", "wb"
        ) as _:
            _.write(self.frame_tx[:54])
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip6_lookup=1,
                ether__dst_unspec__ip6_lookup__multicast__send=1,
            ),
        )
        with open(
            TEST_FRAME_DIR + "ip6_packet_to_multicast_address.tx", "rb"
        ) as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ether_phtx__ip6_packet_to_unicast_address_on_local_network__nd_cache_miss(
        self,
    ):
        """
        Test sending IPv6 packet to unicast address on local
        network / ND cache miss.
        """
        tx_status = self.packet_handler._phtx_ip6(
            ip6_src=self.mns.stack_ip6_host.address,
            ip6_dst=self.mns.host_b_ip6_address,
        )
        self.assertEqual(tx_status, TxStatus.DROPED__ETHER__DST_ND_CACHE_FAIL)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip6_lookup=1,
                ether__dst_unspec__ip6_lookup__locnet__nd_cache_miss__drop=1,
            ),
        )

    def test_ether_phtx__ip6_packet_to_unicast_address_on_external_network(
        self,
    ):
        """
        Test sending IPv6 packet to unicast address on external network.
        """
        tx_status = self.packet_handler._phtx_ip6(
            ip6_src=self.mns.stack_ip6_host.address,
            ip6_dst=self.mns.host_c_ip6_address,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip6_lookup=1,
                ether__dst_unspec__ip6_lookup__extnet__gw_nd_cache_hit__send=1,
            ),
        )
        with open(
            TEST_FRAME_DIR
            + "ip6_packet_to_unicast_address_on_external_network.tx",
            "rb",
        ) as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ether_phtx__ip6_packet_to_unicast_address_on_external_network__no_gateway(
        self,
    ):
        """
        Test sending IPv6 packet to unicast address on external
        network / no gateway set.
        """
        self.mns.stack_ip6_host.gateway = None
        tx_status = self.packet_handler._phtx_ip6(
            ip6_src=self.mns.stack_ip6_host.address,
            ip6_dst=self.mns.host_c_ip6_address,
        )
        self.assertEqual(tx_status, TxStatus.DROPED__ETHER__DST_NO_GATEWAY_IP6)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip6_lookup=1,
                ether__dst_unspec__ip6_lookup__extnet__no_gw__drop=1,
            ),
        )

    def test_ether_phtx__ip6_packet_to_unicast_address_on_external_network__gateway_nd_cache_miss(
        self,
    ):
        """
        Test sending IPv6 packet to unicast address on external
        network / gateway ND cache miss.
        """
        self.mns.stack_ip6_host.gateway = self.mns.router_b_ip6_address
        tx_status = self.packet_handler._phtx_ip6(
            ip6_src=self.mns.stack_ip6_host.address,
            ip6_dst=self.mns.host_c_ip6_address,
        )
        self.assertEqual(
            tx_status, TxStatus.DROPED__ETHER__DST_GATEWAY_ND_CACHE_FAIL
        )
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip6_lookup=1,
                ether__dst_unspec__ip6_lookup__extnet__gw_nd_cache_miss__drop=1,
            ),
        )

    def test_ether_phtx__ether_packet_with_specified_source_mac_address(
        self,
    ) -> None:
        """
        Send Ethernet packet with specified source MAC address.
        """
        tx_status = self.packet_handler._phtx_ether(
            ether_src=self.mns.stack_mac_address,
            ether_dst=self.mns.host_a_mac_address,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ether__pre_assemble=1,
                ether__src_spec=1,
                ether__dst_spec__send=1,
            ),
        )
        with open(
            TEST_FRAME_DIR
            + "ether_packet_with_specified_source_mac_address.tx",
            "rb",
        ) as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ether_phtx__ether_packet_with_unspecified_source_mac_address(
        self,
    ) -> None:
        """
        Send Ethernet packet with unspecified source MAC address.
        """
        tx_status = self.packet_handler._phtx_ether(
            ether_src=self.mns.mac_unspecified,
            ether_dst=self.mns.host_a_mac_address,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_spec__send=1,
            ),
        )
        with open(
            TEST_FRAME_DIR
            + "ether_packet_with_unspecified_source_mac_address.tx",
            "rb",
        ) as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ether_phtx__ether_packet_with_unspecified_destination_mac_address(
        self,
    ):
        """
        Send Ethernet packet with unspecified destination MAC address.
        """
        tx_status = self.packet_handler._phtx_ether(
            ether_src=self.mns.stack_mac_address,
            ether_dst=self.mns.mac_unspecified,
        )
        self.assertEqual(tx_status, TxStatus.DROPED__ETHER__DST_RESOLUTION_FAIL)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ether__pre_assemble=1,
                ether__src_spec=1,
                ether__dst_unspec__drop=1,
            ),
        )
