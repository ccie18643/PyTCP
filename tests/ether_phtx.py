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
# tests/ether_phtx.py -  tests specific for Ethernet phtx module
#

#
# Had to use IP packets in most test here because a lot of ether/phtx
# operations revolve around resolving destination IP address into
# proper destination MAC address
#

from __future__ import annotations  # Required by Python ver < 3.10

from testslide import StrictMock, TestCase

from pytcp.lib.ip4_address import Ip4Address, Ip4Host
from pytcp.lib.ip6_address import Ip6Address, Ip6Host
from pytcp.lib.mac_address import MacAddress
from pytcp.misc.packet_stats import PacketStatsTx
from pytcp.subsystems.arp_cache import ArpCache
from pytcp.subsystems.nd_cache import NdCache
from pytcp.subsystems.packet_handler import PacketHandler
from pytcp.subsystems.tx_ring import TxRing

# Addresses below match the test packets and should not be changed
STACK_MAC_ADDRESS = MacAddress("02:00:00:00:00:07")

STACK_IP4_HOST = Ip4Host("10.0.1.7/24")
STACK_IP4_GATEWAY = Ip4Address("10.0.1.1")
STACK_IP4_GATEWAY_MAC_ADDRESS = MacAddress("02:00:00:00:00:01")

STACK_IP6_HOST = Ip6Host("2001:db8:0:1::7/64")
STACK_IP6_GATEWAY = Ip6Address("2001::1")
STACK_IP6_GATEWAY_MAC_ADDRESS = MacAddress("02:00:00:00:00:01")

LOCAL_NET_MAC_ADDRESS = MacAddress("02:00:00:00:00:91")
LOCAL_NET_IP4_ADDRESS = Ip4Address("10.0.1.91")
LOCAL_NET_IP4_ADDRESS_NO_ARP = Ip4Address("10.0.1.92")
LOCAL_NET_IP6_ADDRESS = Ip6Address("2001:db8:0:1::91")
LOCAL_NET_IP6_ADDRESS_NO_ND = Ip6Address("2001:db8:0:1::92")

EXTERNAL_NET_IP4_ADDRESS = Ip4Address("10.0.2.50")
EXTERNAL_NET_IP6_ADDRESS = Ip6Address("2001:db8:0:2::50")

IP4_LIMITED_BROADCAST_ADDRESS = Ip4Address("255.255.255.255")
IP4_MULTICAST_ALL_NODES = Ip4Address("224.0.0.1")
IP6_MULTICAST_ALL_NODES = Ip6Address("ff01::1")
MAC_UNSPECIFIED = MacAddress("00:00:00:00:00:00")

TEST_FRAME_DIR = "tests/test_frames/ether_phtx/"


PACKET_HANDLER_MODULES = [
    "pytcp.subsystems.packet_handler",
    "protocols.ether.phtx",
    "protocols.arp.phtx",
    "protocols.ip4.phtx",
    "protocols.ip6.phtx",
    "protocols.icmp4.phtx",
    "protocols.icmp6.phtx",
    "protocols.udp.phtx",
    "protocols.tcp.phtx",
]


CONFIG_PATCHES = {
    "LOG_CHANEL": set(),
    "IP6_SUPPORT": True,
    "IP4_SUPPORT": True,
    "PACKET_INTEGRITY_CHECK": True,
    "PACKET_SANITY_CHECK": True,
    "TAP_MTU": 1500,
    "UDP_ECHO_NATIVE_DISABLE": False,
}


class TestEtherPhtx(TestCase):
    def setUp(self):
        super().setUp()

        STACK_IP4_HOST.gateway = STACK_IP4_GATEWAY
        STACK_IP6_HOST.gateway = STACK_IP6_GATEWAY

        self._patch_config()

        self.arp_cache_mock = StrictMock(ArpCache)
        self.nd_cache_mock = StrictMock(NdCache)
        self.tx_ring_mock = StrictMock(TxRing)

        self.mock_callable(self.arp_cache_mock, "find_entry").for_call(LOCAL_NET_IP4_ADDRESS).to_return_value(LOCAL_NET_MAC_ADDRESS)
        self.mock_callable(self.arp_cache_mock, "find_entry").for_call(LOCAL_NET_IP4_ADDRESS_NO_ARP).to_return_value(None)
        self.mock_callable(self.arp_cache_mock, "find_entry").for_call(STACK_IP4_GATEWAY).to_return_value(STACK_IP4_GATEWAY_MAC_ADDRESS)
        self.mock_callable(self.nd_cache_mock, "find_entry").for_call(LOCAL_NET_IP6_ADDRESS).to_return_value(LOCAL_NET_MAC_ADDRESS)
        self.mock_callable(self.nd_cache_mock, "find_entry").for_call(LOCAL_NET_IP6_ADDRESS_NO_ND).to_return_value(None)
        self.mock_callable(self.nd_cache_mock, "find_entry").for_call(STACK_IP6_GATEWAY).to_return_value(STACK_IP6_GATEWAY_MAC_ADDRESS)
        self.mock_callable(self.tx_ring_mock, "enqueue").with_implementation(lambda packet_tx: packet_tx.assemble(self.frame_tx))

        # Initialize packet handler and manually set all the variables that normally would require network connectivity
        self.packet_handler = PacketHandler(None)
        self.packet_handler.mac_unicast = STACK_MAC_ADDRESS
        self.packet_handler.mac_multicast = [STACK_IP6_HOST.address.solicited_node_multicast.multicast_mac]
        self.packet_handler.ip4_host = [STACK_IP4_HOST]
        self.packet_handler.ip6_host = [STACK_IP6_HOST]
        self.packet_handler.ip6_multicast = [Ip6Address("ff02::1"), STACK_IP6_HOST.address.solicited_node_multicast]
        self.packet_handler.arp_cache = self.arp_cache_mock
        self.packet_handler.nd_cache = self.nd_cache_mock
        self.packet_handler.tx_ring = self.tx_ring_mock

        self.frame_tx = memoryview(bytearray(2048))

    def _patch_config(self):
        """Patch critical config setting for all packet handler modules"""

        for module in PACKET_HANDLER_MODULES:
            for variable, value in CONFIG_PATCHES.items():
                try:
                    self.patch_attribute(f"{module}.config", variable, value)
                except ModuleNotFoundError:
                    continue

    # Test name format: 'test_name__test_description__optional_condition'

    def test_ehter_phtx__ip4_packet_to_unicast_address_on_local_network(self):
        """Test sending IPv4 packet to unicast address on local network"""

        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=STACK_IP4_HOST.address,
            ip4_dst=LOCAL_NET_IP4_ADDRESS,
        )
        self.assertEqual(str(tx_status), "PASSED_TO_TX_RING")
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
        with open(TEST_FRAME_DIR + "ip4_packet_to_unicast_address_on_local_network.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ether_phtx__ip4_packet_to_multicast_address(self):
        """Test sending IPv4 packet to multicast address"""

        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=STACK_IP4_HOST.address,
            ip4_dst=IP4_MULTICAST_ALL_NODES,
        )
        with open(TEST_FRAME_DIR + "ip4_packet_to_multicast_address.tx", "wb") as _:
            _.write(self.frame_tx[:34])
        self.assertEqual(str(tx_status), "PASSED_TO_TX_RING")
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
        with open(TEST_FRAME_DIR + "ip4_packet_to_multicast_address.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ether_phtx__ip4_packet_to_limited_broadcast_address(self):
        """Test sending IPv4 packet to limited broadcast address"""

        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=STACK_IP4_HOST.address,
            ip4_dst=IP4_LIMITED_BROADCAST_ADDRESS,
        )
        self.assertEqual(str(tx_status), "PASSED_TO_TX_RING")
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
        with open(TEST_FRAME_DIR + "ip4_packet_to_limited_broadcast_address.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ether_phtx__ip4_packet_to_local_network_broadcast_address(self):
        """Test sending IPv4 packet to the broadcast address of local network"""

        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=STACK_IP4_HOST.address,
            ip4_dst=STACK_IP4_HOST.network.broadcast,
        )
        self.assertEqual(str(tx_status), "PASSED_TO_TX_RING")
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
        with open(TEST_FRAME_DIR + "ip4_packet_to_local_network_broadcast_address.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ether_phtx__ip4_packet_to_local_network_network_address(self):
        """Test sending IPv4 packet to the network address of local network"""

        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=STACK_IP4_HOST.address,
            ip4_dst=STACK_IP4_HOST.network.address,
        )
        self.assertEqual(str(tx_status), "PASSED_TO_TX_RING")
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
        with open(TEST_FRAME_DIR + "ip4_packet_to_local_network_network_address.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ether_phtx__ip4_packet_to_unicast_address_on_local_network__arp_cache_miss(self):
        """Test sending IPv4 packet to unicast address on local network / arp cache miss"""

        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=STACK_IP4_HOST.address,
            ip4_dst=LOCAL_NET_IP4_ADDRESS_NO_ARP,
        )
        self.assertEqual(str(tx_status), "DROPED_ETHER_DST_ARP_CACHE_FAIL")
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

    def test_ether_phtx__ip4_packet_to_unicast_address_on_external_network(self):
        """Test sending IPv4 packet to unicast address on external network"""

        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=STACK_IP4_HOST.address,
            ip4_dst=EXTERNAL_NET_IP4_ADDRESS,
        )
        self.assertEqual(str(tx_status), "PASSED_TO_TX_RING")
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
        with open(TEST_FRAME_DIR + "ip4_packet_to_unicast_address_on_external_network.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ether_phtx__ip4_packet_to_unicast_address_on_external_network__no_gateway(self):
        """Test sending IPv4 packet to unicast address on external network / no gateway set"""

        STACK_IP4_HOST.gateway = None

        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=STACK_IP4_HOST.address,
            ip4_dst=EXTERNAL_NET_IP4_ADDRESS,
        )
        self.assertEqual(str(tx_status), "DROPED_ETHER_DST_NO_GATEWAY_IP4")
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

    def test_ether_phtx__ip4_packet_to_unicast_address_on_external_network__gateway_arp_cache_miss(self):
        """Test sending IPv4 packet to unicast address on external network / gateway ARP cache miss"""

        STACK_IP4_HOST.gateway = LOCAL_NET_IP4_ADDRESS_NO_ARP

        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=STACK_IP4_HOST.address,
            ip4_dst=EXTERNAL_NET_IP4_ADDRESS,
        )
        self.assertEqual(str(tx_status), "DROPED_ETHER_DST_GATEWAY_ARP_CACHE_FAIL")
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

    def test_ehter_phtx__ip6_packet_to_unicast_address_on_local_network(self):
        """Test sending IPv6 packet to unicast address on local network"""

        tx_status = self.packet_handler._phtx_ip6(
            ip6_src=STACK_IP6_HOST.address,
            ip6_dst=LOCAL_NET_IP6_ADDRESS,
        )
        self.assertEqual(str(tx_status), "PASSED_TO_TX_RING")
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
        with open(TEST_FRAME_DIR + "ip6_packet_to_unicast_address_on_local_network.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ether_phtx__ip6_packet_to_multicast_address(self):
        """Test sending IPv6 packet to multicast address"""

        tx_status = self.packet_handler._phtx_ip6(
            ip6_src=STACK_IP6_HOST.address,
            ip6_dst=IP6_MULTICAST_ALL_NODES,
        )
        self.assertEqual(str(tx_status), "PASSED_TO_TX_RING")
        with open(TEST_FRAME_DIR + "ip6_packet_to_multicast_address.tx", "wb") as _:
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
        with open(TEST_FRAME_DIR + "ip6_packet_to_multicast_address.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ether_phtx__ip6_packet_to_unicast_address_on_local_network__nd_cache_miss(self):
        """Test sending IPv6 packet to unicast address on local network / ND cache miss"""

        tx_status = self.packet_handler._phtx_ip6(
            ip6_src=STACK_IP6_HOST.address,
            ip6_dst=LOCAL_NET_IP6_ADDRESS_NO_ND,
        )
        self.assertEqual(str(tx_status), "DROPED_ETHER_DST_ND_CACHE_FAIL")
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

    def test_ether_phtx__ip6_packet_to_unicast_address_on_external_network(self):
        """Test sending IPv6 packet to unicast address on external network"""

        tx_status = self.packet_handler._phtx_ip6(
            ip6_src=STACK_IP6_HOST.address,
            ip6_dst=EXTERNAL_NET_IP6_ADDRESS,
        )
        self.assertEqual(str(tx_status), "PASSED_TO_TX_RING")
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
        with open(TEST_FRAME_DIR + "ip6_packet_to_unicast_address_on_external_network.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ether_phtx__ip6_packet_to_unicast_address_on_external_network__no_gateway(self):
        """Test sending IPv6 packet to unicast address on external network / no gateway set"""

        STACK_IP6_HOST.gateway = None

        tx_status = self.packet_handler._phtx_ip6(
            ip6_src=STACK_IP6_HOST.address,
            ip6_dst=EXTERNAL_NET_IP6_ADDRESS,
        )
        self.assertEqual(str(tx_status), "DROPED_ETHER_DST_NO_GATEWAY_IP6")
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

    def test_ether_phtx__ip6_packet_to_unicast_address_on_external_network__gateway_nd_cache_miss(self):
        """Test sending IPv6 packet to unicast address on external network / gateway ND cache miss"""

        STACK_IP6_HOST.gateway = LOCAL_NET_IP6_ADDRESS_NO_ND

        tx_status = self.packet_handler._phtx_ip6(
            ip6_src=STACK_IP6_HOST.address,
            ip6_dst=EXTERNAL_NET_IP6_ADDRESS,
        )
        self.assertEqual(str(tx_status), "DROPED_ETHER_DST_GATEWAY_ND_CACHE_FAIL")
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

    def test_ether_phtx__ether_packet_with_specified_source_mac_address(self):
        """Send Ethernet packet with specified source MAC address"""

        tx_status = self.packet_handler._phtx_ether(
            ether_src=STACK_MAC_ADDRESS,
            ether_dst=LOCAL_NET_MAC_ADDRESS,
        )
        self.assertEqual(str(tx_status), "PASSED_TO_TX_RING")
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ether__pre_assemble=1,
                ether__src_spec=1,
                ether__dst_spec__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ether_packet_with_specified_source_mac_address.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ether_phtx__ether_packet_with_unspecified_source_mac_address(self):
        """Send Ethernet packet with unspecified source MAC address"""

        tx_status = self.packet_handler._phtx_ether(
            ether_src=MAC_UNSPECIFIED,
            ether_dst=LOCAL_NET_MAC_ADDRESS,
        )
        self.assertEqual(str(tx_status), "PASSED_TO_TX_RING")
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_spec__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ether_packet_with_unspecified_source_mac_address.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ether_phtx__ether_packet_with_unspecified_destination_mac_address(self):
        """Send Ethernet packet with unspecified destination MAC address"""

        tx_status = self.packet_handler._phtx_ether(
            ether_src=STACK_MAC_ADDRESS,
            ether_dst=MAC_UNSPECIFIED,
        )
        self.assertEqual(str(tx_status), "DROPED_ETHER_DST_RESOLUTION_FAIL")
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ether__pre_assemble=1,
                ether__src_spec=1,
                ether__dst_unspec__drop=1,
            ),
        )
