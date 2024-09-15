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
# tests/test_packet_flows_rx.py - unit tests for packets received by stack
# with no response sent back
#
# ver 3.0.2
#


from testslide import TestCase

from pytcp import config
from net_addr import Ip4Address, Ip4Host, Ip6Address, Ip6Host, MacAddress
from pytcp.lib.packet import PacketRx
from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx
from pytcp.stack.packet_handler import PacketHandler
from pytcp import stack


# Ensure critical configuration settings are set properly for the testing
# regardless of actual configuration
CONFIG_PATCHES = {
    "LOG__CHANNEL": set(),
    "IP6__SUPPORT": True,
    "IP4__SUPPORT": True,
    "INTERFACE__TAP__MTU": 1500,
    "UDP__ECHO_NATIVE": True,
}


# Addresses below match the test packets and should not be changed
STACK_MAC_ADDRESS = MacAddress("02:00:00:77:77:77")
STACK_IP4_HOST = Ip4Host("192.168.9.7/24")
STACK_IP6_HOST = Ip6Host("2603:9000:e307:9f09:0:ff:fe77:7777/64")
REMOTE_MAC_ADDRESS = MacAddress("52:54:00:df:85:37")
REMOTE_IP4_ADDRESS = Ip4Address("192.168.9.102")
REMOTE_IP6_ADDRESS = Ip6Address("2603:9000:e307:9f09::1fa1")


class TestPacketHandlerRx(TestCase):
    """
    The RX packet flow integration__legacy test class.
    """

    def setUp(self) -> None:
        """
        Set up the test environment.
        """

        super().setUp()

        self._patch_config()

        # Initialize packet handler and manually set all the variables that
        # normally would require network connectivity
        self.packet_handler = PacketHandler(
            mac_address=STACK_MAC_ADDRESS,
            interface_mtu=1500,
        )
        self.packet_handler.mac_multicast = [
            STACK_IP6_HOST.address.solicited_node_multicast.multicast_mac
        ]
        self.packet_handler.ip4_host = [STACK_IP4_HOST]
        self.packet_handler.ip6_host = [STACK_IP6_HOST]
        self.packet_handler.ip6_multicast = [
            Ip6Address("ff02::1"),
            STACK_IP6_HOST.address.solicited_node_multicast,
        ]

        self.packet_tx = memoryview(bytearray(2048))

        stack.mock__init(
            mock__packet_handler=self.packet_handler,
        )

    def _patch_config(self) -> None:
        """
        Patch critical config setting for all packet handler modules.
        """
        for attribute, new_value in CONFIG_PATCHES.items():
            stack.__dict__[attribute] = new_value
            config.__dict__[attribute] = new_value

    # Test name format:
    # 'test_name__protocol_tested__test_description__optional_condition'

    def test_packet_flow_rx__ethernet__ethernet_unknown_dst(self) -> None:
        """
        [Ethernet] Receive Ethernet packet with unknown destination
        MAC address, drop.
        """
        with open(
            "tests__legacy/integration/test_frames/rx/ethernet_unknown_dst.rx",
            "rb",
        ) as _:
            packet_rx = _.read()
        self.packet_handler._phrx_ethernet(PacketRx(packet_rx))
        self.assertEqual(
            self.packet_handler.packet_stats_rx,
            PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unknown__drop=1,
            ),
        )
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(),
        )

    def test_packet_flow_rx__ethernet__ethernet_malformed_header(self) -> None:
        """
        [Ethernet] Receive Ethernet packet with malformed header, drop.
        """
        with open(
            "tests__legacy/integration/test_frames/rx/ethernet_malformed_header.rx",
            "rb",
        ) as _:
            packet_rx = _.read()
        self.packet_handler._phrx_ethernet(PacketRx(packet_rx))
        self.assertEqual(
            self.packet_handler.packet_stats_rx,
            PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__failed_parse__drop=1,
            ),
        )
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(),
        )

    def test_packet_flow_rx__ip4__ip4_unknown_dst(self) -> None:
        """
        [IPv4] Receive IPv4 packet for unknown destination, drop.
        """
        with open(
            "tests__legacy/integration/test_frames/rx/ip4_unknown_dst.rx", "rb"
        ) as _:
            packet_rx = _.read()
        self.packet_handler._phrx_ethernet(PacketRx(packet_rx))
        self.assertEqual(
            self.packet_handler.packet_stats_rx,
            PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip4__pre_parse=1,
                ip4__dst_unknown__drop=1,
            ),
        )
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(),
        )

    def test_packet_flow_rx__ip6__ip6_unknown_dst(self) -> None:
        """
        [IPv6] Receive IPv6 packet for unknown destination, drop.
        """
        with open(
            "tests__legacy/integration/test_frames/rx/ip6_unknown_dst.rx", "rb"
        ) as _:
            packet_rx = _.read()
        self.packet_handler._phrx_ethernet(PacketRx(packet_rx))
        self.assertEqual(
            self.packet_handler.packet_stats_rx,
            PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip6__pre_parse=1,
                ip6__dst_unknown__drop=1,
            ),
        )
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(),
        )

    def test_packet_flow_rx__arp__arp_unknown_tpa(self) -> None:
        """
        [ARP] Receive ARP Request packet for unknown IPv4 address, drop.
        """
        with open(
            "tests__legacy/integration/test_frames/rx/arp_unknown_tpa.rx", "rb"
        ) as _:
            packet_rx = _.read()
        self.packet_handler._phrx_ethernet(PacketRx(packet_rx))
        self.assertEqual(
            self.packet_handler.packet_stats_rx,
            PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_request=1,
                arp__op_request__tpa_unknown__drop=1,
            ),
        )
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(),
        )

    def test_packet_flow_rx_tx__icmp6_nd__nd_ns__dad(self) -> None:
        """
        [ICMPv6 ND] Receive ICMPv6 Neighbor Solicitation DAD packet,
        respond with Neighbor Advertisement.
        """
        with open(
            "tests__legacy/integration/test_frames/rx/ip6_icmp6_nd_ns__dad_slla.rx",
            "rb",
        ) as _:
            packet_rx = _.read()
        self.packet_handler._phrx_ethernet(PacketRx(packet_rx))
        self.assertEqual(
            self.packet_handler.packet_stats_rx,
            PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_multicast=1,
                ip6__pre_parse=1,
                ip6__dst_multicast=1,
                icmp6__pre_parse=1,
                icmp6__failed_parse__drop=1,
            ),
        )
