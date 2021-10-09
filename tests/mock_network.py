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
# tests/mock_network.py - module used to mock network for packet flow tests
#


from testslide import StrictMock

from pytcp.lib.ip4_address import Ip4Address, Ip4Host
from pytcp.lib.ip6_address import Ip6Address, Ip6Host
from pytcp.lib.mac_address import MacAddress
from pytcp.subsystems.arp_cache import ArpCache
from pytcp.subsystems.nd_cache import NdCache
from pytcp.subsystems.packet_handler import PacketHandler
from pytcp.subsystems.tx_ring import TxRing

#
#           .7  10.0.1.0/24  .1          .1  10.0.2.0/24  .50
#   [STACK] ------------------- [ROUTER] -------------------- [HOST C]
#             |
#             |   .91
#             |------ [HOST A] (working arp/nd resolution)
#             |
#             |   .92
#             |------ [HOST B] (not working arp/nd resolution)
#


class MockNetworkSettings:
    """Mock network setting to mimic the above network"""

    def __init__(self):
        self.stack_mac_address = MacAddress("02:00:00:00:00:07")
        self.stack_ip4_host = Ip4Host("10.0.1.7/24")
        self.stack_ip4_gateway = Ip4Address("10.0.1.1")
        self.stack_ip4_host.gateway = self.stack_ip4_gateway
        self.stack_ip4_gateway_mac_address = MacAddress("02:00:00:00:00:01")
        self.stack_ip6_host = Ip6Host("2001:db8:0:1::7/64")
        self.stack_ip6_gateway = Ip6Address("2001::1")
        self.stack_ip6_host.gateway = self.stack_ip6_gateway
        self.stack_ip6_gateway_mac_address = MacAddress("02:00:00:00:00:01")

        self.host_a_mac_address = MacAddress("02:00:00:00:00:91")
        self.host_a_ip4_address = Ip4Address("10.0.1.91")
        self.host_a_ip6_address = Ip6Address("2001:db8:0:1::91")

        self.host_b_ip4_address = Ip4Address("10.0.1.92")
        self.host_b_ip6_address = Ip6Address("2001:db8:0:1::92")

        self.host_c_ip4_address = Ip4Address("10.0.2.50")
        self.host_c_ip6_address = Ip6Address("2001:db8:0:2::50")

        self.mac_unspecified = MacAddress("00:00:00:00:00:00")
        self.mac_broadcast = MacAddress("ff:ff:ff:ff:ff:ff")
        self.ip4_unspecified = Ip4Address("0.0.0.0")
        self.ip4_limited_broadcast = Ip4Address("255.255.255.255")
        self.ip4_multicast_all_nodes = Ip4Address("224.0.0.1")
        self.ip6_unspecified = Ip6Address("::")
        self.ip6_multicast_all_nodes = Ip6Address("ff01::1")


PACKET_HANDLER_MODULES = [
    "pytcp.subsystems.packet_handler",
    "protocols.ether.phrx",
    "protocols.ether.phtx",
    "protocols.arp.phrx",
    "protocols.arp.phtx",
    "protocols.ip4.phrx",
    "protocols.ip4.phtx",
    "protocols.ip6.phrx",
    "protocols.ip6.phtx",
    "protocols.icmp4.phrx",
    "protocols.icmp4.phtx",
    "protocols.icmp6.phrx",
    "protocols.icmp6.phtx",
    "protocols.udp.phrx",
    "protocols.udp.phtx",
    "protocols.tcp.phrx",
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
    "IP4_DEFAULT_TTL": 64,
    "IP6_DEFAULT_HOP": 64,
}


def patch_config(self, *, enable_log=False):
    """Patch critical config setting for all packet handler modules"""

    for module in PACKET_HANDLER_MODULES:
        for variable, value in CONFIG_PATCHES.items():
            if enable_log and variable == "LOG_CHANEL":
                value = {
                    "stack",
                    "arp-c",
                    "nd-c",
                    "ether",
                    "arp",
                    "ip4",
                    "ip6",
                    "icmp4",
                    "icmp6",
                    "udp",
                    "tcp",
                    "socket",
                }
            try:
                self.patch_attribute(f"{module}.config", variable, value)
            except ModuleNotFoundError:
                continue


def setup_mock_packet_handler(self):
    """Prepare packet handler so it can pass packets without need of being physically connected to the network"""

    self.arp_cache_mock = StrictMock(ArpCache)
    self.nd_cache_mock = StrictMock(NdCache)
    self.tx_ring_mock = StrictMock(TxRing)

    self.mock_callable(self.arp_cache_mock, "find_entry").for_call(self.mns.host_a_ip4_address).to_return_value(self.mns.host_a_mac_address)
    self.mock_callable(self.arp_cache_mock, "find_entry").for_call(self.mns.host_b_ip4_address).to_return_value(None)
    self.mock_callable(self.arp_cache_mock, "find_entry").for_call(self.mns.stack_ip4_gateway).to_return_value(self.mns.stack_ip4_gateway_mac_address)
    self.mock_callable(self.nd_cache_mock, "find_entry").for_call(self.mns.host_a_ip6_address).to_return_value(self.mns.host_a_mac_address)
    self.mock_callable(self.nd_cache_mock, "find_entry").for_call(self.mns.host_b_ip6_address).to_return_value(None)
    self.mock_callable(self.nd_cache_mock, "find_entry").for_call(self.mns.stack_ip6_gateway).to_return_value(self.mns.stack_ip6_gateway_mac_address)
    self.mock_callable(self.tx_ring_mock, "enqueue").with_implementation(
        lambda packet_tx: packet_tx.assemble(self.frame_tx) or self.frames_tx.append(self.frame_tx)
    )

    self.packet_handler = PacketHandler(None)
    self.packet_handler.mac_unicast = self.mns.stack_mac_address
    self.packet_handler.mac_multicast = [self.mns.stack_ip6_host.address.solicited_node_multicast.multicast_mac]
    self.packet_handler.ip4_host = [self.mns.stack_ip4_host]
    self.packet_handler.ip4_multicast = [self.mns.ip4_multicast_all_nodes]
    self.packet_handler.ip6_host = [self.mns.stack_ip6_host]
    self.packet_handler.ip6_multicast = [self.mns.ip6_multicast_all_nodes, self.mns.stack_ip6_host.address.solicited_node_multicast]
    self.packet_handler.arp_cache = self.arp_cache_mock
    self.packet_handler.nd_cache = self.nd_cache_mock
    self.packet_handler.tx_ring = self.tx_ring_mock

    self.frame_tx = memoryview(bytearray(2048))
    self.frames_tx = []
