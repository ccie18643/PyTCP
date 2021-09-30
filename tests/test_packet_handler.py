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
# tests/test_packet_handler.py - unit tests for PacketHandler class
#


from testslide import StrictMock, TestCase

from pytcp.lib.ip4_address import Ip4Address, Ip4Host
from pytcp.lib.ip6_address import Ip6Address, Ip6Host
from pytcp.lib.mac_address import MacAddress
from pytcp.misc.packet import PacketRx
from pytcp.misc.packet_stats import PacketStatsRx
from pytcp.subsystems.arp_cache import ArpCache
from pytcp.subsystems.nd_cache import NdCache
from pytcp.subsystems.packet_handler import PacketHandler
from pytcp.subsystems.tx_ring import TxRing

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
    "IP6_SUPPORT": True,
    "IP4_SUPPORT": True,
    "PACKET_INTEGRITY_CHECK": True,
    "PACKET_SANITY_CHECK": True,
    "TAP_MTU": 1500,
    "UDP_ECHO_NATIVE_DISABLE": False,
}


class TestPacketHandler(TestCase):
    def setUp(self):
        super().setUp()

        self._patch_logger()
        self._patch_config()

        self.arp_cache_mock = StrictMock(ArpCache)
        self.nd_cache_mock = StrictMock(NdCache)
        self.tx_ring_mock = StrictMock(TxRing)

        self.mock_callable(self.arp_cache_mock, "find_entry").for_call(Ip4Address("192.168.9.102")).to_return_value(MacAddress("52:54:00:df:85:37"))
        self.mock_callable(self.nd_cache_mock, "find_entry").for_call(Ip6Address("2603:9000:e307:9f09::1fa1")).to_return_value(MacAddress("52:54:00:df:85:37"))
        self.mock_callable(self.tx_ring_mock, "enqueue").with_implementation(lambda _: _.assemble(self.frame_tx))

        self.packet_handler = PacketHandler(None)
        self.packet_handler.mac_address = MacAddress("02:00:00:77:77:77")
        self.packet_handler.ip4_host = [Ip4Host("192.168.9.7/24")]
        self.packet_handler.ip6_host = [Ip6Host("2603:9000:e307:9f09:0:ff:fe77:7777/64")]
        self.packet_handler.arp_cache = self.arp_cache_mock
        self.packet_handler.nd_cache = self.nd_cache_mock
        self.packet_handler.tx_ring = self.tx_ring_mock

        self.frame_tx = memoryview(bytearray(2048))

    def _patch_config(self):
        for module in PACKET_HANDLER_MODULES:
            for variable, value in CONFIG_PATCHES.items():
                try:
                    self.patch_attribute(f"{module}.config", variable, value)
                except ModuleNotFoundError:
                    continue

    def _patch_logger(self):
        for module in PACKET_HANDLER_MODULES:
            try:
                self.mock_callable(module, "log").to_return_value(None)
            except ModuleNotFoundError:
                continue

    def test_parse_stack_ip6_address_candidate(self):
        sample = [
            ("FE80::7/64", None),  # valid link loal address [pass]
            ("FE80::77/64", None),  # valid link local address [pass]
            ("FE80::7777/64", None),  # valid link local address [pass]
            ("FE80::7777/64", None),  # valid duplicated address [fail]
            ("FE80::9999/64", "FE80::1"),  # valid link local address with default gateway [fail]
            ("2007::1111/64", "DUPA"),  # valid global address with malformed gateway [fail]
            ("ZHOPA", None),  # malformed address [fail]
            ("2099::99/64", "2222::99"),  # valid global address with out of subnet gateway [fail]
            ("2007::7/64", "FE80::1"),  # valid global address with valid link local gateway [pass]
            ("2009::9/64", "2009::1"),  # valid global address with valid global gateway [pass]
            ("2015::15/64", None),  # valid global address with no gateway [pass]
        ]
        expected = [
            Ip6Host("fe80::7/64"),
            Ip6Host("fe80::77/64"),
            Ip6Host("fe80::7777/64"),
            Ip6Host("2007::7/64"),
            Ip6Host("2009::9/64"),
            Ip6Host("2015::15/64"),
        ]
        result = self.packet_handler._parse_stack_ip6_host_candidate(sample)
        self.assertEqual(result, expected)
        expected = [None, None, None, Ip6Address("fe80::1"), Ip6Address("2009::1"), None]
        result = [ip6_address.gateway for ip6_address in result]
        self.assertEqual(result, expected)

    def test_parse_stack_ip4_host_candidate(self):
        sample = [
            ("192.168.9.7/24", "192.168.9.1"),  # valid address and valid gateway [pass]
            ("192.168.9.77/24", "192.168.9.1"),  # valid address and valid gateway [pass]
            ("224.0.0.1/24", "192.168.9.1"),  # invalid address [fail]
            ("DUPA", "192.168.9.1"),  # malformed address [fail]
            ("192.168.9.99/24", "DUPA"),  # malformed gateway [fail]
            ("192.168.9.77/24", "192.168.9.1"),  # duplicate address [fail]
            ("192.168.9.170/24", "10.0.0.1"),  # valid address but invalid gateway [fail]
            ("192.168.9.171/24", "192.168.9.0"),  # valid address but test invalid gateway [fail]
            ("192.168.9.172/24", "192.168.9.172"),  # valid address but invalid gateway [fail]
            ("192.168.9.173/24", "192.168.9.255"),  # valid address but invalid gateway [fail]
            ("192.168.9.0/24", "192.168.9.1"),  # invalid address [fail]
            ("192.168.9.255/24", "192.168.9.1"),  # invalid address [fail]
            ("0.0.0.0/0", None),  # invalid address [fail]
            ("192.168.9.102/24", None),  # valid address and no gateway [pass]
            ("172.16.17.7/24", "172.16.17.1"),  # valid address and valid gateway [pass]
            ("10.10.10.7/24", "10.10.10.1"),  # valid address and valid gateway [pass]
        ]
        expected = [
            Ip4Host("192.168.9.7/24"),
            Ip4Host("192.168.9.77/24"),
            Ip4Host("192.168.9.102/24"),
            Ip4Host("172.16.17.7/24"),
            Ip4Host("10.10.10.7/24"),
        ]
        result = self.packet_handler._parse_stack_ip4_host_candidate(sample)
        self.assertEqual(result, expected)
        expected = [Ip4Address("192.168.9.1"), Ip4Address("192.168.9.1"), None, Ip4Address("172.16.17.1"), Ip4Address("10.10.10.1")]
        result = [ip4_host.gateway for ip4_host in result]
        self.assertEqual(result, expected)

    def test_packet_flow__ip4_ping(self):
        with open("tests/frames/ip4_ping.rx", "rb") as _:
            frame_rx = _.read()
        with open("tests/frames/ip4_ping.tx", "rb") as _:
            frame_tx = _.read()
        self.packet_handler._phrx_ether(PacketRx(frame_rx))
        self.assertEqual(
            self.packet_handler.packet_stats_rx,
            PacketStatsRx(
                ether_pre_parse=1,
                ether_unicast=1,
                ip4_pre_parse=1,
                ip4_unicast=1,
                icmp4_pre_parse=1,
                icmp4_echo_request=1,
            ),
        )
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_packet_flow__ip4_udp_to_closed_port(self):
        with open("tests/frames/ip4_udp_to_closed_port.rx", "rb") as _:
            frame_rx = _.read()
        with open("tests/frames/ip4_udp_to_closed_port.tx", "rb") as _:
            frame_tx = _.read()
        self.packet_handler._phrx_ether(PacketRx(frame_rx))
        self.assertEqual(
            self.packet_handler.packet_stats_rx,
            PacketStatsRx(
                ether_pre_parse=1,
                ether_unicast=1,
                ip4_pre_parse=1,
                ip4_unicast=1,
                udp_pre_parse=1,
                udp_respond_icmp4_unreachable=1,
            ),
        )
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_packet_flow__ip4_udp_echo(self):
        with open("tests/frames/ip4_udp_echo.rx", "rb") as _:
            frame_rx = _.read()
        with open("tests/frames/ip4_udp_echo.tx", "rb") as _:
            frame_tx = _.read()
        self.packet_handler._phrx_ether(PacketRx(frame_rx))
        self.assertEqual(
            self.packet_handler.packet_stats_rx,
            PacketStatsRx(
                ether_pre_parse=1,
                ether_unicast=1,
                ip4_pre_parse=1,
                ip4_unicast=1,
                udp_pre_parse=1,
                udp_echo_native=1,
            ),
        )
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_packet_flow__ip4_tcp_syn_to_closed_port(self):
        with open("tests/frames/ip4_tcp_syn_to_closed_port.rx", "rb") as _:
            frame_rx = _.read()
        with open("tests/frames/ip4_tcp_syn_to_closed_port.tx", "rb") as _:
            frame_tx = _.read()
        self.packet_handler._phrx_ether(PacketRx(frame_rx))
        self.assertEqual(
            self.packet_handler.packet_stats_rx,
            PacketStatsRx(
                ether_pre_parse=1,
                ether_unicast=1,
                ip4_pre_parse=1,
                ip4_unicast=1,
                tcp_pre_parse=1,
                tcp_respond_no_socket_match_rst=1,
            ),
        )
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_packet_flow__ip6_ping(self):
        with open("tests/frames/ip6_ping.rx", "rb") as _:
            frame_rx = _.read()
        with open("tests/frames/ip6_ping.tx", "rb") as _:
            frame_tx = _.read()
        self.packet_handler._phrx_ether(PacketRx(frame_rx))
        self.assertEqual(
            self.packet_handler.packet_stats_rx,
            PacketStatsRx(
                ether_pre_parse=1,
                ether_unicast=1,
                ip6_pre_parse=1,
                ip6_unicast=1,
                icmp6_pre_parse=1,
                icmp6_echo_request=1,
            ),
        )
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_packet_flow__ip6_udp_to_closed_port(self):
        with open("tests/frames/ip6_udp_to_closed_port.rx", "rb") as _:
            frame_rx = _.read()
        with open("tests/frames/ip6_udp_to_closed_port.tx", "rb") as _:
            frame_tx = _.read()
        self.packet_handler._phrx_ether(PacketRx(frame_rx))
        self.assertEqual(
            self.packet_handler.packet_stats_rx,
            PacketStatsRx(
                ether_pre_parse=1,
                ether_unicast=1,
                ip6_pre_parse=1,
                ip6_unicast=1,
                udp_pre_parse=1,
                udp_respond_icmp6_unreachable=1,
            ),
        )
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_packet_flow__ip6_udp_echo(self):
        with open("tests/frames/ip6_udp_echo.rx", "rb") as _:
            frame_rx = _.read()
        with open("tests/frames/ip6_udp_echo.tx", "rb") as _:
            frame_tx = _.read()
        self.packet_handler._phrx_ether(PacketRx(frame_rx))
        self.assertEqual(
            self.packet_handler.packet_stats_rx,
            PacketStatsRx(
                ether_pre_parse=1,
                ether_unicast=1,
                ip6_pre_parse=1,
                ip6_unicast=1,
                udp_pre_parse=1,
                udp_echo_native=1,
            ),
        )
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_packet_flow__ip6_tcp_syn_to_closed_port(self):
        with open("tests/frames/ip6_tcp_syn_to_closed_port.rx", "rb") as _:
            frame_rx = _.read()
        with open("tests/frames/ip6_tcp_syn_to_closed_port.tx", "rb") as _:
            frame_tx = _.read()
        self.packet_handler._phrx_ether(PacketRx(frame_rx))
        self.assertEqual(
            self.packet_handler.packet_stats_rx,
            PacketStatsRx(
                ether_pre_parse=1,
                ether_unicast=1,
                ip6_pre_parse=1,
                ip6_unicast=1,
                tcp_pre_parse=1,
                tcp_respond_no_socket_match_rst=1,
            ),
        )
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_packet_flow__arp_request(self):
        with open("tests/frames/arp_request.rx", "rb") as _:
            frame_rx = _.read()
        with open("tests/frames/arp_request.tx", "rb") as _:
            frame_tx = _.read()
        self.mock_callable(self.arp_cache_mock, "add_entry").to_return_value(None).and_assert_called_once()
        self.packet_handler._phrx_ether(PacketRx(frame_rx))
        self.assertEqual(
            self.packet_handler.packet_stats_rx,
            PacketStatsRx(
                ether_pre_parse=1,
                ether_broadcast=1,
                arp_pre_parse=1,
                arp_op_request=1,
                arp_op_request_update_cache=1,
            ),
        )
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)
