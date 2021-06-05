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
# tests/test_misc_ph.py - unit tests for PacketHandler class
#


from mock import patch
from testslide import TestCase

from misc.ph import PacketHandler


class TestPacketHandler(TestCase):
    def setUp(self):
        super().setUp()

        self.packet_handler = PacketHandler(None)

    @patch("misc.ph.log", return_value=None)
    def test__parse_stack_ip6_address_candidate(self, _):
        from lib.ip6_address import Ip6Address, Ip6Host

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

    @patch("misc.ph.log", return_value=None)
    def test__parse_stack_ip4_host_candidate(self, _):
        from lib.ip4_address import Ip4Address, Ip4Host

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
