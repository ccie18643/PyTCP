#!/usr/bin/env python3

from testslide import StrictMock, TestCase

from misc.ph import PacketHandler


class TestPacketHandler(TestCase):
    def setUp(self):
        super().setUp()
        self.packet_handler = PacketHandler(None)
        self.packet_handler._logger = StrictMock()
        self.packet_handler._logger.debug = lambda _: None
        self.packet_handler._logger.warning = lambda _: None

    def test__parse_stack_ip6_address_candidate(self):
        from misc.ipv6_address import IPv6Address, IPv6Interface

        sample = [
            ("FE80::7/64", ""),  # valid link loal address [pass]
            ("FE80::77/64", ""),  # valid link local address [pass]
            ("FE80::7777/64", ""),  # valid link local address [pass]
            ("FE80::7777/64", ""),  # valid duplicated address [fail]
            ("FE80::9999/64", "FE80::1"),  # valid link local address with default gateway [fail]
            ("2007::1111/64", "DUPA"),  # valid global address with malformed gateway [fail]
            ("ZHOPA", ""),  # malformed address [fail]
            ("2099::99/64", "2222::99"),  # valid global address with out of subnet gateway [fail]
            ("2007::7/64", "FE80::1"),  # valid global address with valid link local gateway [pass]
            ("2009::9/64", "2009::1"),  # valid global address with valid global gateway [pass]
            ("2015::15/64", ""),  # valid global address with no gateway [pass]
        ]
        expected = [
            IPv6Interface("fe80::7/64"),
            IPv6Interface("fe80::77/64"),
            IPv6Interface("fe80::7777/64"),
            IPv6Interface("2007::7/64"),
            IPv6Interface("2009::9/64"),
            IPv6Interface("2015::15/64"),
        ]
        result = self.packet_handler._parse_stack_ip6_address_candidate(sample)
        self.assertEqual(result, expected)
        expected = [None, None, None, IPv6Address("fe80::1"), IPv6Address("2009::1"), None]
        result = [ip6_address.gateway for ip6_address in result]
        self.assertEqual(result, expected)

    def test__parse_stack_ip4_address_candidate(self):
        from misc.ipv4_address import IPv4Address, IPv4Interface

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
            ("0.0.0.0/0", ""),  # invalid address [fail]
            ("192.168.9.102/24", ""),  # valid address and no gateway [pass]
            ("172.16.17.7/24", "172.16.17.1"),  # valid address and valid gateway [pass]
            ("10.10.10.7/24", "10.10.10.1"),  # valid address and valid gateway [pass]
        ]
        expected = [
            IPv4Interface("192.168.9.7/24"),
            IPv4Interface("192.168.9.77/24"),
            IPv4Interface("192.168.9.102/24"),
            IPv4Interface("172.16.17.7/24"),
            IPv4Interface("10.10.10.7/24"),
        ]
        result = self.packet_handler._parse_stack_ip4_address_candidate(sample)
        self.assertEqual(result, expected)
        expected = [IPv4Address("192.168.9.1"), IPv4Address("192.168.9.1"), None, IPv4Address("172.16.17.1"), IPv4Address("10.10.10.1")]
        result = [ip4_address.gateway for ip4_address in result]
        self.assertEqual(result, expected)
