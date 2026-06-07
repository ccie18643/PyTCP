################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


"""
This module contains tests for the ARP packet parser operation.

net_proto/tests/unit/protocols/arp/test__arp__parser__operation.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import Ip4Address, MacAddress
from net_proto import (
    ARP__HEADER__LEN,
    ArpHardwareType,
    ArpHeader,
    ArpOperation,
    ArpParser,
    EtherType,
    PacketRx,
)


@parameterized_class(
    [
        {
            "_description": "ARP Request.",
            "_frame_rx": (
                # ARP (Ethernet/IPv4)
                #   Hardware type : 0x0001 (Ethernet)
                #   Protocol type : 0x0800 (IPv4)
                #   HLEN / PLEN   : 6 / 4
                #   Operation     : 1 (Request)
                #   Sender MAC    : 02:00:00:00:00:91
                #   Sender IP     : 10.0.1.91
                #   Target MAC    : 00:00:00:00:00:07
                #   Target IP     : 10.0.1.7
                #
                #   Summary       : Unicast ARP request — "Who has 10.0.1.7? Tell 10.0.1.91."
                b"\x00\x01\x08\x00\x06\x04\x00\x01\x02\x00\x00\x00\x00\x91\x0a\x00"
                b"\x01\x5b\x00\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
            ),
            "_trailing": b"",
            "_results": {
                "header": ArpHeader(
                    oper=ArpOperation.REQUEST,
                    sha=MacAddress("02:00:00:00:00:91"),
                    spa=Ip4Address("10.0.1.91"),
                    tha=MacAddress("00:00:00:00:00:07"),
                    tpa=Ip4Address("10.0.1.7"),
                ),
                "oper": ArpOperation.REQUEST,
                "sha": MacAddress("02:00:00:00:00:91"),
                "spa": Ip4Address("10.0.1.91"),
                "tha": MacAddress("00:00:00:00:00:07"),
                "tpa": Ip4Address("10.0.1.7"),
            },
        },
        {
            "_description": "ARP Reply.",
            "_frame_rx": (
                # ARP (Ethernet/IPv4)
                #   Hardware type : 0x0001 (Ethernet)
                #   Protocol type : 0x0800 (IPv4)
                #   HLEN / PLEN   : 6 / 4
                #   Operation     : 2 (Reply)
                #   Sender MAC    : 02:00:00:00:00:07
                #   Sender IP     : 10.0.1.7
                #   Target MAC    : 02:00:00:00:00:91
                #   Target IP     : 10.0.1.91
                #
                #   Summary       : Unicast ARP reply — "10.0.1.7 is at 02:00:00:00:00:07."
                b"\x00\x01\x08\x00\x06\x04\x00\x02\x02\x00\x00\x00\x00\x07\x0a\x00"
                b"\x01\x07\x02\x00\x00\x00\x00\x91\x0a\x00\x01\x5b"
            ),
            "_trailing": b"",
            "_results": {
                "header": ArpHeader(
                    oper=ArpOperation.REPLY,
                    sha=MacAddress("02:00:00:00:00:07"),
                    spa=Ip4Address("10.0.1.7"),
                    tha=MacAddress("02:00:00:00:00:91"),
                    tpa=Ip4Address("10.0.1.91"),
                ),
                "oper": ArpOperation.REPLY,
                "sha": MacAddress("02:00:00:00:00:07"),
                "spa": Ip4Address("10.0.1.7"),
                "tha": MacAddress("02:00:00:00:00:91"),
                "tpa": Ip4Address("10.0.1.91"),
            },
        },
        {
            "_description": "ARP Request with Ethernet-padding trailer.",
            "_frame_rx": (
                # ARP (Ethernet/IPv4) followed by 18 bytes of padding
                #   Hardware type : 0x0001 (Ethernet)
                #   Protocol type : 0x0800 (IPv4)
                #   HLEN / PLEN   : 6 / 4
                #   Operation     : 1 (Request)
                #   Sender MAC    : 02:00:00:00:00:91
                #   Sender IP     : 10.0.1.91
                #   Target MAC    : 00:00:00:00:00:07
                #   Target IP     : 10.0.1.7
                #   Padding       : 18 bytes of 0x00 (min Ethernet payload = 46, ARP = 28)
                #
                #   Summary       : Valid ARP Request carried in a minimum-sized Ethernet frame.
                b"\x00\x01\x08\x00\x06\x04\x00\x01\x02\x00\x00\x00\x00\x91\x0a\x00"
                b"\x01\x5b\x00\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00"
            ),
            "_trailing": b"\x00" * 18,
            "_results": {
                "header": ArpHeader(
                    oper=ArpOperation.REQUEST,
                    sha=MacAddress("02:00:00:00:00:91"),
                    spa=Ip4Address("10.0.1.91"),
                    tha=MacAddress("00:00:00:00:00:07"),
                    tpa=Ip4Address("10.0.1.7"),
                ),
                "oper": ArpOperation.REQUEST,
                "sha": MacAddress("02:00:00:00:00:91"),
                "spa": Ip4Address("10.0.1.91"),
                "tha": MacAddress("00:00:00:00:00:07"),
                "tpa": Ip4Address("10.0.1.7"),
            },
        },
    ]
)
class TestArpParserOperation(TestCase):
    """
    The ARP packet parser operation tests.
    """

    _description: str
    _frame_rx: bytes
    _trailing: bytes
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Wrap the raw frame in a PacketRx and parse it.
        """

        self._packet_rx = PacketRx(self._frame_rx)
        self._parser = ArpParser(self._packet_rx)

    def test__arp__parser__header(self) -> None:
        """
        Ensure the parser produces the expected 'header' object.

        Reference: RFC 826 (ARP Packet Reception — parse Ethernet/IPv4 layout).
        """

        self.assertEqual(
            self._parser.header,
            self._results["header"],
            msg=f"Unexpected ArpHeader for case: {self._description}",
        )

    def test__arp__parser__header_field_properties(self) -> None:
        """
        Ensure the parser exposes all ARP header fields through its properties.

        Reference: RFC 826 (ARP Packet Reception — parse Ethernet/IPv4 layout).
        """

        self.assertEqual(self._parser.hrtype, ArpHardwareType.ETHERNET, msg="Unexpected 'hrtype'.")
        self.assertEqual(self._parser.prtype, EtherType.IP4, msg="Unexpected 'prtype'.")
        self.assertEqual(self._parser.hrlen, 6, msg="Unexpected 'hrlen'.")
        self.assertEqual(self._parser.prlen, 4, msg="Unexpected 'prlen'.")
        self.assertEqual(self._parser.oper, self._results["oper"], msg="Unexpected 'oper'.")
        self.assertEqual(self._parser.sha, self._results["sha"], msg="Unexpected 'sha'.")
        self.assertEqual(self._parser.spa, self._results["spa"], msg="Unexpected 'spa'.")
        self.assertEqual(self._parser.tha, self._results["tha"], msg="Unexpected 'tha'.")
        self.assertEqual(self._parser.tpa, self._results["tpa"], msg="Unexpected 'tpa'.")

    def test__arp__parser__len(self) -> None:
        """
        Ensure 'len()' on the parser returns the 28-byte header size.

        Reference: RFC 826 (ARP Packet Reception — parse Ethernet/IPv4 layout).
        """

        self.assertEqual(len(self._parser), ARP__HEADER__LEN, msg="Parser length must be 28 bytes.")

    def test__arp__parser__packet_rx_arp_attribute(self) -> None:
        """
        Ensure the parser attaches itself to the PacketRx as the 'arp' field.

        Reference: RFC 826 (ARP Packet Reception — parse Ethernet/IPv4 layout).
        """

        self.assertIs(
            self._packet_rx.arp,
            self._parser,
            msg="PacketRx.arp must reference the ArpParser instance that parsed it.",
        )

    def test__arp__parser__packet_rx_frame_advances(self) -> None:
        """
        Ensure the parser advances the PacketRx frame past the ARP header.

        Reference: RFC 826 (ARP Packet Reception — parse Ethernet/IPv4 layout).
        """

        self.assertEqual(
            bytes(self._packet_rx.frame),
            self._trailing,
            msg="PacketRx.frame must point to the bytes that follow the ARP header.",
        )

    def test__arp__parser__buffer_roundtrip(self) -> None:
        """
        Ensure 'bytes(parser)' yields the ARP header exactly as it appeared on
        the wire.

        Reference: RFC 826 (ARP Packet Reception — parse Ethernet/IPv4 layout).
        """

        self.assertEqual(
            bytes(memoryview(self._parser)),
            self._frame_rx[:ARP__HEADER__LEN],
            msg="Parser buffer must reproduce the original header bytes.",
        )

    def test__arp__parser__str_format(self) -> None:
        """
        Ensure the parser '__str__()' includes operation, sender, target, and
        length information.

        Reference: RFC 826 (ARP Packet Reception — parse Ethernet/IPv4 layout).
        """

        representation = str(self._parser)

        self.assertIn("ARP", representation, msg="String form must start with 'ARP'.")
        self.assertIn(str(self._results["spa"]), representation, msg="String form must include SPA.")
        self.assertIn(str(self._results["sha"]), representation, msg="String form must include SHA.")
        self.assertIn(str(self._results["tpa"]), representation, msg="String form must include TPA.")
        self.assertIn(str(self._results["tha"]), representation, msg="String form must include THA.")
        self.assertIn("len 28", representation, msg="String form must include length marker 'len 28'.")

    def test__arp__parser__repr_format(self) -> None:
        """
        Ensure the parser '__repr__()' wraps the ArpHeader repr.

        Reference: RFC 826 (ARP Packet Reception — parse Ethernet/IPv4 layout).
        """

        self.assertEqual(
            repr(self._parser),
            f"ArpParser(header={self._results['header']!r})",
            msg="Parser repr must wrap the ArpHeader repr.",
        )
