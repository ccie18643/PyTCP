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
This module contains tests for the Ethernet II packet assembler operation.

The assembler composes a 14-byte EthernetHeader (dst + src + EtherType) and
stacks an upper-layer payload via the Python 3.12 generic type envelope. The
'type' field is derived from the payload through EtherType.from_proto().

net_proto/tests/unit/protocols/ethernet/test__ethernet__assembler__operation.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import Ip4Address, MacAddress
from net_proto import (
    ArpAssembler,
    EthernetAssembler,
    EthernetHeader,
    EtherType,
    Ip4Assembler,
    Ip6Assembler,
    RawAssembler,
)
from net_proto.lib.buffer import Buffer


@parameterized_class(
    [
        {
            "_description": "Ethernet packet with a 16-byte Raw payload.",
            "_kwargs": {
                "ethernet__src": MacAddress("78:89:9a:ab:bc:cd"),
                "ethernet__dst": MacAddress("11:22:33:44:55:66"),
                "ethernet__payload": RawAssembler(raw__payload=b"0123456789ABCDEF"),
            },
            "_results": {
                "__len__": 30,
                "__str__": "ETHER 78:89:9a:ab:bc:cd > 11:22:33:44:55:66, type Raw, len 30 (14+16)",
                "__repr__": (
                    "EthernetAssembler(header=EthernetHeader(dst=MacAddress('11:22:33:44:55:66'), "
                    "src=MacAddress('78:89:9a:ab:bc:cd'), type=<EtherType.RAW: 65535>), "
                    "payload=RawAssembler(raw__payload=b'0123456789ABCDEF'))"
                ),
                "__bytes__": (
                    # Ethernet II
                    #   Destination MAC : 11:22:33:44:55:66
                    #   Source MAC      : 78:89:9a:ab:bc:cd
                    #   Ethertype       : 0xffff (Raw)
                    #   Payload         : b"0123456789ABCDEF" (16 bytes)
                    b"\x11\x22\x33\x44\x55\x66\x78\x89\x9a\xab\xbc\xcd\xff\xff"
                    b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
                "dst": MacAddress("11:22:33:44:55:66"),
                "src": MacAddress("78:89:9a:ab:bc:cd"),
                "type": EtherType.RAW,
                "header": EthernetHeader(
                    dst=MacAddress("11:22:33:44:55:66"),
                    src=MacAddress("78:89:9a:ab:bc:cd"),
                    type=EtherType.RAW,
                ),
                "payload": RawAssembler(raw__payload=b"0123456789ABCDEF"),
            },
        },
        {
            "_description": "Ethernet packet with a 1500-byte Raw payload (MTU-sized).",
            "_kwargs": {
                "ethernet__dst": MacAddress("a1:b2:c3:d4:e5:f6"),
                "ethernet__src": MacAddress("12:13:14:15:16:17"),
                "ethernet__payload": RawAssembler(raw__payload=b"X" * 1500),
            },
            "_results": {
                "__len__": 1514,
                "__str__": "ETHER 12:13:14:15:16:17 > a1:b2:c3:d4:e5:f6, type Raw, len 1514 (14+1500)",
                "__repr__": (
                    "EthernetAssembler(header=EthernetHeader(dst=MacAddress('a1:b2:c3:d4:e5:f6'), "
                    "src=MacAddress('12:13:14:15:16:17'), type=<EtherType.RAW: 65535>), "
                    f"payload=RawAssembler(raw__payload=b'{'X' * 1500}'))"
                ),
                "__bytes__": (
                    # Ethernet II
                    #   Destination MAC : a1:b2:c3:d4:e5:f6
                    #   Source MAC      : 12:13:14:15:16:17
                    #   Ethertype       : 0xffff (Raw)
                    #   Payload         : b"X" * 1500
                    b"\xa1\xb2\xc3\xd4\xe5\xf6\x12\x13\x14\x15\x16\x17\xff\xff"
                    + b"X" * 1500
                ),
                "dst": MacAddress("a1:b2:c3:d4:e5:f6"),
                "src": MacAddress("12:13:14:15:16:17"),
                "type": EtherType.RAW,
                "header": EthernetHeader(
                    dst=MacAddress("a1:b2:c3:d4:e5:f6"),
                    src=MacAddress("12:13:14:15:16:17"),
                    type=EtherType.RAW,
                ),
                "payload": RawAssembler(raw__payload=b"X" * 1500),
            },
        },
        {
            "_description": "Ethernet packet carrying a Raw payload tagged as IPv4 via 'ether_type' override.",
            "_kwargs": {
                "ethernet__dst": MacAddress("11:22:33:44:55:66"),
                "ethernet__src": MacAddress("78:89:9a:ab:bc:cd"),
                "ethernet__payload": RawAssembler(
                    raw__payload=b"\xde\xad\xbe\xef",
                    ether_type=EtherType.IP4,
                ),
            },
            "_results": {
                "__len__": 18,
                "__str__": "ETHER 78:89:9a:ab:bc:cd > 11:22:33:44:55:66, type IPv4, len 18 (14+4)",
                "__repr__": (
                    "EthernetAssembler(header=EthernetHeader(dst=MacAddress('11:22:33:44:55:66'), "
                    "src=MacAddress('78:89:9a:ab:bc:cd'), type=<EtherType.IP4: 2048>), "
                    "payload=RawAssembler(raw__payload=b'\\xde\\xad\\xbe\\xef'))"
                ),
                "__bytes__": (
                    # Ethernet II
                    #   Destination MAC : 11:22:33:44:55:66
                    #   Source MAC      : 78:89:9a:ab:bc:cd
                    #   Ethertype       : 0x0800 (IPv4, inferred from Raw.ether_type)
                    #   Payload         : b"\xde\xad\xbe\xef" (4 bytes)
                    b"\x11\x22\x33\x44\x55\x66\x78\x89\x9a\xab\xbc\xcd\x08\x00"
                    b"\xde\xad\xbe\xef"
                ),
                "dst": MacAddress("11:22:33:44:55:66"),
                "src": MacAddress("78:89:9a:ab:bc:cd"),
                "type": EtherType.IP4,
                "header": EthernetHeader(
                    dst=MacAddress("11:22:33:44:55:66"),
                    src=MacAddress("78:89:9a:ab:bc:cd"),
                    type=EtherType.IP4,
                ),
                "payload": RawAssembler(raw__payload=b"\xde\xad\xbe\xef", ether_type=EtherType.IP4),
            },
        },
    ]
)
class TestEthernetAssemblerOperation(TestCase):
    """
    The Ethernet packet assembler operation tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Initialize the Ethernet packet assembler with the testcase arguments.
        """

        self._ethernet__assembler = EthernetAssembler(**self._kwargs)

    def test__ethernet__assembler__len(self) -> None:
        """
        Ensure the Ethernet packet assembler '__len__()' method returns a
        correct value (header + payload bytes).

        Reference: RFC 894 (Ethernet II frame — dst, src, EtherType).
        """

        self.assertEqual(
            len(self._ethernet__assembler),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__ethernet__assembler__str(self) -> None:
        """
        Ensure the Ethernet packet assembler '__str__()' method returns the
        canonical log line.

        Reference: RFC 894 (Ethernet II frame — dst, src, EtherType).
        """

        self.assertEqual(
            str(self._ethernet__assembler),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__ethernet__assembler__repr(self) -> None:
        """
        Ensure the Ethernet packet assembler '__repr__()' method returns a
        string that can rebuild the header and embeds the payload repr.

        Reference: RFC 894 (Ethernet II frame — dst, src, EtherType).
        """

        self.assertEqual(
            repr(self._ethernet__assembler),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__ethernet__assembler__bytes(self) -> None:
        """
        Ensure the Ethernet packet assembler '__bytes__()' method emits the
        expected on-wire frame.

        Reference: RFC 894 (Ethernet II frame — dst, src, EtherType).
        """

        self.assertEqual(
            bytes(self._ethernet__assembler),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__ethernet__assembler__dst(self) -> None:
        """
        Ensure the Ethernet packet assembler 'dst' property returns a correct
        value.

        Reference: RFC 894 (Ethernet II frame — dst, src, EtherType).
        """

        self.assertEqual(
            self._ethernet__assembler.dst,
            self._results["dst"],
            msg=f"Unexpected 'dst' for case: {self._description}",
        )

    def test__ethernet__assembler__src(self) -> None:
        """
        Ensure the Ethernet packet assembler 'src' property returns a correct
        value.

        Reference: RFC 894 (Ethernet II frame — dst, src, EtherType).
        """

        self.assertEqual(
            self._ethernet__assembler.src,
            self._results["src"],
            msg=f"Unexpected 'src' for case: {self._description}",
        )

    def test__ethernet__assembler__type(self) -> None:
        """
        Ensure the Ethernet packet assembler 'type' property returns the
        EtherType inferred from the payload via EtherType.from_proto().

        Reference: RFC 894 (Ethernet II frame — dst, src, EtherType).
        """

        self.assertEqual(
            self._ethernet__assembler.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__ethernet__assembler__header(self) -> None:
        """
        Ensure the Ethernet packet assembler 'header' property exposes the
        fully populated EthernetHeader.

        Reference: RFC 894 (Ethernet II frame — dst, src, EtherType).
        """

        self.assertEqual(
            self._ethernet__assembler.header,
            self._results["header"],
            msg=f"Unexpected 'header' for case: {self._description}",
        )

    def test__ethernet__assembler__payload(self) -> None:
        """
        Ensure the Ethernet packet assembler 'payload' property returns the
        wrapped upper-layer assembler.

        Reference: RFC 894 (Ethernet II frame — dst, src, EtherType).
        """

        self.assertEqual(
            self._ethernet__assembler.payload,
            self._results["payload"],
            msg=f"Unexpected 'payload' for case: {self._description}",
        )

    def test__ethernet__assembler__assemble(self) -> None:
        """
        Ensure the Ethernet packet assembler 'assemble()' method appends the
        header + payload buffers that concatenate to the expected wire image.

        Reference: RFC 894 (Ethernet II frame — dst, src, EtherType).
        """

        buffers: list[Buffer] = []

        self._ethernet__assembler.assemble(buffers)

        self.assertEqual(
            b"".join(buffers),
            self._results["__bytes__"],
            msg=f"Unexpected assembled buffers for case: {self._description}",
        )

    def test__ethernet__assembler__tracker_is_inherited_from_payload(self) -> None:
        """
        Ensure the Ethernet assembler reuses the payload's Tracker so that
        upstream TX log lines remain correlated with the payload assembler.

        Reference: RFC 894 (Ethernet II frame — dst, src, EtherType).
        """

        self.assertIs(
            self._ethernet__assembler.tracker,
            self._kwargs["ethernet__payload"].tracker,
            msg=f"Tracker must be inherited from payload for case: {self._description}",
        )


class TestEthernetAssemblerEtherTypeFromProto(TestCase):
    """
    Coverage for the EtherType inference performed by EtherType.from_proto().

    These tests exercise the Arp / Ip4 / Ip6 branches of EtherType.from_proto
    which parameterized Raw-payload cases cannot reach.
    """

    def test__ethernet__assembler__infers_arp_ethertype(self) -> None:
        """
        Ensure wrapping an ArpAssembler yields EtherType.ARP (0x0806).

        Reference: RFC 894 (Ethernet II frame — dst, src, EtherType).
        """

        assembler = EthernetAssembler(
            ethernet__src=MacAddress("00:11:22:33:44:55"),
            ethernet__dst=MacAddress("ff:ff:ff:ff:ff:ff"),
            ethernet__payload=ArpAssembler(
                arp__sha=MacAddress("00:11:22:33:44:55"),
                arp__spa=Ip4Address("10.0.0.1"),
                arp__tha=MacAddress(),
                arp__tpa=Ip4Address("10.0.0.2"),
            ),
        )

        self.assertEqual(
            assembler.type,
            EtherType.ARP,
            msg="ARP payload must set the Ethernet 'type' field to 0x0806.",
        )
        self.assertEqual(
            bytes(assembler)[12:14],
            b"\x08\x06",
            msg="On-wire ethertype bytes must encode ARP as 0x0806.",
        )

    def test__ethernet__assembler__infers_ip4_ethertype(self) -> None:
        """
        Ensure wrapping an Ip4Assembler yields EtherType.IP4 (0x0800).

        Reference: RFC 894 (Ethernet II frame — dst, src, EtherType).
        """

        assembler = EthernetAssembler(
            ethernet__src=MacAddress("00:11:22:33:44:55"),
            ethernet__dst=MacAddress("aa:bb:cc:dd:ee:ff"),
            ethernet__payload=Ip4Assembler(),
        )

        self.assertEqual(
            assembler.type,
            EtherType.IP4,
            msg="IPv4 payload must set the Ethernet 'type' field to 0x0800.",
        )
        self.assertEqual(
            bytes(assembler)[12:14],
            b"\x08\x00",
            msg="On-wire ethertype bytes must encode IPv4 as 0x0800.",
        )

    def test__ethernet__assembler__infers_ip6_ethertype(self) -> None:
        """
        Ensure wrapping an Ip6Assembler yields EtherType.IP6 (0x86dd).

        Reference: RFC 894 (Ethernet II frame — dst, src, EtherType).
        """

        assembler = EthernetAssembler(
            ethernet__src=MacAddress("00:11:22:33:44:55"),
            ethernet__dst=MacAddress("aa:bb:cc:dd:ee:ff"),
            ethernet__payload=Ip6Assembler(),
        )

        self.assertEqual(
            assembler.type,
            EtherType.IP6,
            msg="IPv6 payload must set the Ethernet 'type' field to 0x86dd.",
        )
        self.assertEqual(
            bytes(assembler)[12:14],
            b"\x86\xdd",
            msg="On-wire ethertype bytes must encode IPv6 as 0x86dd.",
        )


class TestEthernetAssemblerDefaults(TestCase):
    """
    The Ethernet assembler default-value tests.
    """

    def test__ethernet__assembler__defaults(self) -> None:
        """
        Ensure the assembler default constructor yields a header-only frame
        with zeroed MAC addresses and a Raw payload (EtherType 0xffff).

        Reference: RFC 894 (Ethernet II frame — dst, src, EtherType).
        """

        assembler = EthernetAssembler()

        self.assertEqual(
            assembler.dst,
            MacAddress(),
            msg="Default 'dst' must be the zero MAC address.",
        )
        self.assertEqual(
            assembler.src,
            MacAddress(),
            msg="Default 'src' must be the zero MAC address.",
        )
        self.assertEqual(
            assembler.type,
            EtherType.RAW,
            msg="Default payload must set the 'type' field to Raw (0xffff).",
        )
        self.assertEqual(
            len(assembler),
            14,
            msg="Default assembler must be header-sized with an empty Raw payload.",
        )
        self.assertEqual(
            bytes(assembler),
            # Ethernet II
            #   Destination MAC : 00:00:00:00:00:00
            #   Source MAC      : 00:00:00:00:00:00
            #   Ethertype       : 0xffff (Raw)
            #   Payload         : empty
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff",
            msg="Default on-wire frame must match the zeroed Raw-tagged header.",
        )
