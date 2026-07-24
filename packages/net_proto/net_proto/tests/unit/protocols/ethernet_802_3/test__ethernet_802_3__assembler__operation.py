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
This module contains tests for the Ethernet 802.3 protocol packet assembling
functionality.

The assembler composes a 14-byte Ethernet8023Header (dst + src + dlen) and
stacks a RawAssembler payload. The 'dlen' field is derived from the
payload length at construction time.

net_proto/tests/unit/protocols/ethernet_802_3/test__ethernet_802_3__assembler__operation.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Buffer, MacAddress
from net_proto import (
    ETHERNET_802_3__HEADER__LEN,
    ETHERNET_802_3__PACKET__MAX_LEN,
    ETHERNET_802_3__PAYLOAD__MAX_LEN,
    Ethernet8023Assembler,
    Ethernet8023Header,
    Ethernet8023Parser,
    PacketRx,
    RawAssembler,
)
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Ethernet 802.3 packet with a 16-byte payload.",
            "_kwargs": {
                "ethernet_802_3__src": MacAddress("78:89:9a:ab:bc:cd"),
                "ethernet_802_3__dst": MacAddress("11:22:33:44:55:66"),
                "ethernet_802_3__payload": RawAssembler(raw__payload=b"0123456789ABCDEF"),
            },
            "_results": {
                "__len__": 30,
                "__str__": "ETHER_802.3 78:89:9a:ab:bc:cd > 11:22:33:44:55:66, dlen 16, len 30 (14+16)",
                "__repr__": (
                    "Ethernet8023Assembler(header=Ethernet8023Header(dst=MacAddress('11:22:33:44:55:66'), "
                    "src=MacAddress('78:89:9a:ab:bc:cd'), dlen=16), "
                    "payload=RawAssembler(raw__payload=b'0123456789ABCDEF'))"
                ),
                "__bytes__": (
                    # Ethernet 802.3
                    #   Destination MAC : 11:22:33:44:55:66
                    #   Source MAC      : 78:89:9a:ab:bc:cd
                    #   Length          : 0x0010 (16 bytes)
                    #   Payload         : b"0123456789ABCDEF" (16 bytes)
                    b"\x11\x22\x33\x44\x55\x66\x78\x89\x9a\xab\xbc\xcd\x00\x10"
                    b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45\x46"
                ),
                "dst": MacAddress("11:22:33:44:55:66"),
                "src": MacAddress("78:89:9a:ab:bc:cd"),
                "dlen": 16,
                "header": Ethernet8023Header(
                    dst=MacAddress("11:22:33:44:55:66"),
                    src=MacAddress("78:89:9a:ab:bc:cd"),
                    dlen=16,
                ),
                "payload": RawAssembler(raw__payload=b"0123456789ABCDEF"),
            },
        },
        {
            "_description": "Ethernet 802.3 packet at MTU (1500-byte payload, 1514-byte total).",
            "_kwargs": {
                "ethernet_802_3__dst": MacAddress("a1:b2:c3:d4:e5:f6"),
                "ethernet_802_3__src": MacAddress("12:13:14:15:16:17"),
                "ethernet_802_3__payload": RawAssembler(raw__payload=b"X" * ETHERNET_802_3__PAYLOAD__MAX_LEN),
            },
            "_results": {
                "__len__": ETHERNET_802_3__PACKET__MAX_LEN,
                "__str__": (
                    "ETHER_802.3 12:13:14:15:16:17 > a1:b2:c3:d4:e5:f6, "
                    f"dlen {ETHERNET_802_3__PAYLOAD__MAX_LEN}, "
                    f"len {ETHERNET_802_3__PACKET__MAX_LEN} "
                    f"({ETHERNET_802_3__HEADER__LEN}+{ETHERNET_802_3__PAYLOAD__MAX_LEN})"
                ),
                "__repr__": (
                    "Ethernet8023Assembler(header=Ethernet8023Header(dst=MacAddress('a1:b2:c3:d4:e5:f6'), "
                    f"src=MacAddress('12:13:14:15:16:17'), dlen={ETHERNET_802_3__PAYLOAD__MAX_LEN}), "
                    f"payload=RawAssembler(raw__payload=b'{'X' * ETHERNET_802_3__PAYLOAD__MAX_LEN}'))"
                ),
                "__bytes__": (
                    # Ethernet 802.3
                    #   Destination MAC : a1:b2:c3:d4:e5:f6
                    #   Source MAC      : 12:13:14:15:16:17
                    #   Length          : 0x05dc (1500 bytes == maximum)
                    #   Payload         : b"X" * 1500
                    b"\xa1\xb2\xc3\xd4\xe5\xf6\x12\x13\x14\x15\x16\x17\x05\xdc"
                    + b"X" * ETHERNET_802_3__PAYLOAD__MAX_LEN
                ),
                "dst": MacAddress("a1:b2:c3:d4:e5:f6"),
                "src": MacAddress("12:13:14:15:16:17"),
                "dlen": ETHERNET_802_3__PAYLOAD__MAX_LEN,
                "header": Ethernet8023Header(
                    dst=MacAddress("a1:b2:c3:d4:e5:f6"),
                    src=MacAddress("12:13:14:15:16:17"),
                    dlen=ETHERNET_802_3__PAYLOAD__MAX_LEN,
                ),
                "payload": RawAssembler(raw__payload=b"X" * ETHERNET_802_3__PAYLOAD__MAX_LEN),
            },
        },
        {
            "_description": "Ethernet 802.3 packet destined to the broadcast MAC.",
            "_kwargs": {
                "ethernet_802_3__dst": MacAddress("ff:ff:ff:ff:ff:ff"),
                "ethernet_802_3__src": MacAddress("00:11:22:33:44:55"),
                "ethernet_802_3__payload": RawAssembler(raw__payload=b"\xde\xad\xbe\xef"),
            },
            "_results": {
                "__len__": 18,
                "__str__": "ETHER_802.3 00:11:22:33:44:55 > ff:ff:ff:ff:ff:ff, dlen 4, len 18 (14+4)",
                "__repr__": (
                    "Ethernet8023Assembler(header=Ethernet8023Header(dst=MacAddress('ff:ff:ff:ff:ff:ff'), "
                    "src=MacAddress('00:11:22:33:44:55'), dlen=4), "
                    "payload=RawAssembler(raw__payload=b'\\xde\\xad\\xbe\\xef'))"
                ),
                "__bytes__": (
                    # Ethernet 802.3
                    #   Destination MAC : ff:ff:ff:ff:ff:ff (broadcast)
                    #   Source MAC      : 00:11:22:33:44:55
                    #   Length          : 0x0004 (4 bytes)
                    #   Payload         : b"\xde\xad\xbe\xef" (4 bytes)
                    b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55\x00\x04"
                    b"\xde\xad\xbe\xef"
                ),
                "dst": MacAddress("ff:ff:ff:ff:ff:ff"),
                "src": MacAddress("00:11:22:33:44:55"),
                "dlen": 4,
                "header": Ethernet8023Header(
                    dst=MacAddress("ff:ff:ff:ff:ff:ff"),
                    src=MacAddress("00:11:22:33:44:55"),
                    dlen=4,
                ),
                "payload": RawAssembler(raw__payload=b"\xde\xad\xbe\xef"),
            },
        },
    ]
)
class TestEthernet8023AssemblerOperation(TestCase):
    """
    The Ethernet 802.3 packet assembler operation tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Initialize the Ethernet 802.3 packet assembler with the testcase arguments.
        """

        self._ethernet_802_3__assembler = Ethernet8023Assembler(**self._kwargs)

    def test__ethernet_802_3__assembler__len(self) -> None:
        """
        Ensure the Ethernet 802.3 packet assembler '__len__()' method returns
        a correct value (header + payload bytes).

        Reference: IEEE 802.3 §3 (802.3 MAC frame wire format).
        """

        self.assertEqual(
            len(self._ethernet_802_3__assembler),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__ethernet_802_3__assembler__str(self) -> None:
        """
        Ensure the Ethernet 802.3 packet assembler '__str__()' method returns
        the canonical log line.

        Reference: IEEE 802.3 §3 (802.3 MAC frame wire format).
        """

        self.assertEqual(
            str(self._ethernet_802_3__assembler),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__ethernet_802_3__assembler__repr(self) -> None:
        """
        Ensure the Ethernet 802.3 packet assembler '__repr__()' method returns
        a string that can rebuild the header and embeds the payload repr.

        Reference: IEEE 802.3 §3 (802.3 MAC frame wire format).
        """

        self.assertEqual(
            repr(self._ethernet_802_3__assembler),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__ethernet_802_3__assembler__bytes(self) -> None:
        """
        Ensure the Ethernet 802.3 packet assembler '__bytes__()' method emits
        the expected on-wire frame.

        Reference: IEEE 802.3 §3 (802.3 MAC frame wire format).
        """

        self.assertEqual(
            bytes(self._ethernet_802_3__assembler),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__ethernet_802_3__assembler__dst(self) -> None:
        """
        Ensure the Ethernet 802.3 packet assembler 'dst' property returns a
        correct value.

        Reference: IEEE 802.3 §3 (802.3 MAC frame wire format).
        """

        self.assertEqual(
            self._ethernet_802_3__assembler.dst,
            self._results["dst"],
            msg=f"Unexpected 'dst' for case: {self._description}",
        )

    def test__ethernet_802_3__assembler__src(self) -> None:
        """
        Ensure the Ethernet 802.3 packet assembler 'src' property returns a
        correct value.

        Reference: IEEE 802.3 §3 (802.3 MAC frame wire format).
        """

        self.assertEqual(
            self._ethernet_802_3__assembler.src,
            self._results["src"],
            msg=f"Unexpected 'src' for case: {self._description}",
        )

    def test__ethernet_802_3__assembler__dlen(self) -> None:
        """
        Ensure the Ethernet 802.3 packet assembler 'dlen' property reflects
        the payload byte length derived at construction time.

        Reference: IEEE 802.3 §3 (802.3 MAC frame wire format).
        """

        self.assertEqual(
            self._ethernet_802_3__assembler.dlen,
            self._results["dlen"],
            msg=f"Unexpected 'dlen' for case: {self._description}",
        )

    def test__ethernet_802_3__assembler__header(self) -> None:
        """
        Ensure the Ethernet 802.3 packet assembler 'header' property exposes
        the fully populated Ethernet8023Header.

        Reference: IEEE 802.3 §3 (802.3 MAC frame wire format).
        """

        self.assertEqual(
            self._ethernet_802_3__assembler.header,
            self._results["header"],
            msg=f"Unexpected 'header' for case: {self._description}",
        )

    def test__ethernet_802_3__assembler__payload(self) -> None:
        """
        Ensure the Ethernet 802.3 packet assembler 'payload' property returns
        the wrapped upper-layer assembler.

        Reference: IEEE 802.3 §3 (802.3 MAC frame wire format).
        """

        self.assertEqual(
            self._ethernet_802_3__assembler.payload,
            self._results["payload"],
            msg=f"Unexpected 'payload' for case: {self._description}",
        )

    def test__ethernet_802_3__assembler__assemble(self) -> None:
        """
        Ensure the Ethernet 802.3 packet assembler 'assemble()' method
        appends the header + payload buffers that concatenate to the
        expected wire image.

        Reference: IEEE 802.3 §3 (802.3 MAC frame wire format).
        """

        buffers: list[Buffer] = []

        self._ethernet_802_3__assembler.assemble(buffers)

        self.assertEqual(
            b"".join(buffers),
            self._results["__bytes__"],
            msg=f"Unexpected assembled buffers for case: {self._description}",
        )

    def test__ethernet_802_3__assembler__tracker_is_inherited_from_payload(self) -> None:
        """
        Ensure the Ethernet 802.3 assembler reuses the payload's Tracker so
        that upstream TX log lines remain correlated with the payload
        assembler.

        Reference: IEEE 802.3 §3 (802.3 MAC frame wire format).
        """

        self.assertIs(
            self._ethernet_802_3__assembler.tracker,
            self._kwargs["ethernet_802_3__payload"].tracker,
            msg=f"Tracker must be inherited from payload for case: {self._description}",
        )


class TestEthernet8023AssemblerDefaults(TestCase):
    """
    The Ethernet 802.3 assembler default-value tests.
    """

    def test__ethernet_802_3__assembler__defaults(self) -> None:
        """
        Ensure the assembler default constructor yields a header-only frame
        with zeroed MAC addresses, a zero 'dlen' and an empty Raw payload.

        Reference: IEEE 802.3 §3 (802.3 MAC frame wire format).
        """

        assembler = Ethernet8023Assembler()

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
            assembler.dlen,
            0,
            msg="Default 'dlen' must be 0 (empty Raw payload).",
        )
        self.assertEqual(
            len(assembler),
            ETHERNET_802_3__HEADER__LEN,
            msg="Default assembler must be header-sized with an empty Raw payload.",
        )
        self.assertEqual(
            bytes(assembler),
            # Ethernet 802.3
            #   Destination MAC : 00:00:00:00:00:00
            #   Source MAC      : 00:00:00:00:00:00
            #   Length          : 0x0000 (empty payload)
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            msg="Default on-wire frame must match the zeroed header with empty payload.",
        )


class TestEthernet8023AssemblerBoundaries(TestCase):
    """
    Boundary and validation tests for the Ethernet 802.3 assembler.
    """

    def test__ethernet_802_3__assembler__rejects_oversized_payload(self) -> None:
        """
        Ensure the assembler raises AssertionError when the wrapped payload
        exceeds ETHERNET_802_3__PAYLOAD__MAX_LEN — the Ethernet8023Header
        '__post_init__' assert catches the 'dlen' overflow at construction
        time, before any bytes are emitted.

        Reference: IEEE 802.3 §3 (802.3 MAC frame wire format).
        """

        oversized = RawAssembler(raw__payload=b"Q" * (ETHERNET_802_3__PAYLOAD__MAX_LEN + 1))

        with self.assertRaises(AssertionError) as error:
            Ethernet8023Assembler(ethernet_802_3__payload=oversized)

        self.assertIn(
            f"Got: {ETHERNET_802_3__PAYLOAD__MAX_LEN + 1}",
            str(error.exception),
            msg="Assertion message must echo the offending payload length.",
        )

    def test__ethernet_802_3__assembler__roundtrips_through_parser(self) -> None:
        """
        Ensure bytes emitted by the assembler parse back into an equivalent
        header (field-for-field) through the Ethernet 802.3 parser.

        Reference: IEEE 802.3 §3 (802.3 MAC frame wire format).
        """

        assembler = Ethernet8023Assembler(
            ethernet_802_3__dst=MacAddress("aa:bb:cc:dd:ee:ff"),
            ethernet_802_3__src=MacAddress("00:11:22:33:44:55"),
            ethernet_802_3__payload=RawAssembler(raw__payload=b"payload"),
        )

        parser = Ethernet8023Parser(PacketRx(bytes(assembler)))

        self.assertEqual(
            parser.header,
            assembler.header,
            msg="Parser header must equal the assembler header after a bytes roundtrip.",
        )
