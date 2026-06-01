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
This module contains tests for the IPv4 packet parser operation.

net_proto/tests/unit/protocols/ip4/test__ip4__parser__operation.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import Ip4Address
from net_proto import (
    Ip4Header,
    Ip4OptionNop,
    Ip4Options,
    Ip4Parser,
    IpProto,
    PacketRx,
)


@parameterized_class(
    [
        {
            "_description": "IPv4 header with no options and empty payload.",
            # IPv4 wire frame (20 bytes):
            #   ver=4, hlen=20, dscp=63, ecn=3, plen=20, id=65535,
            #   flag_df=1, ttl=255, proto=RAW, cksum=0xd923,
            #   src=10.20.30.40, dst=50.60.70.80.
            "_frame_rx": (b"\x45\xff\x00\x14\xff\xff\x40\x00\xff\xff\xd9\x23" b"\x0a\x14\x1e\x28\x32\x3c\x46\x50"),
            "_results": {
                "header": Ip4Header(
                    hlen=20,
                    dscp=63,
                    ecn=3,
                    plen=20,
                    id=65535,
                    flag_df=True,
                    flag_mf=False,
                    offset=0,
                    ttl=255,
                    proto=IpProto.RAW,
                    cksum=55587,
                    src=Ip4Address("10.20.30.40"),
                    dst=Ip4Address("50.60.70.80"),
                ),
                "options": Ip4Options(),
                "payload": b"",
                "header_bytes": (
                    b"\x45\xff\x00\x14\xff\xff\x40\x00\xff\xff\xd9\x23" b"\x0a\x14\x1e\x28\x32\x3c\x46\x50"
                ),
                "payload_bytes": b"",
                "packet_bytes": (
                    b"\x45\xff\x00\x14\xff\xff\x40\x00\xff\xff\xd9\x23" b"\x0a\x14\x1e\x28\x32\x3c\x46\x50"
                ),
            },
        },
        {
            "_description": "IPv4 header with no options and 16-byte payload.",
            # IPv4 wire frame (36 bytes):
            #   header 20 bytes (dscp=17, ecn=2, plen=36, id=12345,
            #   flag_df=1, ttl=255, proto=RAW, cksum=0x3a48,
            #   src=1.2.3.4, dst=5.6.7.8)
            #   + 16-byte ASCII payload b"0123456789ABCDEF".
            "_frame_rx": (
                b"\x45\x46\x00\x24\x30\x39\x40\x00\xff\xff\x3a\x48"
                b"\x01\x02\x03\x04\x05\x06\x07\x08"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"
            ),
            "_results": {
                "header": Ip4Header(
                    hlen=20,
                    dscp=17,
                    ecn=2,
                    plen=36,
                    id=12345,
                    flag_df=True,
                    flag_mf=False,
                    offset=0,
                    ttl=255,
                    proto=IpProto.RAW,
                    cksum=14920,
                    src=Ip4Address("1.2.3.4"),
                    dst=Ip4Address("5.6.7.8"),
                ),
                "options": Ip4Options(),
                "payload": b"0123456789ABCDEF",
                "header_bytes": (
                    b"\x45\x46\x00\x24\x30\x39\x40\x00\xff\xff\x3a\x48" b"\x01\x02\x03\x04\x05\x06\x07\x08"
                ),
                "payload_bytes": b"0123456789ABCDEF",
                "packet_bytes": (
                    b"\x45\x46\x00\x24\x30\x39\x40\x00\xff\xff\x3a\x48"
                    b"\x01\x02\x03\x04\x05\x06\x07\x08"
                    b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
            },
        },
        {
            "_description": "IPv4 packet at maximum plen (65535) with 40 Nop options.",
            # IPv4 wire frame (65535 bytes):
            #   60-byte header (hlen=60, dscp=8, ecn=0, plen=65535,
            #   id=21212, ttl=64, proto=RAW, cksum=0x02ea,
            #   src=1.1.1.1, dst=2.2.2.2) followed by 40 NOP bytes
            #   then 65475 bytes of 'X'.
            "_frame_rx": (
                b"\x4f\x20\xff\xff\x52\xdc\x00\x00\x40\xff\x02\xea"
                b"\x01\x01\x01\x01\x02\x02\x02\x02" + b"\x01" * 40 + b"X" * 65475
            ),
            "_results": {
                "header": Ip4Header(
                    hlen=60,
                    dscp=8,
                    ecn=0,
                    plen=65535,
                    id=21212,
                    flag_df=False,
                    flag_mf=False,
                    offset=0,
                    ttl=64,
                    proto=IpProto.RAW,
                    cksum=746,
                    src=Ip4Address("1.1.1.1"),
                    dst=Ip4Address("2.2.2.2"),
                ),
                "options": Ip4Options(*([Ip4OptionNop()] * 40)),
                "payload": b"X" * 65475,
                "header_bytes": (
                    b"\x4f\x20\xff\xff\x52\xdc\x00\x00\x40\xff\x02\xea" b"\x01\x01\x01\x01\x02\x02\x02\x02"
                ),
                "payload_bytes": b"X" * 65475,
                "packet_bytes": (
                    b"\x4f\x20\xff\xff\x52\xdc\x00\x00\x40\xff\x02\xea"
                    b"\x01\x01\x01\x01\x02\x02\x02\x02" + b"\x01" * 40 + b"X" * 65475
                ),
            },
        },
        {
            "_description": "IPv4 mid-stream fragment (no MF, non-zero offset).",
            # IPv4 wire frame (36 bytes):
            #   header 20 bytes (dscp=10, ecn=1, plen=36, id=54321,
            #   offset=32008, ttl=128, proto=RAW, cksum=0x41d0,
            #   src=4.3.2.1, dst=8.7.6.5)
            #   + 16-byte ASCII payload.
            "_frame_rx": (
                b"\x45\x29\x00\x24\xd4\x31\x0f\xa1\x80\xff\x41\xd0"
                b"\x04\x03\x02\x01\x08\x07\x06\x05"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"
            ),
            "_results": {
                "header": Ip4Header(
                    hlen=20,
                    dscp=10,
                    ecn=1,
                    plen=36,
                    id=54321,
                    flag_df=False,
                    flag_mf=False,
                    offset=32008,
                    ttl=128,
                    proto=IpProto.RAW,
                    cksum=16848,
                    src=Ip4Address("4.3.2.1"),
                    dst=Ip4Address("8.7.6.5"),
                ),
                "options": Ip4Options(),
                "payload": b"0123456789ABCDEF",
                "header_bytes": (
                    b"\x45\x29\x00\x24\xd4\x31\x0f\xa1\x80\xff\x41\xd0" b"\x04\x03\x02\x01\x08\x07\x06\x05"
                ),
                "payload_bytes": b"0123456789ABCDEF",
                "packet_bytes": (
                    b"\x45\x29\x00\x24\xd4\x31\x0f\xa1\x80\xff\x41\xd0"
                    b"\x04\x03\x02\x01\x08\x07\x06\x05"
                    b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
            },
        },
        {
            "_description": "IPv4 leading fragment (MF set, offset=0, 1466-byte payload).",
            # IPv4 wire frame (1486 bytes):
            #   header 20 bytes (dscp=17, ecn=2, plen=1486, id=12345,
            #   flag_mf=1, ttl=255, proto=RAW, cksum=0x549e,
            #   src=1.2.3.4, dst=5.6.7.8)
            #   + 1466 bytes of 'X'.
            "_frame_rx": (
                b"\x45\x46\x05\xce\x30\x39\x20\x00\xff\xff\x54\x9e" b"\x01\x02\x03\x04\x05\x06\x07\x08" + b"X" * 1466
            ),
            "_results": {
                "header": Ip4Header(
                    hlen=20,
                    dscp=17,
                    ecn=2,
                    plen=1486,
                    id=12345,
                    flag_df=False,
                    flag_mf=True,
                    offset=0,
                    ttl=255,
                    proto=IpProto.RAW,
                    cksum=21662,
                    src=Ip4Address("1.2.3.4"),
                    dst=Ip4Address("5.6.7.8"),
                ),
                "options": Ip4Options(),
                "payload": b"X" * 1466,
                "header_bytes": (
                    b"\x45\x46\x05\xce\x30\x39\x20\x00\xff\xff\x54\x9e" b"\x01\x02\x03\x04\x05\x06\x07\x08"
                ),
                "payload_bytes": b"X" * 1466,
                "packet_bytes": (
                    b"\x45\x46\x05\xce\x30\x39\x20\x00\xff\xff\x54\x9e"
                    b"\x01\x02\x03\x04\x05\x06\x07\x08" + b"X" * 1466
                ),
            },
        },
    ]
)
class TestIp4PacketParserOperation(TestCase):
    """
    The IPv4 packet parser operation tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Wrap the parametrized frame in a PacketRx so it can be fed to
        Ip4Parser.
        """

        self._packet_rx = PacketRx(self._frame_rx)

    def test__ip4__parser__header(self) -> None:
        """
        Ensure the parser exposes the expected Ip4Header object.

        Reference: RFC 791 §3.1 (IPv4 datagram parse — header + payload).
        """

        parser = Ip4Parser(self._packet_rx)

        self.assertEqual(
            parser.header,
            self._results["header"],
            msg=f"Unexpected parsed header for case: {self._description}",
        )

    def test__ip4__parser__options(self) -> None:
        """
        Ensure the parser exposes the expected Ip4Options container.

        Reference: RFC 791 §3.1 (IPv4 datagram parse — header + payload).
        """

        parser = Ip4Parser(self._packet_rx)

        self.assertEqual(
            parser.options,
            self._results["options"],
            msg=f"Unexpected parsed options for case: {self._description}",
        )

    def test__ip4__parser__header_bytes(self) -> None:
        """
        Ensure 'header_bytes' returns the first hlen bytes of the frame.

        Reference: RFC 791 §3.1 (IPv4 datagram parse — header + payload).
        """

        parser = Ip4Parser(self._packet_rx)

        self.assertEqual(
            bytes(parser.header_bytes),
            self._results["header_bytes"],
            msg=f"Unexpected header_bytes for case: {self._description}",
        )

    def test__ip4__parser__payload_bytes(self) -> None:
        """
        Ensure 'payload_bytes' returns the bytes between hlen and plen.

        Reference: RFC 791 §3.1 (IPv4 datagram parse — header + payload).
        """

        parser = Ip4Parser(self._packet_rx)

        self.assertEqual(
            bytes(parser.payload_bytes),
            self._results["payload_bytes"],
            msg=f"Unexpected payload_bytes for case: {self._description}",
        )

    def test__ip4__parser__packet_bytes(self) -> None:
        """
        Ensure 'packet_bytes' returns the full header + options +
        payload span.

        Reference: RFC 791 §3.1 (IPv4 datagram parse — header + payload).
        """

        parser = Ip4Parser(self._packet_rx)

        self.assertEqual(
            bytes(parser.packet_bytes),
            self._results["packet_bytes"],
            msg=f"Unexpected packet_bytes for case: {self._description}",
        )

    def test__ip4__parser__packet_rx_ip4_backref(self) -> None:
        """
        Ensure the parser stores itself on the PacketRx as both 'ip'
        and 'ip4' so downstream handlers can look it up by either name.

        Reference: RFC 791 §3.1 (IPv4 datagram parse — header + payload).
        """

        parser = Ip4Parser(self._packet_rx)

        self.assertIs(
            self._packet_rx.ip4,
            parser,
            msg=f"PacketRx.ip4 must reference the parser for case: {self._description}",
        )
        self.assertIs(
            self._packet_rx.ip,
            parser,
            msg=f"PacketRx.ip must reference the parser for case: {self._description}",
        )

    def test__ip4__parser__packet_rx_frame_advanced_to_payload(self) -> None:
        """
        Ensure the parser advances 'PacketRx.frame' past the IPv4
        header+options to the payload bytes so the next-layer parser
        sees only what it is supposed to consume.

        Reference: RFC 791 §3.1 (IPv4 datagram parse — header + payload).
        """

        Ip4Parser(self._packet_rx)

        self.assertEqual(
            bytes(self._packet_rx.frame),
            self._results["payload"],
            msg=f"PacketRx.frame must be advanced to payload for case: {self._description}",
        )
