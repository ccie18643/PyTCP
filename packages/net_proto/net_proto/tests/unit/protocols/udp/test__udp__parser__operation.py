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
This module contains tests for the UDP packet parser operation.

net_proto/tests/unit/protocols/udp/test__udp__parser__operation.py

ver 3.0.9
"""

from types import SimpleNamespace
from typing import Any, override
from unittest import TestCase

from net_addr import IpVersion
from net_proto import PacketRx, UdpHeader, UdpParser
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "UDP packet with no payload, maximum port values.",
            # UDP wire frame (8 bytes, header-only):
            #   Bytes 0-1 : 0xffff -> sport=65535 (UINT_16__MAX)
            #   Bytes 2-3 : 0xffff -> dport=65535 (UINT_16__MAX)
            #   Bytes 4-5 : 0x0008 -> plen=8 (header-only)
            #   Bytes 6-7 : 0xfff7 -> cksum=65527 (valid for init=0)
            "_frame_rx": b"\xff\xff\xff\xff\x00\x08\xff\xf7",
            "_results": {
                "header": UdpHeader(
                    sport=65535,
                    dport=65535,
                    plen=8,
                    cksum=65527,
                ),
                "payload": b"",
            },
        },
        {
            "_description": "UDP packet with 16-byte ASCII payload.",
            # UDP wire frame (24 bytes = 8-byte header + 16-byte payload):
            #   Bytes 0-1   : 0x3039 -> sport=12345
            #   Bytes 2-3   : 0xd431 -> dport=54321
            #   Bytes 4-5   : 0x0018 -> plen=24
            #   Bytes 6-7   : 0x2ca6 -> cksum=11430 (valid for init=0)
            #   Bytes 8-23  : b"0123456789ABCDEF" (ASCII payload)
            "_frame_rx": (
                b"\x30\x39\xd4\x31\x00\x18\x2c\xa6\x30\x31\x32\x33\x34\x35\x36\x37" b"\x38\x39\x41\x42\x43\x44\x45\x46"
            ),
            "_results": {
                "header": UdpHeader(
                    sport=12345,
                    dport=54321,
                    plen=24,
                    cksum=11430,
                ),
                "payload": b"0123456789ABCDEF",
            },
        },
        {
            "_description": "UDP packet with maximum 65527-byte payload (total 65535).",
            # UDP wire frame (65535 bytes = 8-byte header + 65527-byte payload):
            #   Bytes 0-1  : 0x2b67 -> sport=11111
            #   Bytes 2-3  : 0x56ce -> dport=22222
            #   Bytes 4-5  : 0xffff -> plen=65535 (UINT_16__MAX)
            #   Bytes 6-7  : 0xb357 -> cksum=45911 (valid for init=0)
            #   Bytes 8+   : 65527 bytes of 'X'
            "_frame_rx": b"\x2b\x67\x56\xce\xff\xff\xb3\x57" + b"X" * 65527,
            "_results": {
                "header": UdpHeader(
                    sport=11111,
                    dport=22222,
                    plen=65535,
                    cksum=45911,
                ),
                "payload": b"X" * 65527,
            },
        },
        {
            "_description": "UDP packet with 'cksum' field set to zero (RFC 768 opt-out).",
            # UDP wire frame (8 bytes, header-only, cksum=0):
            #   Bytes 0-1 : 0x3039 -> sport=12345
            #   Bytes 2-3 : 0xd431 -> dport=54321
            #   Bytes 4-5 : 0x0008 -> plen=8
            #   Bytes 6-7 : 0x0000 -> cksum=0 (validation skipped)
            "_frame_rx": b"\x30\x39\xd4\x31\x00\x08\x00\x00",
            "_results": {
                "header": UdpHeader(
                    sport=12345,
                    dport=54321,
                    plen=8,
                    cksum=0,
                ),
                "payload": b"",
            },
        },
    ]
)
class TestUdpParserOperation(TestCase):
    """
    The UDP packet parser operation tests.

    The UDP parser reads 'ip.payload_len', 'ip.pshdr_sum', and 'ip.ver'
    from the containing IP layer, so a SimpleNamespace stub is
    sufficient. These operation-path fixtures default the carrier to
    IPv4; IPv6-specific behaviour (e.g. RFC 6935 zero-cksum
    default-discard) is covered by dedicated test classes elsewhere.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Wrap the parametrized frame in a PacketRx and stub the IP layer
        attributes the UDP parser reads from it.
        """

        self._packet_rx = PacketRx(self._frame_rx)
        self._packet_rx.ip = SimpleNamespace(  # type: ignore[assignment]
            payload_len=len(self._frame_rx),
            pshdr_sum=0,
            ver=IpVersion.IP4,
        )

    def test__udp__parser__header(self) -> None:
        """
        Ensure the UDP packet parser decodes the 8-byte fixed header
        into the expected UdpHeader dataclass.

        Reference: RFC 768 (UDP datagram parse — header + payload).
        """

        udp_parser = UdpParser(self._packet_rx)

        self.assertEqual(
            udp_parser.header,
            self._results["header"],
            msg=f"Unexpected parsed header for case: {self._description}",
        )

    def test__udp__parser__payload(self) -> None:
        """
        Ensure the UDP packet parser extracts the payload starting at
        'UDP__HEADER__LEN' and ending at 'header.plen'.

        Reference: RFC 768 (UDP datagram parse — header + payload).
        """

        udp_parser = UdpParser(self._packet_rx)

        self.assertEqual(
            bytes(udp_parser.payload),
            self._results["payload"],
            msg=f"Unexpected parsed payload for case: {self._description}",
        )

    def test__udp__parser__packet_rx_udp(self) -> None:
        """
        Ensure the UDP packet parser installs itself on the PacketRx as
        'packet_rx.udp'.

        Reference: RFC 768 (UDP datagram parse — header + payload).
        """

        udp_parser = UdpParser(self._packet_rx)

        self.assertIs(
            self._packet_rx.udp,
            udp_parser,
            msg=f"Parser must install itself on packet_rx.udp for case: {self._description}",
        )

    def test__udp__parser__packet_rx_frame_advanced_past_header(self) -> None:
        """
        Ensure the UDP packet parser advances 'packet_rx.frame' past the
        UDP header so the remaining bytes are the UDP payload.

        Reference: RFC 768 (UDP datagram parse — header + payload).
        """

        udp_parser = UdpParser(self._packet_rx)

        self.assertEqual(
            bytes(self._packet_rx.frame),
            self._results["payload"],
            msg=f"Parser must advance packet_rx.frame past the header for case: {self._description}",
        )
        # Sanity: parser.payload and packet_rx.frame refer to the same
        # payload region after construction.
        self.assertEqual(
            bytes(self._packet_rx.frame),
            bytes(udp_parser.payload),
            msg=f"packet_rx.frame and parser.payload must match for case: {self._description}",
        )
