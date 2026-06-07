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
Module contains tests for the UDP packet sanity checks.

net_proto/tests/unit/protocols/udp/test__udp__parser__sanity_checks.py

ver 3.0.8
"""

from types import SimpleNamespace
from typing import override
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import IpVersion
from net_proto import PacketRx, UdpParser, UdpSanityError


@parameterized_class(
    [
        {
            "_description": "The 'dport' field equals 0.",
            # UDP wire frame (8 bytes, header-only):
            #   Bytes 0-1 : 0x3039 -> sport=12345
            #   Bytes 2-3 : 0x0000 -> dport=0 (sanity violation)
            #   Bytes 4-5 : 0x0008 -> plen=8
            #   Bytes 6-7 : 0xcfbe -> cksum (valid for init=0)
            "_frame_rx": b"\x30\x39\x00\x00\x00\x08\xcf\xbe",
            "_error_message": "The 'dport' field must be greater than 0. Got: 0",
        },
    ]
)
class TestUdpParserSanityChecks(TestCase):
    """
    The UDP packet parser sanity checks tests.

    The UDP parser reads only 'ip.payload_len' and 'ip.pshdr_sum' from
    the containing IP layer, so a SimpleNamespace stub is sufficient and
    the tests are agnostic to whether the carrier is IPv4 or IPv6.
    """

    _description: str
    _frame_rx: bytes
    _error_message: str

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

    def test__udp__parser__sanity_error(self) -> None:
        """
        Ensure the UDP packet parser raises UdpSanityError with the
        expected message for each frame that is structurally well-formed
        but logically inconsistent.

        Reference: RFC 768 (UDP datagram sanity — port fields).
        """

        with self.assertRaises(UdpSanityError) as error:
            UdpParser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][UDP] {self._error_message}",
            msg=f"Unexpected sanity-error message for case: {self._description}",
        )


class TestUdpParserSourcePortOptional(TestCase):
    """
    The UDP parser source-port-optional (RFC 768) tests.

    RFC 768 designates Source Port as an optional field; the wire
    value 0 is the documented "source port not used" sentinel. The
    receiver MUST accept and deliver such datagrams.
    """

    def test__udp__parser__source_port_zero_accepted(self) -> None:
        """
        Ensure a UDP datagram with sport=0 parses to completion
        without raising a sanity error.

        Reference: RFC 768 (Source Port is optional; zero
        sentinel means "not used").
        """

        # UDP wire frame (8 bytes, header-only), sport=0:
        #   Bytes 0-1 : 0x0000 -> sport=0 (RFC 768 absent sentinel)
        #   Bytes 2-3 : 0xd431 -> dport=54321
        #   Bytes 4-5 : 0x0008 -> plen=8 (header-only)
        #   Bytes 6-7 : 0x2bc6 -> cksum (valid for init=0)
        frame_rx = b"\x00\x00\xd4\x31\x00\x08\x2b\xc6"
        packet_rx = PacketRx(frame_rx)
        packet_rx.ip = SimpleNamespace(  # type: ignore[assignment]
            payload_len=len(frame_rx),
            pshdr_sum=0,
            ver=IpVersion.IP4,
        )

        parser = UdpParser(packet_rx)

        self.assertEqual(
            parser.sport,
            0,
            msg="UDP parser must accept sport=0 (RFC 768 source-port-optional).",
        )
        self.assertEqual(
            parser.dport,
            54321,
            msg="UDP parser must parse the rest of the header normally when sport=0.",
        )
        self.assertIs(
            packet_rx.udp,
            parser,
            msg="UDP parser must install itself on packet_rx for sport=0 frames.",
        )
