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
This module contains tests for the Ethernet 802.3 packet parser sanity checks.

The Ethernet 802.3 parser enforces a source-MAC unicast invariant: the
'src' field MUST NOT be the unspecified (all-zeros), multicast (group-bit-
set), or broadcast (all-ones) MAC address.

net_proto/tests/unit/protocols/ethernet_802_3/test__ethernet_802_3__parser__sanity_checks.py

ver 3.0.10
"""

from typing import Any
from unittest import TestCase

from net_addr import MacAddress
from net_proto import (
    ETHERNET_802_3__PAYLOAD__MAX_LEN,
    Ethernet8023Parser,
    Ethernet8023SanityError,
    PacketRx,
)
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Minimum-sized valid frame with no payload (dlen == 0).",
            "_frame_rx": (
                # Ethernet 802.3
                #   Destination MAC : a1:b2:c3:d4:e5:f6
                #   Source MAC      : 12:13:14:15:16:17
                #   Length          : 0x0000 (empty payload)
                #   Frame length    : 14 bytes
                b"\xa1\xb2\xc3\xd4\xe5\xf6\x12\x13\x14\x15\x16\x17\x00\x00"
            ),
            "_results": {
                "dst": MacAddress("a1:b2:c3:d4:e5:f6"),
                "src": MacAddress("12:13:14:15:16:17"),
                "dlen": 0,
            },
        },
        {
            "_description": "Broadcast-destined frame with a small payload.",
            "_frame_rx": (
                # Ethernet 802.3
                #   Destination MAC : ff:ff:ff:ff:ff:ff (broadcast)
                #   Source MAC      : 00:11:22:33:44:55
                #   Length          : 0x0004 (4 bytes)
                #   Payload bytes   : 4
                b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55\x00\x04"
                b"\xde\xad\xbe\xef"
            ),
            "_results": {
                "dst": MacAddress("ff:ff:ff:ff:ff:ff"),
                "src": MacAddress("00:11:22:33:44:55"),
                "dlen": 4,
            },
        },
        {
            "_description": "Maximum-payload frame (dlen == 1500).",
            "_frame_rx": (
                # Ethernet 802.3
                #   Destination MAC : a1:b2:c3:d4:e5:f6
                #   Source MAC      : 12:13:14:15:16:17
                #   Length          : 0x05dc (1500 bytes == maximum)
                #   Payload bytes   : 1500
                b"\xa1\xb2\xc3\xd4\xe5\xf6\x12\x13\x14\x15\x16\x17\x05\xdc"
                + b"Z" * ETHERNET_802_3__PAYLOAD__MAX_LEN
            ),
            "_results": {
                "dst": MacAddress("a1:b2:c3:d4:e5:f6"),
                "src": MacAddress("12:13:14:15:16:17"),
                "dlen": ETHERNET_802_3__PAYLOAD__MAX_LEN,
            },
        },
    ]
)
class TestEthernet8023ParserSanityHappyPaths(TestCase):
    """
    Happy-path tests — valid frames must pass the sanity validator.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    def test__ethernet_802_3__parser__sanity_accepts_valid_frame(self) -> None:
        """
        Ensure every frame that clears the integrity validator AND carries
        a unicast 'src' MAC also clears the sanity validator and surfaces
        the parsed fields unchanged.

        Reference: IEEE 802.3 / RFC 1042 (Ethernet 802.3 frame format).
        """

        try:
            parser = Ethernet8023Parser(PacketRx(self._frame_rx))
        except Ethernet8023SanityError as error:  # pragma: no cover
            self.fail(f"Unexpected Ethernet8023SanityError for case {self._description!r}: {error!s}")

        self.assertEqual(
            parser.dst,
            self._results["dst"],
            msg=f"Unexpected 'dst' for case: {self._description}",
        )
        self.assertEqual(
            parser.src,
            self._results["src"],
            msg=f"Unexpected 'src' for case: {self._description}",
        )
        self.assertEqual(
            parser.dlen,
            self._results["dlen"],
            msg=f"Unexpected 'dlen' for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "The 'src' MAC is unspecified (all zeros).",
            "_frame_rx": (
                # Ethernet 802.3
                #   Destination MAC : a1:b2:c3:d4:e5:f6
                #   Source MAC      : 00:00:00:00:00:00  (unspecified)
                #   Length          : 0x0000 (empty payload)
                #   Frame length    : 14 bytes
                b"\xa1\xb2\xc3\xd4\xe5\xf6\x00\x00\x00\x00\x00\x00\x00\x00"
            ),
            "_results": {
                "error_message": "The 'src' field value 00:00:00:00:00:00 must not be an unspecified MAC address.",
            },
        },
        {
            "_description": "The 'src' MAC is multicast (group bit set).",
            "_frame_rx": (
                # Ethernet 802.3
                #   Destination MAC : a1:b2:c3:d4:e5:f6
                #   Source MAC      : 01:00:5e:00:00:01  (IPv4 multicast OUI — illegal as source)
                #   Length          : 0x0000 (empty payload)
                #   Frame length    : 14 bytes
                b"\xa1\xb2\xc3\xd4\xe5\xf6\x01\x00\x5e\x00\x00\x01\x00\x00"
            ),
            "_results": {
                "error_message": "The 'src' field value 01:00:5e:00:00:01 must not be a multicast MAC address.",
            },
        },
        {
            "_description": "The 'src' MAC is broadcast (all ones).",
            "_frame_rx": (
                # Ethernet 802.3
                #   Destination MAC : a1:b2:c3:d4:e5:f6
                #   Source MAC      : ff:ff:ff:ff:ff:ff  (broadcast — illegal as source)
                #   Length          : 0x0000 (empty payload)
                #   Frame length    : 14 bytes
                b"\xa1\xb2\xc3\xd4\xe5\xf6\xff\xff\xff\xff\xff\xff\x00\x00"
            ),
            "_results": {
                "error_message": "The 'src' field value ff:ff:ff:ff:ff:ff must not be a broadcast MAC address.",
            },
        },
    ]
)
class TestEthernet8023ParserSanityChecks(TestCase):
    """
    The Ethernet 802.3 packet parser sanity checks tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    def test__ethernet_802_3__parser__sanity_error(self) -> None:
        """
        Ensure the Ethernet 802.3 parser raises Ethernet8023SanityError on
        a frame whose 'src' MAC violates the IEEE 802.3 unicast-source
        invariant and reports the expected message.

        Reference: IEEE 802.3 (source MAC MUST be unicast — group bit clear, not all-ones, not all-zeros).
        """

        with self.assertRaises(Ethernet8023SanityError) as error:
            Ethernet8023Parser(PacketRx(self._frame_rx))

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][Ethernet 802.3] {self._results['error_message']}",
            msg=f"Unexpected sanity-error message for case: {self._description}",
        )
