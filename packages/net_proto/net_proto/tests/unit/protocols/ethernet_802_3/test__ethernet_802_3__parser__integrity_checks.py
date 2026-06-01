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
This module contains tests for the Ethernet 802.3 packet parser integrity
checks.

The parser's integrity validator enforces three invariants, in order:
  1. The frame must be at least ETHERNET_802_3__HEADER__LEN (14) bytes long.
  2. The 16-bit 'dlen' header field must equal the actual number of payload
     bytes that follow the 14-byte header.
  3. The 'dlen' field must not exceed ETHERNET_802_3__PAYLOAD__MAX_LEN (1500).

Any violation must produce an Ethernet8023IntegrityError before parsing
proceeds.

net_proto/tests/unit/protocols/ethernet_802_3/test__ethernet_802_3__parser__integrity_checks.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import (
    ETHERNET_802_3__HEADER__LEN,
    ETHERNET_802_3__PAYLOAD__MAX_LEN,
    Ethernet8023IntegrityError,
    Ethernet8023Parser,
    PacketRx,
)


@parameterized_class(
    [
        {
            "_description": "The frame is empty (zero length).",
            "_frame_rx": b"",
            "_results": {
                "error_message": (
                    f"The minimum packet length must be {ETHERNET_802_3__HEADER__LEN} bytes. Got: 0 bytes."
                ),
            },
        },
        {
            "_description": "The frame has a single byte.",
            "_frame_rx": b"\x00",
            "_results": {
                "error_message": (
                    f"The minimum packet length must be {ETHERNET_802_3__HEADER__LEN} bytes. Got: 1 bytes."
                ),
            },
        },
        {
            "_description": "The frame length is one byte below the Ethernet 802.3 header minimum.",
            "_frame_rx": (
                # Ethernet 802.3
                #   Destination MAC : 11:22:33:44:55:66
                #   Source MAC      : 78:89:9a:ab:bc:cd
                #   Length          : truncated to a single byte 0x00
                #   Frame length    : 13 bytes (< 14-byte header minimum)
                b"\x11\x22\x33\x44\x55\x66\x78\x89\x9a\xab\xbc\xcd\x00"
            ),
            "_results": {
                "error_message": (
                    f"The minimum packet length must be {ETHERNET_802_3__HEADER__LEN} bytes. "
                    f"Got: {ETHERNET_802_3__HEADER__LEN - 1} bytes."
                ),
            },
        },
        {
            "_description": "The frame holds only the destination and source MAC addresses (12 bytes).",
            "_frame_rx": (
                # Ethernet 802.3
                #   Destination MAC : a1:b2:c3:d4:e5:f6
                #   Source MAC      : 12:13:14:15:16:17
                #   Length          : missing (truncated before 'dlen' field)
                #   Frame length    : 12 bytes (< 14-byte header minimum)
                b"\xa1\xb2\xc3\xd4\xe5\xf6\x12\x13\x14\x15\x16\x17"
            ),
            "_results": {
                "error_message": (
                    f"The minimum packet length must be {ETHERNET_802_3__HEADER__LEN} bytes. "
                    f"Got: {ETHERNET_802_3__HEADER__LEN - 2} bytes."
                ),
            },
        },
        {
            "_description": "The 'dlen' field value is larger than the actual payload length.",
            "_frame_rx": (
                # Ethernet 802.3
                #   Destination MAC : 11:22:33:44:55:66
                #   Source MAC      : 78:89:9a:ab:bc:cd
                #   Length          : 0x0010 (16 bytes declared)
                #   Payload bytes   : 15 (below the declared 16)
                b"\x11\x22\x33\x44\x55\x66\x78\x89\x9a\xab\xbc\xcd\x00\x10"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45"
            ),
            "_results": {
                "error_message": (
                    "The 'dlen' field value must equal the actual payload length. " "Got: dlen=16, payload_len=15."
                ),
            },
        },
        {
            "_description": "The 'dlen' field value is smaller than the actual payload length.",
            "_frame_rx": (
                # Ethernet 802.3
                #   Destination MAC : 11:22:33:44:55:66
                #   Source MAC      : 78:89:9a:ab:bc:cd
                #   Length          : 0x0010 (16 bytes declared)
                #   Payload bytes   : 17 (above the declared 16)
                b"\x11\x22\x33\x44\x55\x66\x78\x89\x9a\xab\xbc\xcd\x00\x10\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x47"
            ),
            "_results": {
                "error_message": (
                    "The 'dlen' field value must equal the actual payload length. " "Got: dlen=16, payload_len=17."
                ),
            },
        },
        {
            "_description": "The 'dlen' field is zero but payload bytes are present.",
            "_frame_rx": (
                # Ethernet 802.3
                #   Destination MAC : 11:22:33:44:55:66
                #   Source MAC      : 78:89:9a:ab:bc:cd
                #   Length          : 0x0000 (no payload declared)
                #   Payload bytes   : 1 (above the declared 0)
                b"\x11\x22\x33\x44\x55\x66\x78\x89\x9a\xab\xbc\xcd\x00\x00\xff"
            ),
            "_results": {
                "error_message": (
                    "The 'dlen' field value must equal the actual payload length. " "Got: dlen=0, payload_len=1."
                ),
            },
        },
        {
            "_description": "The 'dlen' field and payload are both 1501, exceeding the 1500-byte ceiling.",
            "_frame_rx": (
                # Ethernet 802.3
                #   Destination MAC : a1:b2:c3:d4:e5:f6
                #   Source MAC      : 12:13:14:15:16:17
                #   Length          : 0x05dd (1501 bytes declared)
                #   Payload bytes   : 1501 (> 1500 maximum)
                b"\xa1\xb2\xc3\xd4\xe5\xf6\x12\x13\x14\x15\x16\x17\x05\xdd"
                + b"X" * (ETHERNET_802_3__PAYLOAD__MAX_LEN + 1)
            ),
            "_results": {
                "error_message": (
                    f"The 'dlen' field value must be less than or equal to {ETHERNET_802_3__PAYLOAD__MAX_LEN}. "
                    f"Got: {ETHERNET_802_3__PAYLOAD__MAX_LEN + 1}."
                ),
            },
        },
        {
            "_description": "The 'dlen' field and payload are both 2000, well above the 1500-byte ceiling.",
            "_frame_rx": (
                # Ethernet 802.3
                #   Destination MAC : a1:b2:c3:d4:e5:f6
                #   Source MAC      : 12:13:14:15:16:17
                #   Length          : 0x07d0 (2000 bytes declared)
                #   Payload bytes   : 2000 (> 1500 maximum)
                b"\xa1\xb2\xc3\xd4\xe5\xf6\x12\x13\x14\x15\x16\x17\x07\xd0"
                + b"Y" * 2000
            ),
            "_results": {
                "error_message": (
                    f"The 'dlen' field value must be less than or equal to {ETHERNET_802_3__PAYLOAD__MAX_LEN}. "
                    "Got: 2000."
                ),
            },
        },
    ]
)
class TestEthernet8023ParserIntegrityChecks(TestCase):
    """
    The Ethernet 802.3 packet parser integrity checks tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    def test__ethernet_802_3__parser__raises_integrity_error(self) -> None:
        """
        Ensure the Ethernet 802.3 packet parser raises Ethernet8023IntegrityError
        with the expected '[INTEGRITY ERROR][Ethernet 802.3]'-prefixed message
        for every malformed frame.

        Reference: IEEE 802.3 §3 (802.3 frame integrity — length field bound).
        """

        with self.assertRaises(Ethernet8023IntegrityError) as error:
            Ethernet8023Parser(PacketRx(self._frame_rx))

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][Ethernet 802.3] {self._results['error_message']}",
            msg=f"Unexpected integrity error message for case: {self._description}",
        )


class TestEthernet8023ParserIntegrityChecksBoundary(TestCase):
    """
    Boundary tests for the Ethernet 802.3 packet parser integrity validator.
    """

    def test__ethernet_802_3__parser__integrity_check_passes_at_minimum_length(self) -> None:
        """
        Ensure a frame of exactly ETHERNET_802_3__HEADER__LEN bytes whose
        'dlen' field is zero passes the integrity validator and is parsed
        into a header with an empty payload — proving the integrity gate
        accepts the minimal valid frame.

        Reference: IEEE 802.3 §3 (802.3 frame integrity — length field bound).
        """

        frame = (
            # Ethernet 802.3
            #   Destination MAC : a1:b2:c3:d4:e5:f6
            #   Source MAC      : 12:13:14:15:16:17
            #   Length          : 0x0000 (empty payload declared)
            #   Frame length    : 14 bytes (== ETHERNET_802_3__HEADER__LEN)
            b"\xa1\xb2\xc3\xd4\xe5\xf6\x12\x13\x14\x15\x16\x17\x00\x00"
        )

        packet_rx = PacketRx(frame)
        parser = Ethernet8023Parser(packet_rx)

        self.assertEqual(
            parser.dlen,
            0,
            msg="Minimal valid frame must parse with dlen == 0.",
        )
        self.assertEqual(
            bytes(packet_rx.frame),
            b"",
            msg="PacketRx.frame must be advanced to an empty payload for dlen == 0.",
        )

    def test__ethernet_802_3__parser__integrity_check_passes_at_max_payload(self) -> None:
        """
        Ensure a frame with dlen == ETHERNET_802_3__PAYLOAD__MAX_LEN (1500)
        and exactly 1500 payload bytes passes integrity validation.

        Reference: IEEE 802.3 §3 (802.3 frame integrity — length field bound).
        """

        payload = b"Z" * ETHERNET_802_3__PAYLOAD__MAX_LEN
        frame = (
            # Ethernet 802.3
            #   Destination MAC : a1:b2:c3:d4:e5:f6
            #   Source MAC      : 12:13:14:15:16:17
            #   Length          : 0x05dc (1500 bytes == maximum)
            #   Payload bytes   : 1500
            b"\xa1\xb2\xc3\xd4\xe5\xf6\x12\x13\x14\x15\x16\x17\x05\xdc"
            + payload
        )

        packet_rx = PacketRx(frame)
        parser = Ethernet8023Parser(packet_rx)

        self.assertEqual(
            parser.dlen,
            ETHERNET_802_3__PAYLOAD__MAX_LEN,
            msg="Maximum valid frame must parse with dlen == 1500.",
        )
        self.assertEqual(
            bytes(packet_rx.frame),
            payload,
            msg="PacketRx.frame must be advanced to the full 1500-byte payload.",
        )

    def test__ethernet_802_3__parser__integrity_check_message_uses_actual_length(self) -> None:
        """
        Ensure the minimum-length error message reports the exact length of
        the provided buffer (not a truncated or cached value).

        Reference: IEEE 802.3 §3 (802.3 frame integrity — length field bound).
        """

        frame = b"\x00" * 7

        with self.assertRaises(Ethernet8023IntegrityError) as error:
            Ethernet8023Parser(PacketRx(frame))

        self.assertIn(
            "Got: 7 bytes.",
            str(error.exception),
            msg="Error message must include the actual short frame length.",
        )

    def test__ethernet_802_3__parser__integrity_inconsistent_precedes_oversize(self) -> None:
        """
        Ensure the 'inconsistent payload length' check fires before the
        'payload exceeds maximum' check when a frame has an oversized declared
        'dlen' that does not match the actual payload bytes.

        Reference: IEEE 802.3 §3 (802.3 frame integrity — length field bound).
        """

        frame = (
            # Ethernet 802.3
            #   Destination MAC : a1:b2:c3:d4:e5:f6
            #   Source MAC      : 12:13:14:15:16:17
            #   Length          : 0xffff (65535 declared, far above 1500)
            #   Payload bytes   : 1 (also far below 65535)
            b"\xa1\xb2\xc3\xd4\xe5\xf6\x12\x13\x14\x15\x16\x17\xff\xff\x00"
        )

        with self.assertRaises(Ethernet8023IntegrityError) as error:
            Ethernet8023Parser(PacketRx(frame))

        self.assertIn(
            "The 'dlen' field value must equal the actual payload length.",
            str(error.exception),
            msg="Consistency error must take precedence over maximum-length error.",
        )
