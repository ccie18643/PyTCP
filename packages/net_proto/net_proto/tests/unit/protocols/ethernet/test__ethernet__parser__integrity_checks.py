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
This module contains tests for the Ethernet II packet parser integrity checks.

The parser's integrity validator enforces a single invariant: the received
frame must be at least ETHERNET__HEADER__LEN (14) bytes long. Any shorter
frame must produce an EthernetIntegrityError before parsing begins.

net_proto/tests/unit/protocols/ethernet/test__ethernet__parser__integrity_checks.py

ver 3.0.10
"""

from typing import Any
from unittest import TestCase

from net_proto import (
    ETHERNET__HEADER__LEN,
    EthernetIntegrityError,
    EthernetParser,
    PacketRx,
)
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "The frame is empty (zero length).",
            "_frame_rx": b"",
            "_results": {
                "error_message": f"The minimum packet length must be {ETHERNET__HEADER__LEN} bytes. Got: 0 bytes.",
            },
        },
        {
            "_description": "The frame has a single byte.",
            "_frame_rx": b"\x00",
            "_results": {
                "error_message": f"The minimum packet length must be {ETHERNET__HEADER__LEN} bytes. Got: 1 bytes.",
            },
        },
        {
            "_description": "The frame length is one byte below the Ethernet header minimum.",
            "_frame_rx": (
                # Ethernet II
                #   Destination MAC : a1:b2:c3:d4:e5:f6
                #   Source MAC      : 12:13:14:15:16:17
                #   Ethertype       : truncated to a single byte 0xff
                #   Frame length    : 13 bytes (< 14-byte header minimum)
                b"\xa1\xb2\xc3\xd4\xe5\xf6\x12\x13\x14\x15\x16\x17\xff"
            ),
            "_results": {
                "error_message": (
                    f"The minimum packet length must be {ETHERNET__HEADER__LEN} bytes. "
                    f"Got: {ETHERNET__HEADER__LEN - 1} bytes."
                ),
            },
        },
        {
            "_description": "The frame holds only the destination and source MAC addresses (12 bytes).",
            "_frame_rx": (
                # Ethernet II
                #   Destination MAC : a1:b2:c3:d4:e5:f6
                #   Source MAC      : 12:13:14:15:16:17
                #   Ethertype       : missing (truncated before type field)
                #   Frame length    : 12 bytes (< 14-byte header minimum)
                b"\xa1\xb2\xc3\xd4\xe5\xf6\x12\x13\x14\x15\x16\x17"
            ),
            "_results": {
                "error_message": (
                    f"The minimum packet length must be {ETHERNET__HEADER__LEN} bytes. "
                    f"Got: {ETHERNET__HEADER__LEN - 2} bytes."
                ),
            },
        },
    ]
)
class TestEthernetParserIntegrityChecks(TestCase):
    """
    The Ethernet packet parser integrity checks tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    def test__ethernet__parser__raises_integrity_error_on_short_frame(self) -> None:
        """
        Ensure the Ethernet packet parser raises EthernetIntegrityError with
        the expected '[INTEGRITY ERROR][Ethernet]'-prefixed message for every
        under-length frame.

        Reference: RFC 894 (Ethernet II frame integrity — 14-byte header floor).
        """

        with self.assertRaises(EthernetIntegrityError) as error:
            EthernetParser(PacketRx(self._frame_rx))

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][Ethernet] {self._results['error_message']}",
            msg=f"Unexpected integrity error message for case: {self._description}",
        )


class TestEthernetParserIntegrityChecksBoundary(TestCase):
    """
    Boundary tests for the Ethernet packet parser integrity validator.
    """

    def test__ethernet__parser__integrity_check_passes_at_minimum_length(self) -> None:
        """
        Ensure a frame of exactly ETHERNET__HEADER__LEN bytes passes integrity
        validation. With the ethertype field set to an invalid value below
        0x0600 the sanity step must reject the frame instead — proving that
        the integrity gate itself did not raise.

        Reference: RFC 894 (Ethernet II frame integrity — 14-byte header floor).
        """

        frame = (
            # Ethernet II
            #   Destination MAC : a1:b2:c3:d4:e5:f6
            #   Source MAC      : 12:13:14:15:16:17
            #   Ethertype       : 0x0000 (invalid, triggers sanity failure)
            #   Frame length    : 14 bytes (== ETHERNET__HEADER__LEN)
            b"\xa1\xb2\xc3\xd4\xe5\xf6\x12\x13\x14\x15\x16\x17\x00\x00"
        )

        with self.assertRaises(Exception) as error:
            EthernetParser(PacketRx(frame))

        self.assertNotIsInstance(
            error.exception,
            EthernetIntegrityError,
            msg=(
                "At exactly ETHERNET__HEADER__LEN the integrity check must "
                "pass; failures here must originate from sanity validation, "
                "not integrity."
            ),
        )

    def test__ethernet__parser__integrity_check_message_uses_actual_length(self) -> None:
        """
        Ensure the error message reports the exact length of the provided
        buffer (not a truncated or cached value).

        Reference: RFC 894 (Ethernet II frame integrity — 14-byte header floor).
        """

        frame = b"\x00" * 7

        with self.assertRaises(EthernetIntegrityError) as error:
            EthernetParser(PacketRx(frame))

        self.assertIn(
            "Got: 7 bytes.",
            str(error.exception),
            msg="Error message must include the actual short frame length.",
        )
