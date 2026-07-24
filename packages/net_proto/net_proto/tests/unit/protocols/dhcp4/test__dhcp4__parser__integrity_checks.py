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
Module contains tests for the DHCPv4 packet parser integrity checks.

The parser's integrity validator enforces a single invariant: the received
frame must be at least DHCP4__HEADER__LEN (240) bytes long. Any shorter frame
must produce a Dhcp4IntegrityError before parsing begins.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__parser__integrity_checks.py

ver 3.0.9
"""

from typing import Any
from unittest import TestCase

from net_proto import DHCP4__HEADER__LEN, Dhcp4IntegrityError, Dhcp4Parser
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "The packet is empty (zero length).",
            "_args": [b""],
            "_results": {
                "error_message": f"The minimum packet length must be {DHCP4__HEADER__LEN} bytes. Got: 0 bytes.",
            },
        },
        {
            "_description": "The packet has a single byte.",
            "_args": [b"\x00"],
            "_results": {
                "error_message": f"The minimum packet length must be {DHCP4__HEADER__LEN} bytes. Got: 1 bytes.",
            },
        },
        {
            "_description": "The packet length is lower than the DHCPv4 minimum header length by 1.",
            "_args": [b"\x00" * (DHCP4__HEADER__LEN - 1)],
            "_results": {
                "error_message": (
                    f"The minimum packet length must be {DHCP4__HEADER__LEN} bytes. "
                    f"Got: {DHCP4__HEADER__LEN - 1} bytes."
                ),
            },
        },
        {
            "_description": "The packet length is roughly half of the DHCPv4 minimum header length.",
            "_args": [b"\x00" * (DHCP4__HEADER__LEN // 2)],
            "_results": {
                "error_message": (
                    f"The minimum packet length must be {DHCP4__HEADER__LEN} bytes. "
                    f"Got: {DHCP4__HEADER__LEN // 2} bytes."
                ),
            },
        },
    ]
)
class TestDhcp4ParserIntegrityChecks(TestCase):
    """
    The DHCPv4 packet parser integrity checks tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__dhcp4__parser__from_buffer(self) -> None:
        """
        Ensure the DHCPv4 packet parser raises Dhcp4IntegrityError with the
        expected '[INTEGRITY ERROR][DHCPv4]'-prefixed message for every
        under-length frame.

        Reference: RFC 2131 §2 (fixed BOOTP header is 236 B + 4-byte magic cookie = 240 B floor).
        """

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4Parser(*self._args)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][DHCPv4] {self._results['error_message']}",
            msg=f"Unexpected integrity error message for case: {self._description}",
        )


class TestDhcp4ParserIntegrityChecksBoundary(TestCase):
    """
    Boundary tests for the DHCPv4 packet parser integrity validator.
    """

    def test__dhcp4__parser__integrity_check_passes_at_minimum_length(
        self,
    ) -> None:
        """
        Ensure a frame of exactly DHCP4__HEADER__LEN bytes is not rejected
        by the minimum-length check. The parse step still fails (all-zero
        frame has invalid header content) and the failure surfaces as a
        Dhcp4IntegrityError once the parser wraps the header 'from_buffer'
        asserts, but the resulting message must not be the length error.

        Reference: RFC 2131 §2 (240-byte header is the structural floor; content checks are separate).
        """

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4Parser(memoryview(b"\x00" * DHCP4__HEADER__LEN))

        self.assertNotIn(
            "minimum packet length",
            str(error.exception),
            msg=(
                "At exactly DHCP4__HEADER__LEN the minimum-length check must "
                "pass; the parse failure must come from header content, not "
                "length."
            ),
        )

    def test__dhcp4__parser__integrity_check_message_uses_actual_length(
        self,
    ) -> None:
        """
        Ensure the error message reports the exact length of the provided
        buffer (not a truncated or cached value).

        Reference: PyTCP test infrastructure (no RFC clause — diagnostic message integrity).
        """

        frame = memoryview(b"\x00" * 37)

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4Parser(frame)

        self.assertIn(
            "Got: 37 bytes.",
            str(error.exception),
            msg="Error message must include the actual short frame length.",
        )


class TestDhcp4ParserSubnetMaskContiguity(TestCase):
    """
    The DHCPv4 Subnet Mask option contiguity tests. RFC 950 §2.1
    requires a subnet mask to consist of high-order ones
    followed by low-order zeros; non-contiguous wire bytes are
    rejected at the option's `_validate_integrity` static
    method (before `Ip4Mask` construction) with a typed
    `Dhcp4IntegrityError`.
    """

    @staticmethod
    def _bootp_blob() -> bytearray:
        """
        Build a minimal valid BOOTP header (240 bytes including
        the magic cookie) that the parser will accept structurally.
        """

        blob = bytearray(240)
        blob[0] = 0x02  # op = BOOTREPLY
        blob[1] = 0x01  # htype = ETHERNET
        blob[2] = 0x06  # hlen = 6
        # xid at bytes 4..7
        blob[4:8] = (0x12345678).to_bytes(4, "big")
        # magic cookie at bytes 236..239
        blob[236:240] = b"\x63\x82\x53\x63"
        return blob

    def test__dhcp4__parser__non_contiguous_subnet_mask_rejected(self) -> None:
        """
        Ensure a hostile wire frame whose Subnet Mask option carries
        non-contiguous mask bits (e.g. 0xFF00FF00) raises
        Dhcp4IntegrityError at the option's static integrity check —
        before `Ip4Mask` construction would otherwise raise an
        untyped Ip4MaskFormatError.

        Reference: RFC 950 §2.1 (subnet mask consists of contiguous
        high-order ones).
        """

        frame = bytes(self._bootp_blob()) + b"\x01\x04\xff\x00\xff\x00\xff"

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4Parser(memoryview(frame))

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Subnet Mask must consist of contiguous "
            "high-order ones (RFC 950 §2.1). Got: 0xff00ff00",
            msg="Non-contiguous mask must be rejected with RFC 950 §2.1 cite.",
        )

    def test__dhcp4__parser__contiguous_subnet_mask_accepted(self) -> None:
        """
        Ensure a wire frame whose Subnet Mask option carries a
        well-formed contiguous mask (e.g. /24 = 0xFFFFFF00) parses
        cleanly and surfaces the parsed mask via `parser.subnet_mask`.

        Reference: RFC 950 §2.1 (subnet mask consists of contiguous
        high-order ones).
        """

        # Options: Subnet Mask (/24) + Message Type (DISCOVER, required by RFC 2131 §3) + End.
        frame = bytes(self._bootp_blob()) + b"\x01\x04\xff\xff\xff\x00\x35\x01\x01\xff"

        parser = Dhcp4Parser(memoryview(frame))

        self.assertEqual(
            str(parser.subnet_mask),
            "/24",
            msg="Valid contiguous mask must parse to /24.",
        )
