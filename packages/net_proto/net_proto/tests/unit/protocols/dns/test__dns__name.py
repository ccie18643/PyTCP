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
This module contains tests for the DNS domain-name codec.

net_proto/tests/unit/protocols/dns/test__dns__name.py

ver 3.0.8
"""

from unittest import TestCase

from net_proto.protocols.dns.dns__errors import DnsIntegrityError
from net_proto.protocols.dns.dns__name import (
    DNS__LABEL__MAX_LEN,
    DNS__NAME__MAX_LEN,
    decode_name,
    encode_name,
)

# A DNS message fragment exercising RFC 1035 §4.1.4 name compression:
#   Bytes 0-12  : 0x07 'example' 0x03 'com' 0x00 -> the name "example.com"
#   Bytes 13-18 : 0x03 'www' 0xc0 0x00 -> "www" + pointer to offset 0
#                 -> "www.example.com" (name ends after the pointer at 19)
#   Bytes 19-25 : 0x04 'mail' 0xc0 0x0d -> "mail" + pointer to offset 13
#                 -> "mail.www.example.com" (nested pointer; ends at 26)
_FRAME = b"\x07example\x03com\x00" b"\x03www\xc0\x00" b"\x04mail\xc0\x0d"


class TestDnsNameEncode(TestCase):
    """
    The DNS domain-name encoder tests.
    """

    def test__dns__name__encode_single_label(self) -> None:
        """
        Ensure a single-label name encodes as one length-prefixed label
        terminated by the zero-length root label.

        Reference: RFC 1035 §3.1 (Name space definitions).
        """

        self.assertEqual(
            encode_name("localhost"),
            b"\x09localhost\x00",
            msg="A single-label name must encode as length-prefixed label + root.",
        )

    def test__dns__name__encode_multi_label(self) -> None:
        """
        Ensure a multi-label name encodes as a sequence of length-prefixed
        labels terminated by the zero-length root label.

        Reference: RFC 1035 §3.1 (Name space definitions).
        """

        self.assertEqual(
            encode_name("example.com"),
            b"\x07example\x03com\x00",
            msg="A multi-label name must encode each label length-prefixed, root-terminated.",
        )

    def test__dns__name__encode_root(self) -> None:
        """
        Ensure the root name encodes as the single zero-length root label.

        Reference: RFC 1035 §3.1 (Name space definitions).
        """

        self.assertEqual(
            encode_name(""),
            b"\x00",
            msg="The root name must encode as the single zero byte.",
        )

    def test__dns__name__encode_trailing_dot_is_root(self) -> None:
        """
        Ensure a fully qualified name with a trailing dot encodes the same
        as the name without it (the trailing dot denotes the root).

        Reference: RFC 1035 §3.1 (Name space definitions).
        """

        self.assertEqual(
            encode_name("example.com."),
            encode_name("example.com"),
            msg="A trailing-dot FQDN must encode identically to the bare name.",
        )

    def test__dns__name__encode_rejects_oversized_label(self) -> None:
        """
        Ensure encoding a name whose label exceeds 63 octets is rejected.

        Reference: RFC 1035 §2.3.4 (Labels 63 octets or less).
        """

        with self.assertRaises(AssertionError):
            encode_name("a" * (DNS__LABEL__MAX_LEN + 1) + ".com")


class TestDnsNameDecode(TestCase):
    """
    The DNS domain-name decoder tests.
    """

    def test__dns__name__decode_uncompressed(self) -> None:
        """
        Ensure an uncompressed name decodes to its dotted form and reports
        the offset immediately past the root label.

        Reference: RFC 1035 §4.1.4 (Message compression).
        """

        self.assertEqual(
            decode_name(_FRAME, 0),
            ("example.com", 13),
            msg="An uncompressed name must decode to its dotted form with the past-root offset.",
        )

    def test__dns__name__decode_compressed_pointer(self) -> None:
        """
        Ensure a name ending in a compression pointer decodes by following
        the pointer, reporting the offset past the two-octet pointer.

        Reference: RFC 1035 §4.1.4 (Message compression).
        """

        self.assertEqual(
            decode_name(_FRAME, 13),
            ("www.example.com", 19),
            msg="A compressed name must follow the pointer and report the post-pointer offset.",
        )

    def test__dns__name__decode_nested_pointer(self) -> None:
        """
        Ensure a name whose pointer targets another compressed name is
        resolved through the full pointer chain.

        Reference: RFC 1035 §4.1.4 (Message compression).
        """

        self.assertEqual(
            decode_name(_FRAME, 19),
            ("mail.www.example.com", 26),
            msg="A nested pointer chain must resolve to the fully expanded name.",
        )

    def test__dns__name__decode_rejects_pointer_loop(self) -> None:
        """
        Ensure a compression pointer that forms a loop is rejected rather
        than followed indefinitely.

        Reference: RFC 1035 §4.1.4 (Message compression).
        """

        # A pointer at offset 0 that targets offset 0 — an immediate loop.
        with self.assertRaises(DnsIntegrityError):
            decode_name(b"\xc0\x00", 0)

    def test__dns__name__decode_rejects_truncated_label(self) -> None:
        """
        Ensure a label whose declared length runs past the end of the
        message is rejected.

        Reference: RFC 1035 §4.1.4 (Message compression).
        """

        # A 7-octet label declared, but only 3 octets present.
        with self.assertRaises(DnsIntegrityError):
            decode_name(b"\x07abc", 0)

    def test__dns__name__decode_rejects_reserved_label_bits(self) -> None:
        """
        Ensure a label whose top two length bits are the reserved 10 / 01
        combinations is rejected.

        Reference: RFC 1035 §4.1.4 (Message compression).
        """

        # 0x80 -> top bits '10', a reserved label type.
        with self.assertRaises(DnsIntegrityError):
            decode_name(b"\x80\x00", 0)

    def test__dns__name__decode_rejects_name_over_max(self) -> None:
        """
        Ensure a decoded name exceeding the 255-octet domain-name limit is
        rejected.

        Reference: RFC 1035 §2.3.4 (Names 255 octets or less).
        """

        # Five 63-octet labels (5 * 64 = 320 wire octets) exceed the limit.
        label = b"\x3f" + b"a" * DNS__LABEL__MAX_LEN
        frame = label * 5 + b"\x00"
        with self.assertRaises(DnsIntegrityError):
            decode_name(frame, 0)

    def test__dns__name__round_trip(self) -> None:
        """
        Ensure an encoded name decodes back to the original dotted form.

        Reference: RFC 1035 §3.1 (Name space definitions).
        """

        encoded = encode_name("www.example.com")
        self.assertEqual(
            decode_name(encoded, 0),
            ("www.example.com", len(encoded)),
            msg="An encoded name must decode back to its original dotted form.",
        )

    def test__dns__name__max_len_constant(self) -> None:
        """
        Ensure the domain-name length limit constant matches RFC 1035.

        Reference: RFC 1035 §2.3.4 (Names 255 octets or less).
        """

        self.assertEqual(
            DNS__NAME__MAX_LEN,
            255,
            msg="The domain-name length limit must be 255 octets per RFC 1035.",
        )
