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
Unit tests for the multicast service-discovery wire format shared by the
'mcast_announce.py' / 'mcast_discover.py' examples — the round trip through
'format_announcement' / 'parse_announcement' and the rejection of malformed
announcement datagrams.

pytcp/tests/unit/examples/test__examples__mcast_proto.py

ver 3.0.9
"""

from unittest import TestCase

from examples.mcast_proto import (
    Announcement,
    format_announcement,
    parse_announcement,
)

# The canonical one-line wire form of a well-formed announcement:
#   "PyTCP-DISCOVER v1 service=echo host=10.0.1.7 port=7\n"
_ANNOUNCEMENT = Announcement(service="echo", host="10.0.1.7", port=7)
_WIRE = b"PyTCP-DISCOVER v1 service=echo host=10.0.1.7 port=7\n"


class TestMcastProtoFormat(TestCase):
    """
    The multicast service-discovery announcement formatter tests.
    """

    def test__mcast_proto__format_produces_canonical_wire_line(self) -> None:
        """
        Ensure 'format_announcement' renders the announcement as its exact
        UTF-8, LF-terminated 'PyTCP-DISCOVER v1' wire line.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            format_announcement(_ANNOUNCEMENT),
            _WIRE,
            msg="format_announcement must render the canonical announcement line.",
        )


class TestMcastProtoParse(TestCase):
    """
    The multicast service-discovery announcement parser tests.
    """

    def test__mcast_proto__round_trip_preserves_fields(self) -> None:
        """
        Ensure a formatted announcement parses back into an equal
        'Announcement' — service, host and port survive the round trip.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            parse_announcement(format_announcement(_ANNOUNCEMENT)),
            _ANNOUNCEMENT,
            msg="A formatted announcement must parse back into an equal Announcement.",
        )

    def test__mcast_proto__parse_extracts_integer_port(self) -> None:
        """
        Ensure the parsed 'port' field is a real 'int', not the raw string
        token, so callers can use it as a port number directly.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        parsed = parse_announcement(_WIRE)

        assert parsed is not None  # narrow for mypy; asserted below

        self.assertIsInstance(
            parsed.port,
            int,
            msg="The parsed 'port' field must be an int, not the raw string token.",
        )
        self.assertEqual(
            parsed.port,
            7,
            msg="The parsed 'port' field must equal the announced value.",
        )

    def test__mcast_proto__parse_ignores_unknown_trailing_fields(self) -> None:
        """
        Ensure an announcement carrying extra unknown 'key=value' fields
        still parses on the recognised ones, so the format can grow without
        breaking older listeners.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        wire = b"PyTCP-DISCOVER v1 service=echo host=10.0.1.7 port=7 ttl=4 extra=x\n"

        self.assertEqual(
            parse_announcement(wire),
            _ANNOUNCEMENT,
            msg="Unknown trailing fields must be ignored, not rejected.",
        )

    def test__mcast_proto__parse_rejects_malformed_datagrams(self) -> None:
        """
        Ensure a datagram that is not a well-formed 'PyTCP-DISCOVER v1'
        announcement parses to None — wrong magic, wrong version, a missing
        field, a non-integer port, too few tokens, or non-UTF-8 bytes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for description, datagram in [
            ("wrong magic", b"OTHER-PROTO v1 service=echo host=10.0.1.7 port=7\n"),
            ("wrong version", b"PyTCP-DISCOVER v2 service=echo host=10.0.1.7 port=7\n"),
            ("too few tokens", b"PyTCP-DISCOVER\n"),
            ("missing service", b"PyTCP-DISCOVER v1 host=10.0.1.7 port=7\n"),
            ("missing host", b"PyTCP-DISCOVER v1 service=echo port=7\n"),
            ("missing port", b"PyTCP-DISCOVER v1 service=echo host=10.0.1.7\n"),
            ("non-integer port", b"PyTCP-DISCOVER v1 service=echo host=10.0.1.7 port=nope\n"),
            ("non-utf8 bytes", b"PyTCP-DISCOVER v1 service=\xff\xfe port=7\n"),
        ]:
            with self.subTest(case=description):
                self.assertIsNone(
                    parse_announcement(datagram),
                    msg=f"A malformed announcement ({description}) must parse to None.",
                )
