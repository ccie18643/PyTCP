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
Integrity-check unit tests for the SNAP (Sub-Network Access
Protocol) packet parser. The parser enforces a single
pre-parse rule — the frame must be at least 5 bytes long
to cover the 3-byte OUI + 2-byte Protocol ID — plus a
boundary-accepted case pinning that exact minimum.

net_proto/tests/unit/protocols/snap/test__snap__parser__integrity_checks.py

ver 3.0.8
"""

from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import PacketRx, SnapIntegrityError, SnapOui, SnapParser


@parameterized_class(
    [
        {
            "_description": "Frame is shorter than the 5-byte SNAP header.",
            # SNAP bytes (4 bytes — one short of the minimum):
            #   Bytes 0-2 : 0x000000 -> OUI candidate
            #   Byte  3   : 0x08    -> half of the would-be PID
            #   (no fifth byte — integrity violation: < SNAP__HEADER__LEN)
            "_frame_rx": b"\x00\x00\x00\x08",
            "_error_message": "The minimum packet length must be 5 bytes. Got: 4 bytes.",
        },
        {
            "_description": "Frame is empty (zero bytes).",
            # SNAP bytes (0 bytes — extreme under-length case).
            "_frame_rx": b"",
            "_error_message": "The minimum packet length must be 5 bytes. Got: 0 bytes.",
        },
        {
            "_description": "Frame contains only a single byte.",
            # SNAP bytes (1 byte — far below the 5-byte minimum):
            #   Byte 0 : 0xaa -> would-be OUI MSB, but the rest is missing.
            "_frame_rx": b"\xaa",
            "_error_message": "The minimum packet length must be 5 bytes. Got: 1 bytes.",
        },
    ]
)
class TestSnapParserIntegrityChecks(TestCase):
    """
    The SNAP packet parser integrity checks tests.
    """

    _description: str
    _frame_rx: bytes
    _error_message: str

    def test__snap__parser__raises_integrity_error_on_short_frame(self) -> None:
        """
        Ensure the SNAP parser raises SnapIntegrityError with the
        canonical '[INTEGRITY ERROR][SNAP]'-prefixed message for
        every frame shorter than the 5-byte fixed header.

        Reference: RFC 1042 §"Header Format" (5-byte SNAP header is mandatory).
        """

        with self.assertRaises(SnapIntegrityError) as error:
            SnapParser(PacketRx(self._frame_rx))

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][SNAP] {self._error_message}",
            msg=f"Unexpected integrity-error message for case: {self._description}",
        )


class TestSnapParserIntegrityBoundary(TestCase):
    """
    Boundary tests for the SNAP parser integrity validator —
    pins the positive path so a future tightening cannot
    silently reject the minimum-valid 5-byte frame.
    """

    def test__snap__parser__integrity__five_byte_header_only_accepted(self) -> None:
        """
        Ensure the shortest possible valid SNAP frame — exactly
        five bytes covering only the 3-byte OUI + 2-byte PID
        with no payload — passes the integrity check and parses
        successfully.

        Reference: RFC 1042 §"Header Format" (5-byte SNAP header minimum).
        """

        # SNAP bytes (5 bytes, header-only, RFC 1042 IPv4 encapsulation):
        #   Bytes 0-2 : 0x000000 -> OUI = SnapOui.ENCAP_ETHERTYPE
        #   Bytes 3-4 : 0x0800   -> PID = EtherType IPv4
        frame = b"\x00\x00\x00\x08\x00"

        packet_rx = PacketRx(frame)
        parser = SnapParser(packet_rx)

        self.assertEqual(
            parser.oui,
            int(SnapOui.ENCAP_ETHERTYPE),
            msg="Boundary-frame parser must decode OUI as ENCAP_ETHERTYPE.",
        )
        self.assertEqual(
            parser.pid,
            0x0800,
            msg="Boundary-frame parser must decode PID as 0x0800 (IPv4).",
        )
        self.assertEqual(
            bytes(parser.payload),
            b"",
            msg="Five-byte header-only frame must yield an empty payload.",
        )

    def test__snap__parser__integrity__exact_five_bytes_advances_packet_rx_frame(self) -> None:
        """
        Ensure parsing a header-only 5-byte SNAP frame advances
        'packet_rx.frame' past the header so the next layer
        sees an empty buffer rather than the SNAP header bytes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        frame = b"\x00\x00\x00\x08\x00"
        packet_rx = PacketRx(frame)

        SnapParser(packet_rx)

        self.assertEqual(
            bytes(packet_rx.frame),
            b"",
            msg="packet_rx.frame must be empty after consuming a header-only SNAP frame.",
        )


class TestSnapParserIntegrityMisc(TestCase):
    """
    Miscellaneous integrity-error invariants.
    """

    def test__snap__parser__integrity_error_message_includes_actual_length(self) -> None:
        """
        Ensure the under-length error message echoes the exact
        byte count that was received, so log archaeology can
        identify how short the offender was.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(SnapIntegrityError) as error:
            SnapParser(PacketRx(b"\xaa\xaa"))  # 2 bytes, three short

        self.assertIn(
            "Got: 2 bytes.",
            str(error.exception),
            msg="Under-length error must include the actual byte count.",
        )
