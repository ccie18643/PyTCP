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
Integrity-check unit tests for the IEEE 802.2 LLC U-frame
parser. Covers both pre-parse integrity branches —
under-length frame and non-U-frame Control encoding — plus
the boundary-accepted case that pins the 3-byte minimum
valid header.

net_proto/tests/unit/protocols/llc/test__llc__parser__integrity_checks.py

ver 3.0.10
"""

from unittest import TestCase

from net_proto import LlcControl, LlcIntegrityError, LlcParser, LlcSap, PacketRx
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Frame is shorter than the 3-byte LLC U-frame header.",
            # LLC bytes (2 bytes — one short of the minimum):
            #   Byte 0 : 0x42 -> DSAP candidate (LlcSap.LAYER_MGMT)
            #   Byte 1 : 0x42 -> SSAP candidate (LlcSap.LAYER_MGMT)
            #   (no Control byte — integrity violation: < LLC__HEADER__LEN)
            "_frame_rx": b"\x42\x42",
            "_error_message": "The minimum packet length must be 3 bytes. Got: 2 bytes.",
        },
        {
            "_description": "Frame is empty (zero bytes).",
            # LLC bytes (0 bytes — extreme under-length case).
            "_frame_rx": b"",
            "_error_message": "The minimum packet length must be 3 bytes. Got: 0 bytes.",
        },
        {
            "_description": "Control field low 2 bits = 0b00 (I-frame, not supported).",
            # LLC bytes (3 bytes, Control field is an I-frame):
            #   Byte 0 : 0xaa -> DSAP=SNAP
            #   Byte 1 : 0xaa -> SSAP=SNAP
            #   Byte 2 : 0x10 -> Control low 2 bits = 0b00 (I-frame)
            "_frame_rx": b"\xaa\xaa\x10",
            "_error_message": (
                "The 'control' field's low two bits must be 0b11 (U-frame). " "Got: control=0x10 (low2=0b00)."
            ),
        },
        {
            "_description": "Control field low 2 bits = 0b01 (S-frame, not supported).",
            # LLC bytes (3 bytes, Control field is an S-frame):
            #   Byte 0 : 0xaa -> DSAP=SNAP
            #   Byte 1 : 0xaa -> SSAP=SNAP
            #   Byte 2 : 0x01 -> Control low 2 bits = 0b01 (S-frame)
            "_frame_rx": b"\xaa\xaa\x01",
            "_error_message": (
                "The 'control' field's low two bits must be 0b11 (U-frame). " "Got: control=0x01 (low2=0b01)."
            ),
        },
    ]
)
class TestLlcParserIntegrityChecks(TestCase):
    """
    The LLC packet parser integrity checks tests.
    """

    _description: str
    _frame_rx: bytes
    _error_message: str

    def test__llc__parser__raises_integrity_error_on_invalid_frame(self) -> None:
        """
        Ensure the LLC parser raises LlcIntegrityError with the
        canonical '[INTEGRITY ERROR][LLC]'-prefixed message for
        every frame that violates a pre-parse integrity rule.

        Reference: IEEE 802.2 §3 (LLC U-frame header layout).
        Reference: IEEE 802.2 §3.2 (frame-type encoding in Control field).
        """

        with self.assertRaises(LlcIntegrityError) as error:
            LlcParser(PacketRx(self._frame_rx))

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][LLC] {self._error_message}",
            msg=f"Unexpected integrity-error message for case: {self._description}",
        )


class TestLlcParserIntegrityBoundary(TestCase):
    """
    Boundary tests for the LLC parser integrity validator —
    pins the positive path so a future tightening cannot
    silently reject the minimum-valid 3-byte frame.
    """

    def test__llc__parser__integrity__three_byte_header_only_accepted(self) -> None:
        """
        Ensure the shortest possible valid LLC frame — exactly
        three bytes covering only the DSAP / SSAP / Control
        header — passes every integrity check and parses
        successfully.

        Reference: IEEE 802.2 §3 (3-byte U-frame header minimum).
        """

        # LLC bytes (3 bytes, header-only, well-formed UI command):
        #   Byte 0 : 0xaa -> DSAP=LlcSap.SNAP
        #   Byte 1 : 0xaa -> SSAP=LlcSap.SNAP
        #   Byte 2 : 0x03 -> Control=LlcControl.UI (low 2 bits = 0b11)
        frame = b"\xaa\xaa\x03"

        packet_rx = PacketRx(frame)
        parser = LlcParser(packet_rx)

        self.assertIs(
            parser.dsap,
            LlcSap.SNAP,
            msg="Boundary-frame parser must decode DSAP as LlcSap.SNAP.",
        )
        self.assertIs(
            parser.control,
            LlcControl.UI,
            msg="Boundary-frame parser must decode Control as LlcControl.UI.",
        )
        self.assertEqual(
            bytes(parser.payload),
            b"",
            msg="Three-byte header-only frame must yield an empty payload.",
        )

    def test__llc__parser__integrity__control_with_low_two_bits_eleven_accepted(self) -> None:
        """
        Ensure a Control value other than 0x03 but with the low
        two bits equal to 0b11 (e.g. XID/TEST) still passes the
        integrity check — only the low-2-bits encoding is
        validated.

        Reference: IEEE 802.2 §3.2 (U-frame low-2-bits = 0b11).
        """

        # LLC bytes:
        #   Byte 0 : 0xaa -> DSAP=SNAP
        #   Byte 1 : 0xaa -> SSAP=SNAP
        #   Byte 2 : 0xaf -> Control=XID poll-off (low 2 bits = 0b11)
        frame = b"\xaa\xaa\xaf"

        packet_rx = PacketRx(frame)
        parser = LlcParser(packet_rx)

        self.assertIs(
            parser.control,
            LlcControl.XID_POLL_OFF,
            msg="Low-2-bits=0b11 frame must be accepted regardless of upper bits.",
        )


class TestLlcParserIntegrityMisc(TestCase):
    """
    Miscellaneous integrity-error invariants.
    """

    def test__llc__parser__integrity_error_message_includes_actual_length(self) -> None:
        """
        Ensure the under-length error message echoes the exact
        byte count that was received, so log archaeology can
        identify how short the offender was.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(LlcIntegrityError) as error:
            LlcParser(PacketRx(b"\x42"))  # 1 byte, two short

        self.assertIn(
            "Got: 1 bytes.",
            str(error.exception),
            msg="Under-length error must include the actual byte count.",
        )

    def test__llc__parser__integrity_error_message_includes_actual_control(self) -> None:
        """
        Ensure the bad-Control error message echoes the offending
        Control byte verbatim and the parsed low-two-bits value,
        so a future debugging session can see the wire bits
        directly.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # LLC bytes:
        #   Byte 0 : 0xaa -> DSAP=SNAP
        #   Byte 1 : 0xaa -> SSAP=SNAP
        #   Byte 2 : 0x42 -> Control low 2 bits = 0b10 (S-frame variant)
        frame = b"\xaa\xaa\x42"

        with self.assertRaises(LlcIntegrityError) as error:
            LlcParser(PacketRx(frame))

        self.assertIn(
            "control=0x42",
            str(error.exception),
            msg="Bad-control error must include the offending Control byte.",
        )
        self.assertIn(
            "low2=0b10",
            str(error.exception),
            msg="Bad-control error must include the parsed low-2-bits value.",
        )
