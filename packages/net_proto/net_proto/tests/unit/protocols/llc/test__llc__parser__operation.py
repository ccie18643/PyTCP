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
Operation unit tests for the IEEE 802.2 LLC U-frame parser.

net_proto/tests/unit/protocols/llc/test__llc__parser__operation.py

ver 3.0.9
"""

from unittest import TestCase

from net_proto import LlcControl, LlcIntegrityError, LlcParser, LlcSap, PacketRx


class TestLlcParserOperation(TestCase):
    """
    The 'LlcParser' parsing happy-path operation tests.
    """

    def test__llc__parser__stp_bpdu_header(self) -> None:
        """
        Ensure parsing of an IEEE 802.1D Spanning Tree
        Protocol BPDU produces an LlcHeader with DSAP =
        SSAP = LlcSap.LAYER_MGMT and Control = LlcControl.UI.

        Reference: IEEE 802.1D §9 (STP BPDU LLC encapsulation).
        """

        # LLC header bytes for an STP BPDU:
        #   Byte 0 : 0x42 -> DSAP = LlcSap.LAYER_MGMT (STP)
        #   Byte 1 : 0x42 -> SSAP = LlcSap.LAYER_MGMT (STP)
        #   Byte 2 : 0x03 -> Control = LlcControl.UI
        #   Bytes 3+: BPDU payload (arbitrary 4 bytes of stub data)
        frame = b"\x42\x42\x03" + b"BPDU"

        packet_rx = PacketRx(frame)
        parser = LlcParser(packet_rx)

        self.assertIs(
            parser.dsap,
            LlcSap.LAYER_MGMT,
            msg="STP BPDU LLC DSAP must parse as LlcSap.LAYER_MGMT (0x42).",
        )
        self.assertIs(
            parser.ssap,
            LlcSap.LAYER_MGMT,
            msg="STP BPDU LLC SSAP must parse as LlcSap.LAYER_MGMT (0x42).",
        )
        self.assertIs(
            parser.control,
            LlcControl.UI,
            msg="STP BPDU LLC Control must parse as LlcControl.UI (0x03).",
        )
        self.assertEqual(
            bytes(parser.payload),
            b"BPDU",
            msg="LLC payload must equal the bytes after the 3-byte header.",
        )

    def test__llc__parser__snap_header(self) -> None:
        """
        Ensure parsing of an RFC 1042 SNAP-bearing LLC header
        produces DSAP = SSAP = LlcSap.SNAP and Control =
        LlcControl.UI; the SNAP header bytes are left in the
        LLC payload for the SNAP parser to consume next.

        Reference: RFC 1042 §"Header Format" (LLC DSAP=SSAP=0xAA, Control=0x03).
        """

        # LLC bytes for a SNAP-encapsulated frame:
        #   Byte 0 : 0xAA -> DSAP = LlcSap.SNAP
        #   Byte 1 : 0xAA -> SSAP = LlcSap.SNAP
        #   Byte 2 : 0x03 -> Control = LlcControl.UI
        #   Bytes 3-7 : SNAP header (OUI + EtherType)
        frame = b"\xaa\xaa\x03\x00\x00\x00\x08\x00"

        packet_rx = PacketRx(frame)
        parser = LlcParser(packet_rx)

        self.assertIs(
            parser.dsap,
            LlcSap.SNAP,
            msg="RFC 1042 SNAP DSAP must parse as LlcSap.SNAP (0xAA).",
        )
        self.assertIs(
            parser.ssap,
            LlcSap.SNAP,
            msg="RFC 1042 SNAP SSAP must parse as LlcSap.SNAP (0xAA).",
        )
        self.assertIs(
            parser.control,
            LlcControl.UI,
            msg="RFC 1042 SNAP LLC Control must parse as LlcControl.UI (0x03).",
        )
        self.assertEqual(
            bytes(parser.payload),
            b"\x00\x00\x00\x08\x00",
            msg="Five bytes of SNAP header must remain in the LLC payload.",
        )

    def test__llc__parser__packet_rx_llc_installed(self) -> None:
        """
        Ensure the parser installs itself on packet_rx.llc
        and advances packet_rx.frame past the 3-byte header.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        frame = b"\x42\x42\x03\xde\xad"
        packet_rx = PacketRx(frame)
        LlcParser(packet_rx)

        self.assertIsInstance(
            packet_rx.llc,
            LlcParser,
            msg="LlcParser must install itself on packet_rx.llc.",
        )
        self.assertEqual(
            bytes(packet_rx.frame),
            b"\xde\xad",
            msg="packet_rx.frame must be advanced past the 3-byte LLC header.",
        )

    def test__llc__parser__short_frame_raises_integrity(self) -> None:
        """
        Ensure a frame shorter than the 3-byte LLC header
        raises LlcIntegrityError with the canonical
        '[INTEGRITY ERROR][LLC]' prefix.

        Reference: IEEE 802.2 §3 (3-byte U-frame header minimum).
        """

        frame = b"\x42\x42"  # 2 bytes, one short
        packet_rx = PacketRx(frame)

        with self.assertRaises(LlcIntegrityError) as ctx:
            LlcParser(packet_rx)

        self.assertTrue(
            str(ctx.exception).startswith("[INTEGRITY ERROR][LLC]"),
            msg="LlcIntegrityError must carry the canonical [INTEGRITY ERROR][LLC] prefix.",
        )

    def test__llc__parser__non_u_frame_control_raises_integrity(self) -> None:
        """
        Ensure a Control field whose low two bits are not
        0b11 (i.e. an I-frame or S-frame) is rejected — PyTCP
        supports U-frames only per IEEE 802.2 Type 1
        connectionless service.

        Reference: IEEE 802.2 §3.2 (frame-type encoding in Control field).
        Reference: RFC 1042 §"Description" (Type 1 connectionless service).
        """

        # I-frame: Control low 2 bits = 0b00 (e.g. 0x10).
        # DSAP / SSAP arbitrary, the integrity check is on
        # the Control field.
        frame = b"\xaa\xaa\x10\x00"

        packet_rx = PacketRx(frame)

        with self.assertRaises(LlcIntegrityError) as ctx:
            LlcParser(packet_rx)

        self.assertIn(
            "low two bits must be 0b11",
            str(ctx.exception),
            msg="Non-U-frame Control value must raise an integrity error citing the low-2-bits rule.",
        )

    def test__llc__parser__unknown_sap_accepted(self) -> None:
        """
        Ensure DSAP values outside the well-known LlcSap
        enum members are still parsed successfully — the
        engine surfaces the unknown value via the
        'is_unknown' marker on ProtoEnum so the caller can
        log it without the parser rejecting the frame.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # DSAP 0x7E (X.25 PLP, not in the LlcSap enum).
        frame = b"\x7e\x7e\x03payload"

        packet_rx = PacketRx(frame)
        parser = LlcParser(packet_rx)

        self.assertEqual(
            int(parser.dsap),
            0x7E,
            msg="Unknown LLC DSAP value must round-trip via from_int.",
        )
        self.assertTrue(
            parser.dsap.is_unknown,
            msg="Unknown LLC DSAP value must report is_unknown == True.",
        )
