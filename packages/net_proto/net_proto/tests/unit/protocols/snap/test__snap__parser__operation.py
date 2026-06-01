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
Operation unit tests for the SNAP packet parser.

net_proto/tests/unit/protocols/snap/test__snap__parser__operation.py

ver 3.0.8
"""

from unittest import TestCase

from net_proto import (
    PacketRx,
    SnapCiscoProtocol,
    SnapIntegrityError,
    SnapOui,
    SnapParser,
)
from net_proto.lib.buffer import Buffer


class TestSnapParserOperation(TestCase):
    """
    The 'SnapParser' parsing happy-path operation tests.
    """

    def test__snap__parser__rfc1042_ip_over_snap(self) -> None:
        """
        Ensure parsing of an RFC 1042 IP-over-SNAP frame
        produces SnapHeader with OUI = SnapOui.ENCAP_ETHERTYPE
        (0x000000) and PID = 0x0800 (the IPv4 EtherType).

        Reference: RFC 1042 §"Header Format" (OUI 0 → EtherType in PID).
        """

        # SNAP bytes:
        #   Bytes 0-2 : 00 00 00 -> OUI = ENCAP_ETHERTYPE
        #   Bytes 3-4 : 08 00    -> PID = 0x0800 (IPv4)
        #   Bytes 5+  : IPv4 packet bytes (stub)
        frame = b"\x00\x00\x00\x08\x00\xde\xad\xbe\xef"

        packet_rx = PacketRx(frame)
        parser = SnapParser(packet_rx)

        self.assertEqual(
            parser.oui,
            SnapOui.ENCAP_ETHERTYPE,
            msg="RFC 1042 IP-over-SNAP OUI must parse as 0x000000.",
        )
        self.assertEqual(
            parser.pid,
            0x0800,
            msg="RFC 1042 IPv4-over-SNAP PID must parse as 0x0800.",
        )
        self.assertTrue(
            parser.header.is_encapsulated_ethertype,
            msg="is_encapsulated_ethertype must be True when OUI = 0x000000.",
        )
        self.assertEqual(
            bytes(parser.payload),
            b"\xde\xad\xbe\xef",
            msg="SNAP payload must be the bytes after the 5-byte header.",
        )

    def test__snap__parser__cdp_frame(self) -> None:
        """
        Ensure parsing of a Cisco CDP frame produces
        SnapHeader with OUI = SnapOui.CISCO (0x00000C)
        and PID = SnapCiscoProtocol.CDP (0x2000).

        Reference: Cisco CDP encapsulation (OUI 0x00000C, PID 0x2000).
        """

        # SNAP bytes for a CDP frame:
        #   Bytes 0-2 : 00 00 0c -> OUI = SnapOui.CISCO
        #   Bytes 3-4 : 20 00    -> PID = SnapCiscoProtocol.CDP
        frame = b"\x00\x00\x0c\x20\x00CDP-PAYLOAD"

        packet_rx = PacketRx(frame)
        parser = SnapParser(packet_rx)

        self.assertEqual(
            parser.oui,
            SnapOui.CISCO,
            msg="Cisco SNAP OUI must parse as 0x00000C.",
        )
        self.assertEqual(
            parser.pid,
            SnapCiscoProtocol.CDP,
            msg="CDP PID must parse as 0x2000.",
        )
        self.assertFalse(
            parser.header.is_encapsulated_ethertype,
            msg="is_encapsulated_ethertype must be False when OUI is non-zero.",
        )

    def test__snap__parser__packet_rx_snap_installed(self) -> None:
        """
        Ensure the parser installs itself on packet_rx.snap
        and advances packet_rx.frame past the 5-byte header.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        frame = b"\x00\x00\x00\x08\x00\xde\xad"
        packet_rx = PacketRx(frame)
        SnapParser(packet_rx)

        self.assertIsInstance(
            packet_rx.snap,
            SnapParser,
            msg="SnapParser must install itself on packet_rx.snap.",
        )
        self.assertEqual(
            bytes(packet_rx.frame),
            b"\xde\xad",
            msg="packet_rx.frame must be advanced past the 5-byte SNAP header.",
        )

    def test__snap__parser__short_frame_raises_integrity(self) -> None:
        """
        Ensure a frame shorter than the 5-byte SNAP header
        raises SnapIntegrityError with the canonical
        '[INTEGRITY ERROR][SNAP]' prefix.

        Reference: RFC 1042 §"Header Format" (8-byte LLC+SNAP minimum; 5-byte SNAP alone).
        """

        frame = b"\x00\x00\x00\x08"  # 4 bytes, one short
        packet_rx = PacketRx(frame)

        with self.assertRaises(SnapIntegrityError) as ctx:
            SnapParser(packet_rx)

        self.assertTrue(
            str(ctx.exception).startswith("[INTEGRITY ERROR][SNAP]"),
            msg="SnapIntegrityError must carry the canonical [INTEGRITY ERROR][SNAP] prefix.",
        )

    def test__snap__parser__round_trip_via_assembler(self) -> None:
        """
        Ensure that a SnapHeader assembled via SnapAssembler
        and parsed back produces identical OUI + PID values
        — round-trip integrity of the 5-byte SNAP encoding.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from net_proto import SnapAssembler

        original = SnapAssembler(
            snap__oui=int(SnapOui.CISCO),
            snap__pid=int(SnapCiscoProtocol.UDLD),
            snap__payload=b"udld-tlv",
        )
        buffers: list[Buffer] = []
        original.assemble(buffers)
        serialized = b"".join(bytes(b) for b in buffers)

        packet_rx = PacketRx(serialized)
        parser = SnapParser(packet_rx)

        self.assertEqual(
            parser.oui,
            int(SnapOui.CISCO),
            msg="Round-tripped OUI must equal the assembler input.",
        )
        self.assertEqual(
            parser.pid,
            int(SnapCiscoProtocol.UDLD),
            msg="Round-tripped PID must equal the assembler input.",
        )
        self.assertEqual(
            bytes(parser.payload),
            b"udld-tlv",
            msg="Round-tripped payload must equal the assembler input.",
        )
