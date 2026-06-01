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
Sanity-check unit tests for the IEEE 802.2 LLC U-frame
parser. The parser's '_validate_sanity()' currently
implements no checks — every DSAP / SSAP value the parser
will see (including the Global SAP 0xFF used by the
Novell-raw-802.3 convention) has a legitimate
real-world use. This file pins the no-op contract: any
structurally valid frame parses regardless of field
values. A future tightening of the sanity validator MUST
add a corresponding rejection case here.

net_proto/tests/unit/protocols/llc/test__llc__parser__sanity_checks.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import LlcControl, LlcParser, LlcSap, PacketRx


@parameterized_class(
    [
        {
            "_description": "Well-known DSAP/SSAP pair (STP BPDU) accepted by sanity.",
            # LLC bytes:
            #   Byte 0 : 0x42 -> DSAP=LlcSap.LAYER_MGMT (STP)
            #   Byte 1 : 0x42 -> SSAP=LlcSap.LAYER_MGMT (STP)
            #   Byte 2 : 0x03 -> Control=LlcControl.UI
            "_frame_rx": b"\x42\x42\x03",
            "_results": {
                "dsap": LlcSap.LAYER_MGMT,
                "ssap": LlcSap.LAYER_MGMT,
                "control": LlcControl.UI,
            },
        },
        {
            "_description": "NULL DSAP / NULL SSAP (LLC-management null) accepted by sanity.",
            # LLC bytes:
            #   Byte 0 : 0x00 -> DSAP=LlcSap.NULL
            #   Byte 1 : 0x00 -> SSAP=LlcSap.NULL
            #   Byte 2 : 0x03 -> Control=LlcControl.UI
            "_frame_rx": b"\x00\x00\x03",
            "_results": {
                "dsap": LlcSap.NULL,
                "ssap": LlcSap.NULL,
                "control": LlcControl.UI,
            },
        },
        {
            "_description": "Global DSAP (0xFF, Novell raw-802.3 marker) accepted by sanity.",
            # LLC bytes:
            #   Byte 0 : 0xff -> DSAP=LlcSap.GLOBAL
            #   Byte 1 : 0xff -> SSAP=LlcSap.GLOBAL
            #   Byte 2 : 0x03 -> Control=LlcControl.UI
            "_frame_rx": b"\xff\xff\x03",
            "_results": {
                "dsap": LlcSap.GLOBAL,
                "ssap": LlcSap.GLOBAL,
                "control": LlcControl.UI,
            },
        },
        {
            "_description": "Unknown DSAP/SSAP (0x7E, X.25 PLP) accepted by sanity.",
            # LLC bytes:
            #   Byte 0 : 0x7e -> DSAP=unknown (X.25 PLP)
            #   Byte 1 : 0x7e -> SSAP=unknown (X.25 PLP)
            #   Byte 2 : 0x03 -> Control=LlcControl.UI
            "_frame_rx": b"\x7e\x7e\x03",
            "_results": {
                # Unknown LlcSap value extended dynamically.
                "dsap_int": 0x7E,
                "ssap_int": 0x7E,
                "control": LlcControl.UI,
            },
        },
        {
            "_description": "XID command (Control=0xAF) accepted by sanity.",
            # LLC bytes:
            #   Byte 0 : 0xaa -> DSAP=SNAP
            #   Byte 1 : 0xaa -> SSAP=SNAP
            #   Byte 2 : 0xaf -> Control=XID_POLL_OFF (low 2 bits = 0b11)
            "_frame_rx": b"\xaa\xaa\xaf",
            "_results": {
                "dsap": LlcSap.SNAP,
                "ssap": LlcSap.SNAP,
                "control": LlcControl.XID_POLL_OFF,
            },
        },
    ]
)
class TestLlcParserSanityChecks(TestCase):
    """
    The LLC packet parser sanity checks tests. Every case is
    a structurally valid frame; the suite pins that none
    triggers LlcSanityError today (the validator is a no-op).
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    def test__llc__parser__sanity_accepts_every_valid_frame(self) -> None:
        """
        Ensure every structurally valid LLC frame parses without
        raising LlcSanityError. Pins the intentional no-op
        contract of '_validate_sanity()'; any future patch that
        tightens the validator MUST replace this case with a
        targeted rejection test.

        Reference: IEEE 802.2 §3 (LLC SAP space; all values logically valid).
        """

        packet_rx = PacketRx(self._frame_rx)
        parser = LlcParser(packet_rx)

        if "dsap" in self._results:
            self.assertIs(
                parser.dsap,
                self._results["dsap"],
                msg=f"Parsed 'dsap' mismatch for case: {self._description}",
            )
        if "ssap" in self._results:
            self.assertIs(
                parser.ssap,
                self._results["ssap"],
                msg=f"Parsed 'ssap' mismatch for case: {self._description}",
            )
        if "dsap_int" in self._results:
            self.assertEqual(
                int(parser.dsap),
                self._results["dsap_int"],
                msg=f"Parsed 'dsap' integer mismatch for case: {self._description}",
            )
        if "ssap_int" in self._results:
            self.assertEqual(
                int(parser.ssap),
                self._results["ssap_int"],
                msg=f"Parsed 'ssap' integer mismatch for case: {self._description}",
            )
        self.assertIs(
            parser.control,
            self._results["control"],
            msg=f"Parsed 'control' mismatch for case: {self._description}",
        )
