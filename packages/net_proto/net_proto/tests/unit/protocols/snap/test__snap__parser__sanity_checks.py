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
Sanity-check unit tests for the SNAP (Sub-Network Access
Protocol) parser. The parser's '_validate_sanity()'
currently implements no checks — every OUI / PID
combination is logically valid; the higher-level
dispatcher (PacketHandlerEthernet8023Rx) is responsible
for deciding what to do with each one. This file pins
the no-op contract: any structurally valid SNAP frame
parses regardless of OUI / PID values. A future
tightening of the sanity validator MUST add a
corresponding rejection case here.

net_proto/tests/unit/protocols/snap/test__snap__parser__sanity_checks.py

ver 3.0.9
"""

from typing import Any
from unittest import TestCase

from net_proto import PacketRx, SnapCiscoProtocol, SnapOui, SnapParser
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "RFC 1042 IPv4 encapsulation (OUI=0x000000, PID=0x0800) accepted by sanity.",
            # SNAP bytes:
            #   Bytes 0-2 : 0x000000 -> OUI = ENCAP_ETHERTYPE
            #   Bytes 3-4 : 0x0800   -> PID = EtherType IPv4
            "_frame_rx": b"\x00\x00\x00\x08\x00",
            "_results": {
                "oui": int(SnapOui.ENCAP_ETHERTYPE),
                "pid": 0x0800,
            },
        },
        {
            "_description": "RFC 1042 IPv6 encapsulation (OUI=0x000000, PID=0x86DD) accepted by sanity.",
            # SNAP bytes:
            #   Bytes 0-2 : 0x000000 -> OUI = ENCAP_ETHERTYPE
            #   Bytes 3-4 : 0x86dd   -> PID = EtherType IPv6
            "_frame_rx": b"\x00\x00\x00\x86\xdd",
            "_results": {
                "oui": int(SnapOui.ENCAP_ETHERTYPE),
                "pid": 0x86DD,
            },
        },
        {
            "_description": "Cisco CDP (OUI=0x00000C, PID=0x2000) accepted by sanity.",
            # SNAP bytes:
            #   Bytes 0-2 : 0x00000c -> OUI = CISCO
            #   Bytes 3-4 : 0x2000   -> PID = SnapCiscoProtocol.CDP
            "_frame_rx": b"\x00\x00\x0c\x20\x00",
            "_results": {
                "oui": int(SnapOui.CISCO),
                "pid": int(SnapCiscoProtocol.CDP),
            },
        },
        {
            "_description": "All-zero OUI/PID accepted by sanity (boundary minimum values).",
            # SNAP bytes:
            #   Bytes 0-2 : 0x000000 -> OUI=0 (ENCAP_ETHERTYPE)
            #   Bytes 3-4 : 0x0000   -> PID=0 (reserved EtherType)
            "_frame_rx": b"\x00\x00\x00\x00\x00",
            "_results": {
                "oui": 0,
                "pid": 0,
            },
        },
        {
            "_description": "All-one OUI/PID accepted by sanity (boundary maximum values).",
            # SNAP bytes:
            #   Bytes 0-2 : 0xffffff -> OUI = UINT_24__MAX (unknown vendor)
            #   Bytes 3-4 : 0xffff   -> PID = UINT_16__MAX
            "_frame_rx": b"\xff\xff\xff\xff\xff",
            "_results": {
                "oui": 0xFFFFFF,
                "pid": 0xFFFF,
            },
        },
        {
            "_description": "Apple OUI (0x080007, AppleTalk-over-Ethernet legacy) accepted by sanity.",
            # SNAP bytes:
            #   Bytes 0-2 : 0x080007 -> OUI = APPLE
            #   Bytes 3-4 : 0x809b   -> PID = AppleTalk-over-EtherTalk (sentinel)
            "_frame_rx": b"\x08\x00\x07\x80\x9b",
            "_results": {
                "oui": int(SnapOui.APPLE),
                "pid": 0x809B,
            },
        },
    ]
)
class TestSnapParserSanityChecks(TestCase):
    """
    The SNAP packet parser sanity checks tests. Every case is
    a structurally valid frame; the suite pins that none
    triggers SnapSanityError today (the validator is a no-op).
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    def test__snap__parser__sanity_accepts_every_valid_frame(self) -> None:
        """
        Ensure every structurally valid SNAP frame parses without
        raising SnapSanityError. Pins the intentional no-op
        contract of '_validate_sanity()'; any future patch that
        tightens the validator MUST replace this case with a
        targeted rejection test.

        Reference: RFC 1042 §"Header Format" (all OUI / PID combinations are syntactically valid).
        """

        packet_rx = PacketRx(self._frame_rx)
        parser = SnapParser(packet_rx)

        self.assertEqual(
            parser.oui,
            self._results["oui"],
            msg=f"Parsed 'oui' mismatch for case: {self._description}",
        )
        self.assertEqual(
            parser.pid,
            self._results["pid"],
            msg=f"Parsed 'pid' mismatch for case: {self._description}",
        )
