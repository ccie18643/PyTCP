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
Operation unit tests for the SNAP (Sub-Network Access
Protocol) packet assembler.

net_proto/tests/unit/protocols/snap/test__snap__assembler__operation.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Buffer
from net_proto import (
    SNAP__HEADER__LEN,
    SnapAssembler,
    SnapCiscoProtocol,
    SnapHeader,
    SnapOui,
    Tracker,
)
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "RFC 1042 IPv4-over-SNAP (OUI=0x000000, PID=0x0800 EtherType IPv4).",
            "_kwargs": {
                "snap__oui": int(SnapOui.ENCAP_ETHERTYPE),
                "snap__pid": 0x0800,
                "snap__payload": b"IPv4",
            },
            "_results": {
                "__len__": 9,
                "__str__": "SNAP oui 0x000000 pid 0x0800, len 4",
                "__repr__": ("SnapAssembler(header=SnapHeader(oui=0, pid=2048), payload=b'IPv4')"),
                # SNAP wire frame (9 bytes = 5-byte header + 4-byte payload):
                #   Bytes 0-2 : 0x000000 -> OUI = SnapOui.ENCAP_ETHERTYPE
                #   Bytes 3-4 : 0x0800   -> PID = EtherType IPv4
                #   Bytes 5-8 : b"IPv4"  -> Stub IPv4-style payload
                "__bytes__": b"\x00\x00\x00\x08\x00IPv4",
                "oui": 0x000000,
                "pid": 0x0800,
                "header": SnapHeader(oui=0x000000, pid=0x0800),
                "payload": b"IPv4",
            },
        },
        {
            "_description": "RFC 1042 IPv6-over-SNAP (OUI=0x000000, PID=0x86DD EtherType IPv6).",
            "_kwargs": {
                "snap__oui": int(SnapOui.ENCAP_ETHERTYPE),
                "snap__pid": 0x86DD,
                "snap__payload": b"\x60" + b"\x00" * 7,
            },
            "_results": {
                "__len__": 13,
                "__str__": "SNAP oui 0x000000 pid 0x86dd, len 8",
                "__repr__": (
                    "SnapAssembler(header=SnapHeader(oui=0, pid=34525), "
                    "payload=b'`\\x00\\x00\\x00\\x00\\x00\\x00\\x00')"
                ),
                # SNAP wire frame (13 bytes = 5-byte header + 8-byte payload):
                #   Bytes 0-2  : 0x000000 -> OUI = SnapOui.ENCAP_ETHERTYPE
                #   Bytes 3-4  : 0x86dd   -> PID = EtherType IPv6
                #   Byte  5    : 0x60     -> IPv6 Version=6 nibble
                #   Bytes 6-12 : 0x00 * 7 -> Stub IPv6 header tail
                "__bytes__": b"\x00\x00\x00\x86\xdd\x60\x00\x00\x00\x00\x00\x00\x00",
                "oui": 0x000000,
                "pid": 0x86DD,
                "header": SnapHeader(oui=0x000000, pid=0x86DD),
                "payload": b"\x60" + b"\x00" * 7,
            },
        },
        {
            "_description": "RFC 1042 ARP-over-SNAP (OUI=0x000000, PID=0x0806 EtherType ARP).",
            "_kwargs": {
                "snap__oui": int(SnapOui.ENCAP_ETHERTYPE),
                "snap__pid": 0x0806,
                "snap__payload": b"",
            },
            "_results": {
                "__len__": 5,
                "__str__": "SNAP oui 0x000000 pid 0x0806, len 0",
                "__repr__": ("SnapAssembler(header=SnapHeader(oui=0, pid=2054), payload=b'')"),
                # SNAP wire frame (5 bytes, header-only):
                #   Bytes 0-2 : 0x000000 -> OUI = SnapOui.ENCAP_ETHERTYPE
                #   Bytes 3-4 : 0x0806   -> PID = EtherType ARP
                "__bytes__": b"\x00\x00\x00\x08\x06",
                "oui": 0x000000,
                "pid": 0x0806,
                "header": SnapHeader(oui=0x000000, pid=0x0806),
                "payload": b"",
            },
        },
        {
            "_description": "Cisco CDP-over-SNAP (OUI=0x00000C Cisco, PID=0x2000 CDP).",
            "_kwargs": {
                "snap__oui": int(SnapOui.CISCO),
                "snap__pid": int(SnapCiscoProtocol.CDP),
                "snap__payload": b"CDP-TLV",
            },
            "_results": {
                "__len__": 12,
                "__str__": "SNAP oui 0x00000c pid 0x2000, len 7",
                "__repr__": ("SnapAssembler(header=SnapHeader(oui=12, pid=8192), payload=b'CDP-TLV')"),
                # SNAP wire frame (12 bytes = 5-byte header + 7-byte payload):
                #   Bytes 0-2  : 0x00000c -> OUI = SnapOui.CISCO
                #   Bytes 3-4  : 0x2000   -> PID = SnapCiscoProtocol.CDP
                #   Bytes 5-11 : b"CDP-TLV" (CDP TLV stub payload)
                "__bytes__": b"\x00\x00\x0c\x20\x00CDP-TLV",
                "oui": 0x00000C,
                "pid": 0x2000,
                "header": SnapHeader(oui=0x00000C, pid=0x2000),
                "payload": b"CDP-TLV",
            },
        },
    ]
)
class TestSnapAssemblerOperation(TestCase):
    """
    The SNAP packet assembler operation tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the SNAP packet assembler from the parametrized
        kwargs.
        """

        self._snap__assembler = SnapAssembler(**self._kwargs)

    def test__snap__assembler__len(self) -> None:
        """
        Ensure '__len__()' returns header + payload bytes.

        Reference: RFC 1042 §"Header Format" (5-byte SNAP header + variable payload).
        """

        self.assertEqual(
            len(self._snap__assembler),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__snap__assembler__str(self) -> None:
        """
        Ensure '__str__()' returns the canonical log string.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._snap__assembler),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__snap__assembler__repr(self) -> None:
        """
        Ensure '__repr__()' returns the constructor-callable
        representation string.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            repr(self._snap__assembler),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__snap__assembler__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the expected wire-frame
        bytes (3-byte OUI followed by 2-byte PID).

        Reference: RFC 1042 §"Header Format" (24-bit OUI || 16-bit Protocol ID).
        """

        self.assertEqual(
            bytes(self._snap__assembler),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__snap__assembler__oui(self) -> None:
        """
        Ensure the 'oui' property returns the provided 24-bit
        Organizationally Unique Identifier.

        Reference: RFC 1042 §"Header Format" (OUI field).
        """

        self.assertEqual(
            self._snap__assembler.oui,
            self._results["oui"],
            msg=f"Unexpected 'oui' for case: {self._description}",
        )

    def test__snap__assembler__pid(self) -> None:
        """
        Ensure the 'pid' property returns the provided 16-bit
        Protocol Identifier (an EtherType when OUI = 0).

        Reference: RFC 1042 §"Header Format" (Protocol ID field).
        """

        self.assertEqual(
            self._snap__assembler.pid,
            self._results["pid"],
            msg=f"Unexpected 'pid' for case: {self._description}",
        )

    def test__snap__assembler__header(self) -> None:
        """
        Ensure the 'header' property returns the computed
        SnapHeader dataclass.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._snap__assembler.header,
            self._results["header"],
            msg=f"Unexpected 'header' for case: {self._description}",
        )

    def test__snap__assembler__payload(self) -> None:
        """
        Ensure the 'payload' property returns the provided
        payload bytes verbatim.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._snap__assembler.payload,
            self._results["payload"],
            msg=f"Unexpected 'payload' for case: {self._description}",
        )

    def test__snap__assembler__assemble(self) -> None:
        """
        Ensure 'assemble()' appends header and payload in
        wire order so the concatenation matches '__bytes__'.

        Reference: RFC 1042 §"Header Format" (header precedes payload on the wire).
        """

        buffers: list[Buffer] = []

        self._snap__assembler.assemble(buffers)

        self.assertEqual(
            b"".join(buffers),
            self._results["__bytes__"],
            msg=f"Unexpected concatenated buffers for case: {self._description}",
        )

    def test__snap__assembler__assemble__buffer_layout(self) -> None:
        """
        Ensure 'assemble()' appends exactly two buffers —
        the 5-byte SNAP header followed by the payload — so
        downstream code can locate them by index.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        buffers: list[Buffer] = []

        self._snap__assembler.assemble(buffers)

        self.assertEqual(
            len(buffers),
            2,
            msg="SnapAssembler.assemble must append header + payload.",
        )
        self.assertEqual(
            len(buffers[0]),
            SNAP__HEADER__LEN,
            msg="SnapAssembler.assemble must append the 5-byte fixed header first.",
        )
        self.assertEqual(
            len(buffers[1]),
            len(self._results["payload"]),
            msg="SnapAssembler.assemble must append the payload buffer second.",
        )


class TestSnapAssemblerMisc(TestCase):
    """
    The SNAP packet assembler miscellaneous functions tests.
    """

    def test__snap__assembler__defaults(self) -> None:
        """
        Ensure constructing 'SnapAssembler' with no kwargs
        yields a minimum-valid header-only frame: OUI = 0,
        PID = 0, empty payload, length equal to the 5-byte
        SNAP header.

        Reference: RFC 1042 §"Header Format" (minimum SNAP is 5 bytes).
        """

        assembler = SnapAssembler()

        self.assertEqual(
            assembler.oui,
            0,
            msg="Default 'oui' must be 0.",
        )
        self.assertEqual(
            assembler.pid,
            0,
            msg="Default 'pid' must be 0.",
        )
        self.assertEqual(
            len(assembler),
            SNAP__HEADER__LEN,
            msg="Default SnapAssembler must be a header-only 5-byte frame.",
        )

    def test__snap__assembler__echo_tracker(self) -> None:
        """
        Ensure the SNAP packet assembler stores the provided
        echo_tracker on its internal Tracker.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        echo_tracker = Tracker(prefix="RX")

        assembler = SnapAssembler(echo_tracker=echo_tracker)

        self.assertEqual(
            assembler.tracker.echo_tracker,
            echo_tracker,
            msg="Assembler tracker must carry the provided echo_tracker.",
        )
