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
Operation unit tests for the IEEE 802.2 LLC U-frame
assembler.

net_proto/tests/unit/protocols/llc/test__llc__assembler__operation.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import (
    LLC__HEADER__LEN,
    LlcAssembler,
    LlcControl,
    LlcHeader,
    LlcSap,
    Tracker,
)
from net_proto.lib.buffer import Buffer


@parameterized_class(
    [
        {
            "_description": "LLC frame carrying an IEEE 802.1D STP BPDU (DSAP=SSAP=0x42, UI).",
            "_kwargs": {
                "llc__dsap": LlcSap.LAYER_MGMT,
                "llc__ssap": LlcSap.LAYER_MGMT,
                "llc__control": LlcControl.UI,
                "llc__payload": b"BPDU",
            },
            "_results": {
                "__len__": 7,
                "__str__": "LLC dsap STP ssap STP ctrl UI, len 4",
                "__repr__": (
                    "LlcAssembler(header=LlcHeader(dsap=<LlcSap.LAYER_MGMT: 66>, "
                    "ssap=<LlcSap.LAYER_MGMT: 66>, control=<LlcControl.UI: 3>), "
                    "payload=b'BPDU')"
                ),
                # LLC wire frame (7 bytes = 3-byte header + 4-byte payload):
                #   Byte 0    : 0x42 -> DSAP=LlcSap.LAYER_MGMT (STP)
                #   Byte 1    : 0x42 -> SSAP=LlcSap.LAYER_MGMT (STP)
                #   Byte 2    : 0x03 -> Control=LlcControl.UI
                #   Bytes 3-6 : b"BPDU" (4-byte BPDU stub payload)
                "__bytes__": b"\x42\x42\x03BPDU",
                "dsap": LlcSap.LAYER_MGMT,
                "ssap": LlcSap.LAYER_MGMT,
                "control": LlcControl.UI,
                "header": LlcHeader(
                    dsap=LlcSap.LAYER_MGMT,
                    ssap=LlcSap.LAYER_MGMT,
                    control=LlcControl.UI,
                ),
                "payload": b"BPDU",
            },
        },
        {
            "_description": "LLC frame carrying an RFC 1042 SNAP header (DSAP=SSAP=0xAA, UI).",
            "_kwargs": {
                "llc__dsap": LlcSap.SNAP,
                "llc__ssap": LlcSap.SNAP,
                "llc__control": LlcControl.UI,
                # 5-byte SNAP header (OUI=0x000000 + PID=0x0800 IPv4) carried as opaque payload.
                "llc__payload": b"\x00\x00\x00\x08\x00",
            },
            "_results": {
                "__len__": 8,
                "__str__": "LLC dsap SNAP ssap SNAP ctrl UI, len 5",
                "__repr__": (
                    "LlcAssembler(header=LlcHeader(dsap=<LlcSap.SNAP: 170>, "
                    "ssap=<LlcSap.SNAP: 170>, control=<LlcControl.UI: 3>), "
                    "payload=b'\\x00\\x00\\x00\\x08\\x00')"
                ),
                # LLC wire frame (8 bytes = 3-byte header + 5-byte SNAP payload):
                #   Byte 0    : 0xaa -> DSAP=LlcSap.SNAP
                #   Byte 1    : 0xaa -> SSAP=LlcSap.SNAP
                #   Byte 2    : 0x03 -> Control=LlcControl.UI
                #   Bytes 3-5 : 0x000000 -> SNAP OUI=ENCAP_ETHERTYPE
                #   Bytes 6-7 : 0x0800 -> SNAP PID=EtherType IPv4
                "__bytes__": b"\xaa\xaa\x03\x00\x00\x00\x08\x00",
                "dsap": LlcSap.SNAP,
                "ssap": LlcSap.SNAP,
                "control": LlcControl.UI,
                "header": LlcHeader(
                    dsap=LlcSap.SNAP,
                    ssap=LlcSap.SNAP,
                    control=LlcControl.UI,
                ),
                "payload": b"\x00\x00\x00\x08\x00",
            },
        },
        {
            "_description": "LLC frame carrying Novell-IPX-over-802.2 (DSAP=SSAP=0xE0, UI).",
            "_kwargs": {
                "llc__dsap": LlcSap.NOVELL_IPX,
                "llc__ssap": LlcSap.NOVELL_IPX,
                "llc__control": LlcControl.UI,
                "llc__payload": b"\xff" * 8,
            },
            "_results": {
                "__len__": 11,
                "__str__": "LLC dsap Novell-IPX ssap Novell-IPX ctrl UI, len 8",
                "__repr__": (
                    "LlcAssembler(header=LlcHeader(dsap=<LlcSap.NOVELL_IPX: 224>, "
                    "ssap=<LlcSap.NOVELL_IPX: 224>, control=<LlcControl.UI: 3>), "
                    "payload=b'\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff')"
                ),
                # LLC wire frame (11 bytes = 3-byte header + 8-byte IPX stub):
                #   Byte 0    : 0xe0 -> DSAP=LlcSap.NOVELL_IPX
                #   Byte 1    : 0xe0 -> SSAP=LlcSap.NOVELL_IPX
                #   Byte 2    : 0x03 -> Control=LlcControl.UI
                #   Bytes 3-10: 0xff * 8 (Novell IPX stub payload)
                "__bytes__": b"\xe0\xe0\x03" + b"\xff" * 8,
                "dsap": LlcSap.NOVELL_IPX,
                "ssap": LlcSap.NOVELL_IPX,
                "control": LlcControl.UI,
                "header": LlcHeader(
                    dsap=LlcSap.NOVELL_IPX,
                    ssap=LlcSap.NOVELL_IPX,
                    control=LlcControl.UI,
                ),
                "payload": b"\xff" * 8,
            },
        },
    ]
)
class TestLlcAssemblerOperation(TestCase):
    """
    The LLC packet assembler operation tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the LLC packet assembler from the parametrized kwargs.
        """

        self._llc__assembler = LlcAssembler(**self._kwargs)

    def test__llc__assembler__len(self) -> None:
        """
        Ensure '__len__()' returns header + payload bytes.

        Reference: IEEE 802.2 §3 (3-byte U-frame header + variable payload).
        """

        self.assertEqual(
            len(self._llc__assembler),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__llc__assembler__str(self) -> None:
        """
        Ensure '__str__()' returns the canonical log string.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._llc__assembler),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__llc__assembler__repr(self) -> None:
        """
        Ensure '__repr__()' returns the constructor-callable
        representation string.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            repr(self._llc__assembler),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__llc__assembler__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the expected wire-frame bytes.

        Reference: IEEE 802.2 §3 (LLC wire format DSAP + SSAP + Control).
        """

        self.assertEqual(
            bytes(self._llc__assembler),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__llc__assembler__dsap(self) -> None:
        """
        Ensure the 'dsap' property returns the provided
        Destination Service Access Point.

        Reference: IEEE 802.2 §3.2 (DSAP field).
        """

        self.assertIs(
            self._llc__assembler.dsap,
            self._results["dsap"],
            msg=f"Unexpected 'dsap' for case: {self._description}",
        )

    def test__llc__assembler__ssap(self) -> None:
        """
        Ensure the 'ssap' property returns the provided Source
        Service Access Point.

        Reference: IEEE 802.2 §3.3 (SSAP field).
        """

        self.assertIs(
            self._llc__assembler.ssap,
            self._results["ssap"],
            msg=f"Unexpected 'ssap' for case: {self._description}",
        )

    def test__llc__assembler__control(self) -> None:
        """
        Ensure the 'control' property returns the provided
        U-frame Control value.

        Reference: IEEE 802.2 §3.4 (Control field, U-frame form).
        """

        self.assertIs(
            self._llc__assembler.control,
            self._results["control"],
            msg=f"Unexpected 'control' for case: {self._description}",
        )

    def test__llc__assembler__header(self) -> None:
        """
        Ensure the 'header' property returns the computed
        LlcHeader dataclass.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._llc__assembler.header,
            self._results["header"],
            msg=f"Unexpected 'header' for case: {self._description}",
        )

    def test__llc__assembler__payload(self) -> None:
        """
        Ensure the 'payload' property returns the provided
        payload bytes verbatim.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._llc__assembler.payload,
            self._results["payload"],
            msg=f"Unexpected 'payload' for case: {self._description}",
        )

    def test__llc__assembler__assemble(self) -> None:
        """
        Ensure 'assemble()' appends header and payload in
        wire order so the concatenation matches '__bytes__'.

        Reference: IEEE 802.2 §3 (LLC header precedes payload on the wire).
        """

        buffers: list[Buffer] = []

        self._llc__assembler.assemble(buffers)

        self.assertEqual(
            b"".join(buffers),
            self._results["__bytes__"],
            msg=f"Unexpected concatenated buffers for case: {self._description}",
        )

    def test__llc__assembler__assemble__buffer_layout(self) -> None:
        """
        Ensure 'assemble()' appends exactly two buffers —
        the 3-byte LLC header followed by the payload — so
        downstream code can locate them by index.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        buffers: list[Buffer] = []

        self._llc__assembler.assemble(buffers)

        self.assertEqual(
            len(buffers),
            2,
            msg="LlcAssembler.assemble must append header + payload.",
        )
        self.assertEqual(
            len(buffers[0]),
            LLC__HEADER__LEN,
            msg="LlcAssembler.assemble must append the 3-byte fixed header first.",
        )
        self.assertEqual(
            len(buffers[1]),
            len(self._results["payload"]),
            msg="LlcAssembler.assemble must append the payload buffer second.",
        )


class TestLlcAssemblerMisc(TestCase):
    """
    The LLC packet assembler miscellaneous functions tests.
    """

    def test__llc__assembler__defaults(self) -> None:
        """
        Ensure constructing 'LlcAssembler' with no kwargs
        yields a minimum-valid frame: NULL SAPs, UI control,
        empty payload, length equal to the 3-byte header.

        Reference: IEEE 802.2 §3 (minimum U-frame is 3 bytes, header-only).
        """

        assembler = LlcAssembler()

        self.assertIs(
            assembler.dsap,
            LlcSap.NULL,
            msg="Default 'dsap' must be LlcSap.NULL.",
        )
        self.assertIs(
            assembler.ssap,
            LlcSap.NULL,
            msg="Default 'ssap' must be LlcSap.NULL.",
        )
        self.assertIs(
            assembler.control,
            LlcControl.UI,
            msg="Default 'control' must be LlcControl.UI.",
        )
        self.assertEqual(
            len(assembler),
            LLC__HEADER__LEN,
            msg="Default LlcAssembler must be a header-only 3-byte frame.",
        )

    def test__llc__assembler__echo_tracker(self) -> None:
        """
        Ensure the LLC packet assembler stores the provided
        echo_tracker on its internal Tracker.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        echo_tracker = Tracker(prefix="RX")

        assembler = LlcAssembler(echo_tracker=echo_tracker)

        self.assertEqual(
            assembler.tracker.echo_tracker,
            echo_tracker,
            msg="Assembler tracker must carry the provided echo_tracker.",
        )
