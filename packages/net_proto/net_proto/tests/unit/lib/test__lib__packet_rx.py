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
This module contains tests for the NetProto PacketRx class.

net_proto/tests/unit/lib/test__lib__packet_rx.py

ver 3.0.10
"""

import itertools
from typing import Any, override
from unittest import TestCase

from net_proto.lib.packet_rx import PacketRx
from net_proto.lib.tracker import Tracker
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Construct PacketRx from bytes.",
            "_frame": b"\x01\x02\x03\x04",
            "_results": {"__len__": 4, "bytes": b"\x01\x02\x03\x04"},
        },
        {
            "_description": "Construct PacketRx from bytearray.",
            "_frame": bytearray(b"\xff\xee\xdd\xcc\xbb"),
            "_results": {"__len__": 5, "bytes": b"\xff\xee\xdd\xcc\xbb"},
        },
        {
            "_description": "Construct PacketRx from memoryview.",
            "_frame": memoryview(b"\xaa" * 10),
            "_results": {"__len__": 10, "bytes": b"\xaa" * 10},
        },
        {
            "_description": "Construct PacketRx from an empty bytes object.",
            "_frame": b"",
            "_results": {"__len__": 0, "bytes": b""},
        },
        {
            "_description": "Construct PacketRx from a single byte.",
            "_frame": b"\x7f",
            "_results": {"__len__": 1, "bytes": b"\x7f"},
        },
        {
            "_description": "Construct PacketRx from a MTU-sized buffer.",
            "_frame": b"\xa5" * 1500,
            "_results": {"__len__": 1500, "bytes": b"\xa5" * 1500},
        },
    ]
)
class TestNetProtoLibPacketRx(TestCase):
    """
    The NetProto PacketRx construction tests.
    """

    _description: str
    _frame: Any
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Reset the shared Tracker counters so tracker assertions are stable.
        """

        self._saved_rx_counter = Tracker._rx_counter
        self._saved_tx_counter = Tracker._tx_counter
        Tracker._rx_counter = itertools.count()
        Tracker._tx_counter = itertools.count()
        self._packet = PacketRx(self._frame)

    @override
    def tearDown(self) -> None:
        """
        Restore the shared Tracker counters after each test.
        """

        Tracker._rx_counter = self._saved_rx_counter
        Tracker._tx_counter = self._saved_tx_counter

    def test__net_proto__lib__packet_rx__frame_is_memoryview(self) -> None:
        """
        Ensure 'frame' is always normalized to a memoryview regardless of input.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsInstance(
            self._packet.frame,
            memoryview,
            msg=f"{self._description}: frame must be a memoryview.",
        )

    def test__net_proto__lib__packet_rx__frame_contents_preserved(self) -> None:
        """
        Ensure 'frame' preserves the original bytes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            bytes(self._packet.frame),
            self._results["bytes"],
            msg=f"{self._description}: frame contents must match the input bytes.",
        )

    def test__net_proto__lib__packet_rx__len(self) -> None:
        """
        Ensure 'len(PacketRx)' matches the length of the raw frame.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            len(self._packet),
            self._results["__len__"],
            msg=f"{self._description}: PacketRx length must equal the frame length.",
        )

    def test__net_proto__lib__packet_rx__parse_failed_default(self) -> None:
        """
        Ensure 'parse_failed' starts empty on a newly constructed PacketRx.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._packet.parse_failed,
            "",
            msg=f"{self._description}: parse_failed must be empty by default.",
        )

    def test__net_proto__lib__packet_rx__tracker_is_rx(self) -> None:
        """
        Ensure the PacketRx tracker is an RX-prefixed Tracker instance.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsInstance(
            self._packet.tracker,
            Tracker,
            msg=f"{self._description}: tracker must be a Tracker instance.",
        )
        self.assertIn(
            "RX",
            str(self._packet.tracker),
            msg=f"{self._description}: tracker must be tagged as RX.",
        )


class TestNetProtoLibPacketRxBehavior(TestCase):
    """
    The NetProto PacketRx behavior tests not tied to a parameter matrix.
    """

    @override
    def setUp(self) -> None:
        self._saved_rx_counter = Tracker._rx_counter
        self._saved_tx_counter = Tracker._tx_counter
        Tracker._rx_counter = itertools.count()
        Tracker._tx_counter = itertools.count()

    @override
    def tearDown(self) -> None:
        Tracker._rx_counter = self._saved_rx_counter
        Tracker._tx_counter = self._saved_tx_counter

    def test__net_proto__lib__packet_rx__parse_failed_is_writable(self) -> None:
        """
        Ensure 'parse_failed' can be assigned a descriptive reason.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        packet = PacketRx(b"\x00\x01\x02")
        packet.parse_failed = "ethernet__integrity"

        self.assertEqual(packet.parse_failed, "ethernet__integrity")

    def test__net_proto__lib__packet_rx__each_instance_has_fresh_tracker(
        self,
    ) -> None:
        """
        Ensure back-to-back PacketRx instances allocate unique tracker serials.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        first = PacketRx(b"\x01")
        second = PacketRx(b"\x02")

        self.assertNotEqual(
            str(first.tracker),
            str(second.tracker),
            msg="Each PacketRx must carry a distinct tracker serial.",
        )

    def test__net_proto__lib__packet_rx__frame_is_view_not_copy(self) -> None:
        """
        Ensure the memoryview on 'frame' references the underlying buffer of a
        bytearray input (mutation is observable).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        source = bytearray(b"\x00\x00\x00\x00")
        packet = PacketRx(source)
        source[0] = 0xFF

        self.assertEqual(
            bytes(packet.frame),
            b"\xff\x00\x00\x00",
            msg="PacketRx.frame must view the original bytearray buffer, not a copy.",
        )

    def test__net_proto__lib__packet_rx__frame_requires_positional_argument(
        self,
    ) -> None:
        """
        Ensure the constructor only accepts the frame positionally.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError):
            PacketRx(frame=b"\x00")  # type: ignore[call-arg]
