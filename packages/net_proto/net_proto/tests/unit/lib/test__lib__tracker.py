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
This module contains tests for the NetProto package Tracker class.

net_proto/tests/unit/lib/test__lib__tracker.py

ver 3.0.9
"""

import itertools
import time
from typing import override
from unittest import TestCase
from unittest.mock import patch

from net_proto.lib.tracker import Tracker


class _TrackerTestBase(TestCase):
    """
    Base class resetting the Tracker class-level counters around each test.
    """

    @override
    def setUp(self) -> None:
        """
        Reset the shared RX/TX serial counters before each test.
        """

        self._saved_rx_counter = Tracker._rx_counter
        self._saved_tx_counter = Tracker._tx_counter
        Tracker._rx_counter = itertools.count()
        Tracker._tx_counter = itertools.count()

    @override
    def tearDown(self) -> None:
        """
        Restore the shared RX/TX serial counters after each test.
        """

        Tracker._rx_counter = self._saved_rx_counter
        Tracker._tx_counter = self._saved_tx_counter


class TestNetProtoLibTrackerRxTx(_TrackerTestBase):
    """
    The NetProto Tracker RX/TX serial allocation tests.
    """

    def test__net_proto__lib__tracker__rx__serial_format(self) -> None:
        """
        Ensure the RX tracker emits a '<lg>RXXXXX</>' formatted serial.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        tracker = Tracker(prefix="RX")

        self.assertEqual(
            str(tracker),
            "<lg>RX0000</>",
            msg="RX tracker must format the first serial as '<lg>RX0000</>'.",
        )

    def test__net_proto__lib__tracker__tx__serial_format(self) -> None:
        """
        Ensure the TX tracker emits a '<lr>TXXXXX</>' formatted serial.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        tracker = Tracker(prefix="TX")

        self.assertEqual(
            str(tracker),
            "<lr>TX0000</>",
            msg="TX tracker must format the first serial as '<lr>TX0000</>'.",
        )

    def test__net_proto__lib__tracker__rx__counter_increments(self) -> None:
        """
        Ensure each RX tracker allocation increments the shared RX counter.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        first = Tracker(prefix="RX")
        second = Tracker(prefix="RX")
        third = Tracker(prefix="RX")

        self.assertEqual(str(first), "<lg>RX0000</>")
        self.assertEqual(str(second), "<lg>RX0001</>")
        self.assertEqual(str(third), "<lg>RX0002</>")

    def test__net_proto__lib__tracker__tx__counter_increments(self) -> None:
        """
        Ensure each TX tracker allocation increments the shared TX counter.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        first = Tracker(prefix="TX")
        second = Tracker(prefix="TX")

        self.assertEqual(str(first), "<lr>TX0000</>")
        self.assertEqual(str(second), "<lr>TX0001</>")

    def test__net_proto__lib__tracker__rx_and_tx_counters_are_independent(
        self,
    ) -> None:
        """
        Ensure the RX and TX counters advance independently of each other.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        Tracker(prefix="RX")
        Tracker(prefix="TX")
        second_rx = Tracker(prefix="RX")
        second_tx = Tracker(prefix="TX")

        self.assertEqual(
            str(second_rx),
            "<lg>RX0001</>",
            msg="RX counter must advance independently of TX.",
        )
        self.assertEqual(
            str(second_tx),
            "<lr>TX0001</>",
            msg="TX counter must advance independently of RX.",
        )

    def test__net_proto__lib__tracker__rx__counter_wraps_at_0xffff(self) -> None:
        """
        Ensure the RX counter wraps back to zero after hitting 0xFFFF.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        Tracker._rx_counter = itertools.count(0xFFFF)
        last = Tracker(prefix="RX")
        wrapped = Tracker(prefix="RX")
        after_wrap = Tracker(prefix="RX")

        self.assertEqual(str(last), "<lg>RXFFFF</>")
        self.assertEqual(str(wrapped), "<lg>RX0000</>")
        self.assertEqual(str(after_wrap), "<lg>RX0001</>")

    def test__net_proto__lib__tracker__tx__counter_wraps_at_0xffff(self) -> None:
        """
        Ensure the TX counter wraps back to zero after hitting 0xFFFF.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        Tracker._tx_counter = itertools.count(0xFFFF)
        last = Tracker(prefix="TX")
        wrapped = Tracker(prefix="TX")
        after_wrap = Tracker(prefix="TX")

        self.assertEqual(str(last), "<lr>TXFFFF</>")
        self.assertEqual(str(wrapped), "<lr>TX0000</>")
        self.assertEqual(str(after_wrap), "<lr>TX0001</>")

    def test__net_proto__lib__tracker__invalid_prefix_raises(self) -> None:
        """
        Ensure a prefix other than 'RX'/'TX' triggers the constructor assertion.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            Tracker(prefix="XX")


class TestNetProtoLibTrackerExplicitSerial(_TrackerTestBase):
    """
    The NetProto Tracker explicit-serial short-circuit tests.
    """

    def test__net_proto__lib__tracker__explicit_serial_uses_value(self) -> None:
        """
        Ensure passing 'serial=' short-circuits formatting and returns early.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        tracker = Tracker(prefix="RX", serial="CUSTOM-SERIAL")

        self.assertEqual(str(tracker), "CUSTOM-SERIAL")

    def test__net_proto__lib__tracker__explicit_serial_does_not_touch_counters(
        self,
    ) -> None:
        """
        Ensure constructing with an explicit serial does not advance the counters.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        Tracker(prefix="RX", serial="FORCE-RX")
        Tracker(prefix="TX", serial="FORCE-TX")

        next_rx = Tracker(prefix="RX")
        next_tx = Tracker(prefix="TX")

        self.assertEqual(
            str(next_rx),
            "<lg>RX0000</>",
            msg="Explicit-serial constructor must not advance the RX counter.",
        )
        self.assertEqual(
            str(next_tx),
            "<lr>TX0000</>",
            msg="Explicit-serial constructor must not advance the TX counter.",
        )

    def test__net_proto__lib__tracker__explicit_serial_skips_prefix_validation(
        self,
    ) -> None:
        """
        Ensure an explicit serial bypasses the 'prefix in {RX, TX}' assertion.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        tracker = Tracker(prefix="INVALID", serial="BYPASS")

        self.assertEqual(str(tracker), "BYPASS")

    def test__net_proto__lib__tracker__explicit_serial_leaves_timestamp_unset(
        self,
    ) -> None:
        """
        Ensure constructing with a serial leaves the '_timestamp' attribute unset.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        tracker = Tracker(prefix="RX", serial="NO-TIMESTAMP")

        with self.assertRaises(AttributeError):
            _ = tracker.timestamp


class TestNetProtoLibTrackerEchoTracker(_TrackerTestBase):
    """
    The NetProto Tracker echo-tracker chaining tests.
    """

    def test__net_proto__lib__tracker__echo_tracker_property_default_none(
        self,
    ) -> None:
        """
        Ensure 'echo_tracker' is None when the tracker stands alone.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsNone(Tracker(prefix="RX").echo_tracker)

    def test__net_proto__lib__tracker__echo_tracker_property_returns_instance(
        self,
    ) -> None:
        """
        Ensure 'echo_tracker' returns the instance supplied at construction.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        rx = Tracker(prefix="RX")
        tx = Tracker(prefix="TX", echo_tracker=rx)

        self.assertIs(tx.echo_tracker, rx)

    def test__net_proto__lib__tracker__str_with_echo_tracker(self) -> None:
        """
        Ensure '__str__()' appends the echo tracker's string form.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        rx = Tracker(prefix="RX")
        tx = Tracker(prefix="TX", echo_tracker=rx)

        self.assertEqual(str(tx), "<lr>TX0000</> <lg>RX0000</>")

    def test__net_proto__lib__tracker__repr_without_echo_tracker(self) -> None:
        """
        Ensure '__repr__()' omits the echo tracker when it is absent.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        tracker = Tracker(prefix="RX")

        self.assertEqual(
            repr(tracker),
            "Tracker(serial='<lg>RX0000</>')",
        )

    def test__net_proto__lib__tracker__repr_with_echo_tracker(self) -> None:
        """
        Ensure '__repr__()' includes the echo tracker's string form.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        rx = Tracker(prefix="RX")
        tx = Tracker(prefix="TX", echo_tracker=rx)

        self.assertEqual(
            repr(tx),
            "Tracker(serial='<lr>TX0000</>', echo_tracker=<lg>RX0000</>)",
        )

    def test__net_proto__lib__tracker__nested_echo_tracker_str(self) -> None:
        """
        Ensure '__str__()' walks a chain of echo trackers.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        rx = Tracker(prefix="RX")
        intermediate = Tracker(prefix="TX", echo_tracker=rx)
        outer = Tracker(prefix="TX", echo_tracker=intermediate)

        self.assertEqual(
            str(outer),
            "<lr>TX0001</> <lr>TX0000</> <lg>RX0000</>",
        )


class TestNetProtoLibTrackerTimestampAndLatency(_TrackerTestBase):
    """
    The NetProto Tracker timestamp and latency tests.
    """

    def test__net_proto__lib__tracker__rx__timestamp_uses_time_time(self) -> None:
        """
        Ensure the RX constructor records 'time.time()' as the timestamp.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("net_proto.lib.tracker.time.time", return_value=12345.6789):
            tracker = Tracker(prefix="RX")

        self.assertEqual(tracker.timestamp, 12345.6789)

    def test__net_proto__lib__tracker__tx__timestamp_uses_time_time(self) -> None:
        """
        Ensure the TX constructor records 'time.time()' as the timestamp.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("net_proto.lib.tracker.time.time", return_value=42.0):
            tracker = Tracker(prefix="TX")

        self.assertEqual(tracker.timestamp, 42.0)

    def test__net_proto__lib__tracker__latency_empty_without_echo_tracker(
        self,
    ) -> None:
        """
        Ensure 'latency' returns an empty string when no echo tracker is set.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        tracker = Tracker(prefix="RX")

        self.assertEqual(tracker.latency, "")

    def test__net_proto__lib__tracker__latency_with_echo_tracker(self) -> None:
        """
        Ensure 'latency' reports the millisecond delta against the echo tracker.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("net_proto.lib.tracker.time.time", return_value=100.000):
            rx = Tracker(prefix="RX")

        with patch("net_proto.lib.tracker.time.time", return_value=100.250):
            tx = Tracker(prefix="TX", echo_tracker=rx)

            self.assertEqual(tx.latency, " 250.000ms")

    def test__net_proto__lib__tracker__latency_uses_current_clock_not_tx_time(
        self,
    ) -> None:
        """
        Ensure 'latency' measures against the current time each call, not the
        TX tracker's own timestamp.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("net_proto.lib.tracker.time.time", return_value=10.000):
            rx = Tracker(prefix="RX")
            tx = Tracker(prefix="TX", echo_tracker=rx)

        with patch("net_proto.lib.tracker.time.time", return_value=10.500):
            self.assertEqual(tx.latency, " 500.000ms")

    def test__net_proto__lib__tracker__timestamp_is_float(self) -> None:
        """
        Ensure a freshly constructed tracker exposes a float timestamp.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        before = time.time()
        tracker = Tracker(prefix="RX")
        after = time.time()

        self.assertIsInstance(tracker.timestamp, float)
        self.assertGreaterEqual(tracker.timestamp, before)
        self.assertLessEqual(tracker.timestamp, after)
