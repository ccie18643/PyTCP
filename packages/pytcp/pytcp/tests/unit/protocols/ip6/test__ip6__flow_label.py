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
This module contains tests for the IPv6 Flow Label generator
('compute_ip6_flow_label') in 'pytcp/protocols/ip6/ip6__flow_label.py'.

pytcp/tests/unit/protocols/ip6/test__ip6__flow_label.py

ver 3.0.9
"""

from unittest import TestCase
from unittest.mock import patch

from net_addr import Ip6Address
from pytcp import stack
from pytcp.protocols.ip6.ip6__flow_label import compute_ip6_flow_label


class TestIp6FlowLabel(TestCase):
    """
    'compute_ip6_flow_label' picks a stable per-(src, dst)
    20-bit value using the stack's IP6__FLOW_SECRET, meeting
    RFC 6437 §3's "same value for packets of a given flow"
    + "approximation to discrete uniform distribution"
    requirements.
    """

    def test__lib__ip6_flow_label__fits_in_20_bits(self) -> None:
        """
        Ensure 'compute_ip6_flow_label' returns a value
        that fits in 20 bits (the IPv6 Flow Label field
        width).

        Reference: RFC 8200 §3 (IPv6 header — Flow Label is 20 bits).
        """

        label = compute_ip6_flow_label(
            src=Ip6Address("2001:db8::1"),
            dst=Ip6Address("2001:db8::2"),
        )

        self.assertGreaterEqual(label, 0, msg="Flow label must be non-negative.")
        self.assertLess(label, 1 << 20, msg="Flow label must fit in 20 bits (max = 0xFFFFF).")

    def test__lib__ip6_flow_label__same_flow_same_label(self) -> None:
        """
        Ensure two calls with the same (src, dst) pair
        return the same label — required by the
        "same value for packets of a given flow" clause.

        Reference: RFC 6437 §3 (Flow Label Specification — stability).
        """

        a = compute_ip6_flow_label(
            src=Ip6Address("2001:db8::1"),
            dst=Ip6Address("2001:db8::2"),
        )
        b = compute_ip6_flow_label(
            src=Ip6Address("2001:db8::1"),
            dst=Ip6Address("2001:db8::2"),
        )

        self.assertEqual(a, b, msg="Same (src, dst) must yield same flow label.")

    def test__lib__ip6_flow_label__different_flows_different_labels(self) -> None:
        """
        Ensure two calls with different destination
        addresses return different labels (probabilistic;
        20-bit space + 16-byte secret makes collision
        statistically negligible for any test fixture).

        Reference: RFC 6437 §3 (approximation to discrete uniform distribution).
        """

        a = compute_ip6_flow_label(
            src=Ip6Address("2001:db8::1"),
            dst=Ip6Address("2001:db8::2"),
        )
        b = compute_ip6_flow_label(
            src=Ip6Address("2001:db8::1"),
            dst=Ip6Address("2001:db8::3"),
        )

        self.assertNotEqual(a, b, msg="Different destinations must yield different flow labels.")

    def test__lib__ip6_flow_label__different_secret_different_label(self) -> None:
        """
        Ensure two PyTCP stack processes with different
        IP6__FLOW_SECRET values pick different flow labels
        for the same (src, dst) pair.

        Reference: RFC 6437 §3 (random-seeded uniform distribution).
        """

        src = Ip6Address("2001:db8::1")
        dst = Ip6Address("2001:db8::2")

        with patch.object(stack, "IP6__FLOW_SECRET", b"\x00" * 16):
            a = compute_ip6_flow_label(src=src, dst=dst)

        with patch.object(stack, "IP6__FLOW_SECRET", b"\xff" * 16):
            b = compute_ip6_flow_label(src=src, dst=dst)

        self.assertNotEqual(a, b, msg="Different IP6__FLOW_SECRET must yield different flow labels.")

    def test__lib__ip6_flow_label__different_src_different_label(self) -> None:
        """
        Ensure flow label depends on the source as well as
        the destination — two different sources to the same
        destination should pick different flow labels.

        Reference: RFC 6437 §3 (flow identity includes src + dst at minimum).
        """

        a = compute_ip6_flow_label(
            src=Ip6Address("2001:db8::1"),
            dst=Ip6Address("2001:db8::2"),
        )
        b = compute_ip6_flow_label(
            src=Ip6Address("2001:db8::3"),
            dst=Ip6Address("2001:db8::2"),
        )

        self.assertNotEqual(a, b, msg="Different sources to the same destination must yield different labels.")
