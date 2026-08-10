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
This module contains tests for the 'IcmpMetadata' dataclass and
'IcmpCategory' enum that carry inbound ICMP-error events from the
ICMPv4 / ICMPv6 RX path into the TCP FSM dispatch.

pytcp/tests/unit/protocols/tcp/test__tcp__icmp_metadata.py

ver 3.0.9
"""

from dataclasses import FrozenInstanceError
from unittest import TestCase

from pytcp.protocols.tcp.tcp__icmp_metadata import (
    IcmpCategory,
    IcmpMetadata,
)


class TestIcmpCategory(TestCase):
    """
    The 'IcmpCategory' enum tests.
    """

    def test__tcp__icmp_metadata__category_members(self) -> None:
        """
        Ensure 'IcmpCategory' exposes exactly the four event kinds the
        TCP FSM dispatch consumes: DEST_UNREACHABLE, TIME_EXCEEDED,
        PARAM_PROBLEM, PMTU. The category drives 'FSM_ICMP_HANDLERS'
        per-state routing; missing or renaming a member would silently
        break the dispatch.

        Reference: RFC 5927 §3 (ICMP-to-TCP error categories).
        Reference: RFC 1191 §6 (PMTU as a separate event class).
        """

        self.assertEqual(
            {member.name for member in IcmpCategory},
            {"DEST_UNREACHABLE", "TIME_EXCEEDED", "PARAM_PROBLEM", "PMTU"},
            msg="IcmpCategory must expose exactly DEST_UNREACHABLE, TIME_EXCEEDED, PARAM_PROBLEM, PMTU.",
        )


class TestIcmpMetadata(TestCase):
    """
    The 'IcmpMetadata' dataclass tests.
    """

    def test__tcp__icmp_metadata__minimal_dest_unreachable(self) -> None:
        """
        Ensure a minimal Dest-Unreachable metadata constructs with the
        v4 Type 3 / Code 3 (Port Unreachable) signature and exposes
        each input back through its eponymous attribute.

        Reference: RFC 792 (ICMPv4 Destination Unreachable).
        Reference: RFC 1122 §4.2.3.9 (TCP MUST react to ICMP).
        """

        metadata = IcmpMetadata(
            category=IcmpCategory.DEST_UNREACHABLE,
            icmp_type=3,
            icmp_code=3,
            ip_version=4,
        )

        self.assertEqual(
            metadata.category,
            IcmpCategory.DEST_UNREACHABLE,
            msg="category must round-trip as IcmpCategory.DEST_UNREACHABLE.",
        )
        self.assertEqual(
            metadata.icmp_type,
            3,
            msg="icmp_type must round-trip as the constructed value.",
        )
        self.assertEqual(
            metadata.icmp_code,
            3,
            msg="icmp_code must round-trip as the constructed value.",
        )
        self.assertEqual(
            metadata.ip_version,
            4,
            msg="ip_version must round-trip as the constructed value.",
        )
        self.assertIsNone(
            metadata.pointer,
            msg="pointer must default to None for non-Param-Problem categories.",
        )
        self.assertIsNone(
            metadata.next_hop_mtu,
            msg="next_hop_mtu must default to None for non-PMTU categories.",
        )

    def test__tcp__icmp_metadata__pmtu_carries_next_hop_mtu(self) -> None:
        """
        Ensure a PMTU metadata accepts the next-hop MTU and surfaces
        it through 'next_hop_mtu'. The FSM uses this value to clamp
        snd_mss; missing it would force a recompute from a stale MTU.

        Reference: RFC 1191 §6 (PMTUD on the host).
        Reference: RFC 8201 §4 (IPv6 PMTUD MTU update rule).
        """

        metadata = IcmpMetadata(
            category=IcmpCategory.PMTU,
            icmp_type=3,
            icmp_code=4,
            next_hop_mtu=1280,
            ip_version=4,
        )

        self.assertEqual(
            metadata.next_hop_mtu,
            1280,
            msg="next_hop_mtu must round-trip the constructed value.",
        )
        self.assertEqual(
            metadata.category,
            IcmpCategory.PMTU,
            msg="category must round-trip as IcmpCategory.PMTU.",
        )

    def test__tcp__icmp_metadata__param_problem_carries_pointer(self) -> None:
        """
        Ensure a Parameter Problem metadata accepts the IPv6 32-bit
        pointer field. ICMPv4 Parameter Problem also carries a pointer
        (1 byte) so the field is shared across versions.

        Reference: RFC 4443 §3.4 (ICMPv6 Parameter Problem pointer).
        Reference: RFC 792 (ICMPv4 Parameter Problem pointer).
        """

        metadata = IcmpMetadata(
            category=IcmpCategory.PARAM_PROBLEM,
            icmp_type=4,
            icmp_code=1,
            pointer=42,
            ip_version=6,
        )

        self.assertEqual(
            metadata.pointer,
            42,
            msg="pointer must round-trip the constructed value.",
        )

    def test__tcp__icmp_metadata__is_frozen(self) -> None:
        """
        Ensure 'IcmpMetadata' is frozen so the FSM dispatch cannot
        mutate the event in-flight — the metadata's lifetime spans
        multiple per-state handlers and lock-protected sections, so
        immutability prevents cross-handler corruption.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        metadata = IcmpMetadata(
            category=IcmpCategory.DEST_UNREACHABLE,
            icmp_type=3,
            icmp_code=3,
            ip_version=4,
        )

        with self.assertRaises(
            FrozenInstanceError,
            msg="IcmpMetadata must be frozen — direct attribute writes must raise.",
        ):
            metadata.icmp_type = 11  # type: ignore[misc]

    def test__tcp__icmp_metadata__is_kw_only(self) -> None:
        """
        Ensure 'IcmpMetadata' rejects positional construction. The
        keyword-only contract makes call-site code self-documenting
        and immune to silent argument-order swaps.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(
            TypeError,
            msg="IcmpMetadata must reject positional arguments (kw_only=True).",
        ):
            IcmpMetadata(IcmpCategory.DEST_UNREACHABLE, 3, 3, ip_version=4)  # type: ignore[call-arg]


class TestIcmpMetadataMutationGoldens(TestCase):
    """
    Exact enum-value and slotted-dataclass goldens closing the
    IcmpCategory codepoint and IcmpMetadata slots mutation survivors.
    """

    def test__tcp__icmp_metadata__category_codepoints_are_exact(self) -> None:
        """
        Ensure the four IcmpCategory codepoints hold their exact
        values so a NumberReplacer edit is caught.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            (
                IcmpCategory.DEST_UNREACHABLE,
                IcmpCategory.TIME_EXCEEDED,
                IcmpCategory.PARAM_PROBLEM,
                IcmpCategory.PMTU,
            ),
            (1, 2, 3, 4),
            msg="IcmpCategory codepoints must be (1, 2, 3, 4).",
        )

    def test__tcp__icmp_metadata__is_slotted(self) -> None:
        """
        Ensure IcmpMetadata is a slotted dataclass (no __dict__) so
        the slots= flag cannot be flipped unnoticed.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        metadata = IcmpMetadata(
            category=IcmpCategory.DEST_UNREACHABLE,
            icmp_type=3,
            icmp_code=3,
            ip_version=4,
        )
        self.assertFalse(
            hasattr(metadata, "__dict__"),
            msg="IcmpMetadata must be slotted (no __dict__).",
        )
