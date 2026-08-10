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
Unit tests for the RFC 3927 §2.1 MAC-seeded link-local
candidate generator at
'pytcp/protocols/ip4/link_local/link_local__rng.py'.

pytcp/tests/unit/protocols/ip4/link_local/test__link_local__rng.py

ver 3.0.9
"""

from unittest import TestCase

from net_addr import Ip4Address, MacAddress
from pytcp.protocols.ip4.link_local.link_local__rng import (
    RANGE_FIRST,
    RANGE_LAST,
    candidate_from_mac,
)


class TestCandidateFromMac(TestCase):
    """
    The MAC-seeded link-local candidate generator tests.
    """

    def test__candidate_from_mac__same_mac_yields_same_candidate(self) -> None:
        """
        Ensure two calls with the same MAC and the same attempt
        produce the same candidate — deterministic per-MAC
        selection so reboots without persistent storage land
        on the same address.

        Reference: RFC 3927 §2.1 (per-host pseudo-random determinism).
        """

        mac = MacAddress("02:00:00:00:00:07")

        first = candidate_from_mac(mac=mac)
        second = candidate_from_mac(mac=mac)

        self.assertEqual(
            first,
            second,
            msg="Two calls with the same MAC + attempt must yield the same address.",
        )

    def test__candidate_from_mac__different_macs_yield_different_candidates(self) -> None:
        """
        Ensure two different MACs produce two different
        candidates — different hosts MUST NOT generate the
        same sequence of numbers per the RFC's "different
        hosts" rule.

        Reference: RFC 3927 §2.1 (different hosts must diverge).
        """

        mac_a = MacAddress("02:00:00:00:00:07")
        mac_b = MacAddress("02:00:00:00:00:08")

        candidate_a = candidate_from_mac(mac=mac_a)
        candidate_b = candidate_from_mac(mac=mac_b)

        self.assertNotEqual(
            candidate_a,
            candidate_b,
            msg="Different MACs must yield different candidates.",
        )

    def test__candidate_from_mac__attempt_counter_rolls_sequence(self) -> None:
        """
        Ensure the 'attempt' counter changes the candidate so
        a conflict-driven retry picks a different address —
        deterministic per-(MAC, attempt) but varying with
        attempt.

        Reference: RFC 3927 §2.1 (different candidates on conflict regen).
        """

        mac = MacAddress("02:00:00:00:00:07")

        first = candidate_from_mac(mac=mac, attempt=0)
        second = candidate_from_mac(mac=mac, attempt=1)

        self.assertNotEqual(
            first,
            second,
            msg="Different attempt counters must yield different candidates.",
        )

    def test__candidate_from_mac__always_in_range(self) -> None:
        """
        Ensure every generated candidate is in the RFC-pinned
        range [169.254.1.0, 169.254.254.255]. The first 256
        and last 256 of 169.254/16 are reserved and MUST NOT
        be selected.

        Reference: RFC 3927 §2.1 (range is 169.254.1.0..169.254.254.255 inclusive).
        """

        # Sweep many distinct MACs and attempts; assert every
        # generated candidate falls in the legal range. 50
        # MACs × 5 attempts = 250 samples.
        for mac_low in range(50):
            mac = MacAddress(f"02:00:00:00:{mac_low // 256:02x}:{mac_low % 256:02x}")
            for attempt in range(5):
                candidate = candidate_from_mac(mac=mac, attempt=attempt)
                self.assertGreaterEqual(
                    int(candidate),
                    int(RANGE_FIRST),
                    msg=f"Candidate {candidate} for MAC={mac} attempt={attempt} must be >= {RANGE_FIRST}.",
                )
                self.assertLessEqual(
                    int(candidate),
                    int(RANGE_LAST),
                    msg=f"Candidate {candidate} for MAC={mac} attempt={attempt} must be <= {RANGE_LAST}.",
                )

    def test__candidate_from_mac__never_uses_reserved_first_256(self) -> None:
        """
        Ensure the reserved first /24 of the link-local
        prefix (169.254.0.0/24) is never selected.

        Reference: RFC 3927 §2.1 (first 256 reserved).
        """

        reserved_first_start = int(Ip4Address("169.254.0.0"))
        reserved_first_end = int(Ip4Address("169.254.0.255"))

        for mac_low in range(50):
            mac = MacAddress(f"02:00:00:00:{mac_low // 256:02x}:{mac_low % 256:02x}")
            for attempt in range(5):
                candidate_int = int(candidate_from_mac(mac=mac, attempt=attempt))
                self.assertFalse(
                    reserved_first_start <= candidate_int <= reserved_first_end,
                    msg=f"Candidate must not fall in reserved 169.254.0.0/24. "
                    f"Got {candidate_int} for MAC={mac} attempt={attempt}.",
                )

    def test__candidate_from_mac__never_uses_reserved_last_256(self) -> None:
        """
        Ensure the reserved last /24 of the link-local prefix
        (169.254.255.0/24) is never selected.

        Reference: RFC 3927 §2.1 (last 256 reserved).
        """

        reserved_last_start = int(Ip4Address("169.254.255.0"))
        reserved_last_end = int(Ip4Address("169.254.255.255"))

        for mac_low in range(50):
            mac = MacAddress(f"02:00:00:00:{mac_low // 256:02x}:{mac_low % 256:02x}")
            for attempt in range(5):
                candidate_int = int(candidate_from_mac(mac=mac, attempt=attempt))
                self.assertFalse(
                    reserved_last_start <= candidate_int <= reserved_last_end,
                    msg=f"Candidate must not fall in reserved 169.254.255.0/24. "
                    f"Got {candidate_int} for MAC={mac} attempt={attempt}.",
                )

    def test__candidate_from_mac__range_constants_match_rfc(self) -> None:
        """
        Ensure the exported range constants match the RFC
        3927 §2.1 boundary values verbatim. Regression net so
        a future micro-optimisation doesn't accidentally
        widen / narrow the candidate space.

        Reference: RFC 3927 §2.1 (range bounds 169.254.1.0 - 169.254.254.255 inclusive).
        """

        self.assertEqual(
            RANGE_FIRST,
            Ip4Address("169.254.1.0"),
            msg="RANGE_FIRST must equal 169.254.1.0 per the RFC.",
        )
        self.assertEqual(
            RANGE_LAST,
            Ip4Address("169.254.254.255"),
            msg="RANGE_LAST must equal 169.254.254.255 per the RFC.",
        )
