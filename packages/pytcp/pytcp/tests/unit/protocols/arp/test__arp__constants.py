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
Unit tests for the ARP runtime configuration constants
('pytcp/protocols/arp/arp__constants.py').

pytcp/tests/unit/protocols/arp/test__arp__constants.py

ver 3.0.10
"""

from typing import override
from unittest import TestCase

from pytcp.protocols.arp.arp__constants import (
    ARP__ANNOUNCE,
    ARP__ANNOUNCE_INTERVAL,
    ARP__ANNOUNCE_NUM,
    ARP__ANNOUNCE_WAIT,
    ARP__DEFEND_INTERVAL,
    ARP__FILTER,
    ARP__PROBE_MAX,
    ARP__PROBE_MIN,
    ARP__PROBE_NUM,
    ARP__PROBE_WAIT,
)
from pytcp.stack import sysctl as sysctl_module


class TestArpConstants(TestCase):
    """
    The ARP runtime-configuration constants tests.
    """

    def test__arp__constants__defend_interval_matches_rfc_5227(self) -> None:
        """
        Ensure 'ARP__DEFEND_INTERVAL' equals 10 seconds — the
        defensive-ARP rate-limit window. Pinning the constant
        catches a regression that would silently weaken (or
        strengthen) the conflict-defense rate-limit.

        Reference: RFC 5227 §1.1 (DEFEND_INTERVAL = 10 seconds).
        """

        self.assertEqual(
            ARP__DEFEND_INTERVAL,
            10,
            msg=f"DEFEND_INTERVAL must equal 10 s. Got: {ARP__DEFEND_INTERVAL}.",
        )

    def test__arp__constants__announce_num_matches_rfc_5227(self) -> None:
        """
        Ensure 'ARP__ANNOUNCE_NUM' equals 2 — Announcements per
        successful DAD claim.

        Reference: RFC 5227 §1.1 (ANNOUNCE_NUM = 2).
        """

        self.assertEqual(
            ARP__ANNOUNCE_NUM,
            2,
            msg=f"ANNOUNCE_NUM must equal 2. Got: {ARP__ANNOUNCE_NUM}.",
        )

    def test__arp__constants__announce_interval_matches_rfc_5227(self) -> None:
        """
        Ensure 'ARP__ANNOUNCE_INTERVAL' equals 2 seconds — the
        spacing between back-to-back Announcements.

        Reference: RFC 5227 §1.1 (ANNOUNCE_INTERVAL = 2 seconds).
        """

        self.assertEqual(
            ARP__ANNOUNCE_INTERVAL,
            2,
            msg=f"ANNOUNCE_INTERVAL must equal 2 s. Got: {ARP__ANNOUNCE_INTERVAL}.",
        )

    def test__arp__constants__announce_wait_matches_rfc_5227(self) -> None:
        """
        Ensure 'ARP__ANNOUNCE_WAIT' equals 2 seconds — the
        post-probe quiet period during which a late conflicting
        ARP can still abort the claim before the first
        Announcement is emitted.

        Reference: RFC 5227 §1.1 (ANNOUNCE_WAIT = 2 seconds).
        """

        self.assertEqual(
            ARP__ANNOUNCE_WAIT,
            2,
            msg=f"ANNOUNCE_WAIT must equal 2 s. Got: {ARP__ANNOUNCE_WAIT}.",
        )

    def test__arp__constants__probe_wait_matches_rfc_5227(self) -> None:
        """
        Ensure 'ARP__PROBE_WAIT' equals 1 second — the upper
        bound of the initial random delay before the first
        ARP Probe.

        Reference: RFC 5227 §1.1 (PROBE_WAIT = 1 second).
        """

        self.assertEqual(
            ARP__PROBE_WAIT,
            1,
            msg=f"PROBE_WAIT must equal 1 s. Got: {ARP__PROBE_WAIT}.",
        )

    def test__arp__constants__probe_num_matches_rfc_5227(self) -> None:
        """
        Ensure 'ARP__PROBE_NUM' equals 3 — number of ARP
        Probes broadcast per candidate during DAD.

        Reference: RFC 5227 §1.1 (PROBE_NUM = 3).
        """

        self.assertEqual(
            ARP__PROBE_NUM,
            3,
            msg=f"PROBE_NUM must equal 3. Got: {ARP__PROBE_NUM}.",
        )

    def test__arp__constants__probe_min_max_window(self) -> None:
        """
        Ensure 'ARP__PROBE_MIN' equals 1 second and
        'ARP__PROBE_MAX' equals 2 seconds, with MIN < MAX so
        the uniform-random spacing produces a non-degenerate
        distribution.

        Reference: RFC 5227 §1.1 (PROBE_MIN = 1 s, PROBE_MAX = 2 s).
        """

        self.assertEqual(
            ARP__PROBE_MIN,
            1,
            msg=f"PROBE_MIN must equal 1 s. Got: {ARP__PROBE_MIN}.",
        )
        self.assertEqual(
            ARP__PROBE_MAX,
            2,
            msg=f"PROBE_MAX must equal 2 s. Got: {ARP__PROBE_MAX}.",
        )
        self.assertLess(
            ARP__PROBE_MIN,
            ARP__PROBE_MAX,
            msg="PROBE_MIN < PROBE_MAX is required by random.uniform.",
        )

    def test__arp__constants__announce_default_matches_linux(self) -> None:
        """
        Ensure the 'arp.announce' template slot defaults to 0
        — Linux's 'arp_announce' default ("use any local
        address, configured on any interface"). The storage
        is per-interface ('dict[str, int]') with a '"default"'
        template; the operator-facing key is
        'arp.default.announce'.

        Reference: Linux net.ipv4.conf.<iface>.arp_announce (mode 0 default).
        """

        self.assertEqual(
            ARP__ANNOUNCE["default"],
            0,
            msg=f"ARP__ANNOUNCE['default'] must equal 0 (mode 0). Got: {ARP__ANNOUNCE['default']}.",
        )

    def test__arp__constants__filter_default_matches_linux(self) -> None:
        """
        Ensure the 'arp.filter' template slot defaults to 0 —
        Linux's 'arp_filter' default (no source-routing
        filter; reply regardless of receiving interface). The
        storage is per-interface ('dict[str, int]') with a
        '"default"' template.

        Reference: Linux net.ipv4.conf.<iface>.arp_filter (mode 0 default).
        """

        self.assertEqual(
            ARP__FILTER["default"],
            0,
            msg=f"ARP__FILTER['default'] must equal 0 (mode 0). Got: {ARP__FILTER['default']}.",
        )


class TestArpPolicySysctlValidators(TestCase):
    """
    The 'arp.announce' / 'arp.filter' / 'arp.ignore' validator
    tests — pin which integer values each policy knob accepts.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so a per-test mutation never
        leaks into a subsequent test's baseline.
        """

        sysctl_module.reset_to_defaults()

    def test__arp__sysctl__announce_accepts_zero_one_two(self) -> None:
        """
        Ensure the 'arp.announce' validator accepts each of
        the Linux-defined modes 0, 1, 2 — the source-IP
        selection alternatives PyTCP supports today.

        Reference: Linux net.ipv4.conf.<iface>.arp_announce (modes 0/1/2).
        """

        for mode in (0, 1, 2):
            sysctl_module.set("arp.default.announce", mode)
            self.assertEqual(
                sysctl_module.get("arp.default.announce"),
                mode,
                msg=f"arp.default.announce must accept mode {mode}.",
            )

    def test__arp__sysctl__announce_rejects_out_of_range(self) -> None:
        """
        Ensure the 'arp.announce' validator rejects integers
        outside {0, 1, 2} with a descriptive 'ValueError'.

        Reference: Linux net.ipv4.conf.<iface>.arp_announce (no mode 3+).
        """

        for bad in (-1, 3, 99):
            with self.assertRaises(ValueError) as ctx:
                sysctl_module.set("arp.default.announce", bad)
            self.assertIn(
                "arp.announce",
                str(ctx.exception),
                msg=(f"Rejection message must surface the offending key for " f"value {bad!r}."),
            )

    def test__arp__sysctl__filter_accepts_zero_one(self) -> None:
        """
        Ensure the 'arp.filter' validator accepts the boolean
        modes 0 and 1.

        Reference: Linux net.ipv4.conf.<iface>.arp_filter (modes 0/1).
        """

        for mode in (0, 1):
            sysctl_module.set("arp.default.filter", mode)
            self.assertEqual(
                sysctl_module.get("arp.default.filter"),
                mode,
                msg=f"arp.default.filter must accept mode {mode}.",
            )

    def test__arp__sysctl__filter_rejects_out_of_range(self) -> None:
        """
        Ensure the 'arp.filter' validator rejects values
        outside {0, 1} with a descriptive 'ValueError'.

        Reference: Linux net.ipv4.conf.<iface>.arp_filter (boolean 0/1 only).
        """

        for bad in (-1, 2, 99):
            with self.assertRaises(ValueError) as ctx:
                sysctl_module.set("arp.default.filter", bad)
            self.assertIn(
                "arp.filter",
                str(ctx.exception),
                msg=f"Rejection must surface the offending key for value {bad!r}.",
            )

    def test__arp__sysctl__ignore_accepts_mode_eight(self) -> None:
        """
        Ensure the 'arp.ignore' validator now accepts mode 8 —
        the kill-switch ("never reply") that did not require
        address-scope infrastructure.

        Reference: Linux net.ipv4.conf.<iface>.arp_ignore (mode 8 kill-switch).
        """

        sysctl_module.set("arp.default.ignore", 8)
        self.assertEqual(
            sysctl_module.get("arp.default.ignore"),
            8,
            msg="arp.default.ignore must accept mode 8 (kill-switch).",
        )

    def test__arp__sysctl__ignore_rejects_modes_three_through_seven(self) -> None:
        """
        Ensure the 'arp.ignore' validator still rejects modes
        3-7. Mode 3 needs an address-scope concept PyTCP does
        not have today; modes 4-7 are Linux-reserved unused
        slots.

        Reference: Linux net.ipv4.conf.<iface>.arp_ignore (mode 3 needs scope; 4-7 reserved).
        """

        for bad in (3, 4, 5, 6, 7):
            with self.assertRaises(ValueError) as ctx:
                sysctl_module.set("arp.default.ignore", bad)
            self.assertIn(
                "arp.ignore",
                str(ctx.exception),
                msg=f"Rejection must surface the offending key for mode {bad!r}.",
            )
