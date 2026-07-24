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
Unit tests for the IPv4 runtime configuration constants
('pytcp/protocols/ip4/ip4__constants.py').

pytcp/tests/unit/protocols/ip4/test__ip4__constants.py

ver 3.0.9
"""

from typing import override
from unittest import TestCase

from pytcp.protocols.ip4 import ip4__constants as ip4_const
from pytcp.stack import sysctl as sysctl_module


class TestIp4Constants(TestCase):
    """
    The IPv4 runtime-configuration constants tests.
    """

    def test__ip4__constants__default_ttl_matches_rfc_1122(self) -> None:
        """
        Ensure 'IP4__DEFAULT_TTL' equals 64 — the host-default
        TTL for outbound unicast datagrams. Pinning the constant
        catches a regression that would silently shorten the
        per-packet reach the host advertises.

        Reference: RFC 1122 §3.2.1.7 (TTL host default; baseline value).
        """

        self.assertEqual(
            ip4_const.IP4__DEFAULT_TTL,
            64,
            msg=f"IP4__DEFAULT_TTL must equal 64. Got: {ip4_const.IP4__DEFAULT_TTL}.",
        )


class TestIp4DefaultTtlSysctl(TestCase):
    """
    The 'ip4.default_ttl' sysctl registration and validator
    tests.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so a per-test mutation never
        leaks into a subsequent test's baseline.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__ip4__sysctl__default_ttl_is_registered(self) -> None:
        """
        Ensure the 'ip4.default_ttl' key is present in the
        sysctl registry so operator overrides via 'stack.init(
        sysctls={"ip4.default_ttl": N})' / 'pytcp.stack.sysctl
        ["ip4.default_ttl"] = N' resolve to the backing module
        attribute.

        Reference: RFC 1122 §3.2.1.7 (MUST be configurable).
        """

        self.assertIn(
            "ip4.default_ttl",
            sysctl_module.list_keys(),
            msg="ip4.default_ttl must be a registered sysctl knob.",
        )

    def test__ip4__sysctl__default_ttl_get_returns_module_attr(self) -> None:
        """
        Ensure 'sysctl.get("ip4.default_ttl")' returns the live
        value of 'ip4__constants.IP4__DEFAULT_TTL' so reads
        through the registry match qualified-module access.

        Reference: RFC 1122 §3.2.1.7 (MUST be configurable).
        """

        self.assertEqual(
            sysctl_module.get("ip4.default_ttl"),
            ip4_const.IP4__DEFAULT_TTL,
            msg="sysctl.get must mirror ip4__constants.IP4__DEFAULT_TTL.",
        )

    def test__ip4__sysctl__default_ttl_set_updates_module_attr(self) -> None:
        """
        Ensure 'sysctl.set("ip4.default_ttl", N)' updates the
        backing module attribute so qualified-module reads see
        the new value on the next access.

        Reference: RFC 1122 §3.2.1.7 (MUST be configurable).
        """

        sysctl_module.set("ip4.default_ttl", 32)

        self.assertEqual(
            ip4_const.IP4__DEFAULT_TTL,
            32,
            msg="set('ip4.default_ttl', 32) must update IP4__DEFAULT_TTL.",
        )

    def test__ip4__sysctl__default_ttl_accepts_boundary_values(self) -> None:
        """
        Ensure the validator accepts the documented integer
        TTL range — the smallest non-zero value (1), the
        registered default (64), and the largest uint8
        representable on the wire (255).

        Reference: RFC 791 §3.1 (TTL is an 8-bit field, range 1..255).
        Reference: RFC 1122 §3.2.1.7 (MUST NOT send TTL=0).
        """

        for value in (1, 64, 255):
            sysctl_module.set("ip4.default_ttl", value)
            self.assertEqual(
                sysctl_module.get("ip4.default_ttl"),
                value,
                msg=f"ip4.default_ttl must accept value {value}.",
            )

    def test__ip4__sysctl__default_ttl_rejects_zero(self) -> None:
        """
        Ensure the validator rejects TTL=0 — sending a datagram
        with TTL=0 is forbidden on the wire, so the operator
        must not be able to set the host default to a value
        that would violate the spec on every emitted packet.

        Reference: RFC 1122 §3.2.1.7 (MUST NOT send TTL=0).
        """

        with self.assertRaises(ValueError) as ctx:
            sysctl_module.set("ip4.default_ttl", 0)

        self.assertIn(
            "ip4.default_ttl",
            str(ctx.exception),
            msg="Rejection must surface the offending key.",
        )

    def test__ip4__sysctl__default_ttl_rejects_overflow(self) -> None:
        """
        Ensure the validator rejects values that overflow the
        8-bit wire field — TTL is a uint8, so anything above
        255 cannot be encoded.

        Reference: RFC 791 §3.1 (TTL is an 8-bit field).
        """

        for bad in (256, 1024, 1_000_000):
            with self.assertRaises(ValueError) as ctx:
                sysctl_module.set("ip4.default_ttl", bad)
            self.assertIn(
                "ip4.default_ttl",
                str(ctx.exception),
                msg=f"Rejection must surface the offending key for {bad!r}.",
            )

    def test__ip4__sysctl__default_ttl_rejects_non_int(self) -> None:
        """
        Ensure the validator rejects non-integer values — bool
        is rejected too because 'isinstance(True, int)' is True
        in Python and would silently slip through.

        Reference: RFC 1122 §3.2.1.7 (configurable TTL is integer 1..255).
        """

        for bad in (True, False, 1.5, "64", None, [64]):
            with self.assertRaises(ValueError) as ctx:
                sysctl_module.set("ip4.default_ttl", bad)
            self.assertIn(
                "ip4.default_ttl",
                str(ctx.exception),
                msg=f"Rejection must surface the offending key for {bad!r}.",
            )


class TestIp4AllowBroadcastSysctl(TestCase):
    """
    The 'ip4.allow_broadcast' sysctl registration and validator
    tests.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so a per-test mutation never
        leaks into a subsequent test's baseline.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__ip4__sysctl__allow_broadcast_default_is_zero(self) -> None:
        """
        Ensure 'IP4__ALLOW_BROADCAST' defaults to 0 — outbound
        broadcast emission is disallowed unless the operator
        explicitly opts in, matching the Linux per-socket
        'SO_BROADCAST' default-off discipline.

        Reference: Linux net.ipv4.conf.<iface>.bc_forwarding (default 0).
        """

        self.assertEqual(
            ip4_const.IP4__ALLOW_BROADCAST["default"],
            0,
            msg=(
                f"IP4__ALLOW_BROADCAST['default'] must equal 0. " f"Got: {ip4_const.IP4__ALLOW_BROADCAST['default']}."
            ),
        )

    def test__ip4__sysctl__allow_broadcast_is_registered(self) -> None:
        """
        Ensure the 'ip4.allow_broadcast' key is present in the
        sysctl registry so operator overrides resolve through
        the documented sysctl API.

        Reference: RFC 919 §1 (broadcast scope policy).
        """

        self.assertIn(
            "ip4.allow_broadcast",
            sysctl_module.list_keys(),
            msg="ip4.allow_broadcast must be a registered sysctl knob.",
        )

    def test__ip4__sysctl__allow_broadcast_accepts_zero_one(self) -> None:
        """
        Ensure the validator accepts the two documented modes
        — 0 (deny broadcast emission) and 1 (allow broadcast
        emission).

        Reference: Linux net.ipv4.conf.<iface>.bc_forwarding (0/1 only).
        """

        for value in (0, 1):
            sysctl_module.set("ip4.default.allow_broadcast", value)
            self.assertEqual(
                sysctl_module.get("ip4.default.allow_broadcast"),
                value,
                msg=f"ip4.allow_broadcast must accept value {value}.",
            )

    def test__ip4__sysctl__allow_broadcast_rejects_out_of_range(self) -> None:
        """
        Ensure the validator rejects values outside {0, 1} so a
        typo cannot silently set the gate to a half-open state.

        Reference: Linux net.ipv4.conf.<iface>.bc_forwarding (boolean 0/1).
        """

        for bad in (-1, 2, 99, True, False, "1", 1.0, None):
            with self.assertRaises(ValueError) as ctx:
                sysctl_module.set("ip4.default.allow_broadcast", bad)
            self.assertIn(
                "ip4.allow_broadcast",
                str(ctx.exception),
                msg=f"Rejection must surface the offending key for {bad!r}.",
            )
