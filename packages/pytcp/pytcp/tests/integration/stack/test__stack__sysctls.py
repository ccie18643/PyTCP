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
This module contains integration tests for the stack-wide policy
sysctls ('ip4.accept_source_route', 'ip4.frag.flow_timeout_s',
'ip6.frag.flow_timeout_s', 'net.ephemeral_port_range.low',
'net.ephemeral_port_range.high') registered by 'pytcp/stack/__init__.py'.

pytcp/tests/integration/stack/test__stack__sysctls.py

ver 3.0.9
"""

from typing import override

from pytcp import stack
from pytcp.stack import sysctl
from pytcp.tests.lib.network_testcase import NetworkTestCase


class TestStackSysctlDefaults(NetworkTestCase):
    """
    The stack-wide policy-sysctl default-registration tests.
    """

    def test__stack__sysctl__ip4_accept_source_route_default_registered(self) -> None:
        """
        Ensure 'ip4.accept_source_route' registers with the default
        False — the secure default Linux has shipped since the early
        2000s.

        Reference: RFC 791 §3.1 (LSRR / SSRR options).
        """

        self.assertIs(
            sysctl.get("ip4.default.accept_source_route"),
            False,
            msg="ip4.accept_source_route must default to False.",
        )

    def test__stack__sysctl__ip4_frag_flow_timeout_default_registered(self) -> None:
        """
        Ensure 'ip4.frag.flow_timeout_s' registers with the canonical
        5 s reassembly TTL.

        Reference: RFC 815 (IPv4 fragment reassembly time-to-live).
        """

        self.assertEqual(
            sysctl.get("ip4.frag.flow_timeout_s"),
            5,
            msg="ip4.frag.flow_timeout_s must default to 5 seconds.",
        )

    def test__stack__sysctl__ip6_frag_flow_timeout_default_registered(self) -> None:
        """
        Ensure 'ip6.frag.flow_timeout_s' registers with the 5 s
        default PyTCP inherits from Linux (the RFC recommends 60 s
        but Linux ships 5 s and PyTCP matches Linux).

        Reference: RFC 8200 §4.5 (IPv6 fragment reassembly timeout).
        """

        self.assertEqual(
            sysctl.get("ip6.frag.flow_timeout_s"),
            5,
            msg="ip6.frag.flow_timeout_s must default to 5 seconds.",
        )

    def test__stack__sysctl__ephemeral_port_range_low_default_registered(self) -> None:
        """
        Ensure 'net.ephemeral_port_range.low' registers with the
        canonical Linux default 32768.

        Reference: RFC 6056 §3.2 (ephemeral port range).
        """

        self.assertEqual(
            sysctl.get("net.ephemeral_port_range.low"),
            32768,
            msg="net.ephemeral_port_range.low must default to 32768.",
        )

    def test__stack__sysctl__ephemeral_port_range_high_default_registered(self) -> None:
        """
        Ensure 'net.ephemeral_port_range.high' registers with the
        canonical Linux default 61000.

        Reference: RFC 6056 §3.2 (ephemeral port range).
        """

        self.assertEqual(
            sysctl.get("net.ephemeral_port_range.high"),
            61000,
            msg="net.ephemeral_port_range.high must default to 61000.",
        )


class TestStackSysctlOverrides(NetworkTestCase):
    """
    The stack-wide policy-sysctl runtime-override write-through tests.
    """

    def test__stack__sysctl__ip4_accept_source_route_override_updates_attr(self) -> None:
        """
        Ensure overriding 'ip4.default.accept_source_route' writes
        through to the 'IP4__ACCEPT_SOURCE_ROUTE["default"]' slot of
        the per-interface storage dict that the IPv4 RX handler reads
        via 'sysctl_iface.get_for_iface' (Linux per-interface scope).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with sysctl.override("ip4.default.accept_source_route", True):
            self.assertIs(
                stack.IP4__ACCEPT_SOURCE_ROUTE["default"],
                True,
                msg="Override must flip the 'default' slot to True.",
            )

        self.assertIs(
            stack.IP4__ACCEPT_SOURCE_ROUTE["default"],
            False,
            msg="Override exit must restore the registered default.",
        )

    def test__stack__sysctl__ip4_frag_flow_timeout_override_updates_attr(self) -> None:
        """
        Ensure overriding 'ip4.frag.flow_timeout_s' writes through to
        'IP4__FRAG_FLOW_TIMEOUT__S' on the stack module.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with sysctl.override("ip4.frag.flow_timeout_s", 30):
            self.assertEqual(
                stack.IP4__FRAG_FLOW_TIMEOUT__S,
                30,
                msg="Override must write through to IP4__FRAG_FLOW_TIMEOUT__S.",
            )

    def test__stack__sysctl__ephemeral_port_range_low_override_updates_attr(self) -> None:
        """
        Ensure overriding 'net.ephemeral_port_range.low' writes
        through to 'STACK__EPHEMERAL_PORT_RANGE__LOW'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with sysctl.override("net.ephemeral_port_range.low", 40000):
            self.assertEqual(
                stack.STACK__EPHEMERAL_PORT_RANGE__LOW,
                40000,
                msg="Override must write through to STACK__EPHEMERAL_PORT_RANGE__LOW.",
            )


class TestStackSysctlValidators(NetworkTestCase):
    """
    The stack-wide policy-sysctl validator-rejection tests.
    """

    def test__stack__sysctl__ip4_accept_source_route_rejects_non_bool(self) -> None:
        """
        Ensure 'ip4.default.accept_source_route' rejects non-bool
        values — the knob is a clean 0/1 switch and non-bool values
        would muddle the semantics. The validator runs on the
        per-interface set path same as on the 'default' slot.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for bad in (1, 0, "true", None):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    sysctl.set("ip4.default.accept_source_route", bad)

    def test__stack__sysctl__ip4_frag_flow_timeout_rejects_zero(self) -> None:
        """
        Ensure 'ip4.frag.flow_timeout_s' rejects zero — a zero
        timeout would expire every flow on every cleanup pass and
        defeat the reassembly state.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.set("ip4.frag.flow_timeout_s", 0)

    def test__stack__sysctl__ip6_frag_flow_timeout_rejects_negative(self) -> None:
        """
        Ensure 'ip6.frag.flow_timeout_s' rejects a negative value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.set("ip6.frag.flow_timeout_s", -1)

    def test__stack__sysctl__ephemeral_port_range_low_rejects_below_1024(self) -> None:
        """
        Ensure 'net.ephemeral_port_range.low' rejects values below
        1024 — the IANA-registered well-known port range MUST NOT
        overlap the dynamic / ephemeral pool.

        Reference: RFC 6056 §3.2 (ephemeral pool above 1024).
        """

        with self.assertRaises(ValueError):
            sysctl.set("net.ephemeral_port_range.low", 1023)

    def test__stack__sysctl__ephemeral_port_range_high_rejects_above_65535(self) -> None:
        """
        Ensure 'net.ephemeral_port_range.high' rejects values above
        the 16-bit unsigned port-number ceiling.

        Reference: RFC 6056 §3.2 (port numbers are uint16).
        """

        with self.assertRaises(ValueError):
            sysctl.set("net.ephemeral_port_range.high", 65536)

    def test__stack__sysctl__ephemeral_port_range_accepts_inclusive_boundaries(self) -> None:
        """
        Ensure the ephemeral-port-range knobs accept the inclusive
        bounds 1024 (low) and 65535 (high) — the canonical IANA
        dynamic-pool window.

        Reference: RFC 6056 §3.2 (port-number range).
        """

        with sysctl.override("net.ephemeral_port_range.low", 1024):
            with sysctl.override("net.ephemeral_port_range.high", 65535):
                self.assertEqual(stack.STACK__EPHEMERAL_PORT_RANGE__LOW, 1024)
                self.assertEqual(stack.STACK__EPHEMERAL_PORT_RANGE__HIGH, 65535)


class TestStackSysctlCrossKnobConstraints(NetworkTestCase):
    """
    The stack-wide cross-knob finalize-validator tests.
    """

    @override
    def tearDown(self) -> None:
        """
        Reset every sysctl so a cross-knob constraint violated in
        one test does not leak into the next.
        """

        sysctl.reset_to_defaults()
        super().tearDown()

    def test__stack__sysctl__ephemeral_port_range_low_lt_high_pass(self) -> None:
        """
        Ensure 'net.ephemeral_port_range.low < high' passes
        finalize-validation when both knobs are at their defaults
        (32768 < 61000).

        Reference: RFC 6056 §3.2 (range pool requires low < high).
        """

        sysctl.finalize_validators()

    def test__stack__sysctl__ephemeral_port_range_low_ge_high_rejected(self) -> None:
        """
        Ensure 'finalize_validators' rejects a combination where
        'net.ephemeral_port_range.low' is set above
        'net.ephemeral_port_range.high'. A non-positive range
        produces zero ephemeral ports — every bind() falls into the
        no-free-port path.

        Reference: RFC 6056 §3.2 (range pool requires low < high).
        """

        sysctl.set("net.ephemeral_port_range.low", 50000)
        sysctl.set("net.ephemeral_port_range.high", 40000)
        with self.assertRaises(ValueError) as ctx:
            sysctl.finalize_validators()
        self.assertIn(
            "net.ephemeral_port_range",
            str(ctx.exception),
            msg="Cross-knob rejection must surface the offending keyspace.",
        )

    def test__stack__sysctl__ephemeral_port_range_low_eq_high_rejected(self) -> None:
        """
        Ensure low == high is rejected — the range MUST be strictly
        positive (the constructor 'range(low, high)' would be empty
        at low == high).

        Reference: RFC 6056 §3.2 (range pool requires low < high).
        """

        sysctl.set("net.ephemeral_port_range.low", 40000)
        sysctl.set("net.ephemeral_port_range.high", 40000)
        with self.assertRaises(ValueError):
            sysctl.finalize_validators()
