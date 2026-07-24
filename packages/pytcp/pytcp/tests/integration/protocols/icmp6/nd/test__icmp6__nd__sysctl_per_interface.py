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


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
Per-interface 'icmp6.*' sysctl overrides — the 22 ND knobs
that mirror Linux 'net.ipv6.conf.<iface>.*' migrate as a
single batch (no half-migrated namespace). Phase 3 of the
plan at 'docs/refactor/sysctl_per_interface.md'.

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__sysctl_per_interface.py

ver 3.0.9
"""

from typing import override

from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.nd_testcase import NdTestCase

# Every key the Phase-3 batch migrates. Pinned here so a
# registry-meta-test catches a regression that flips a knob
# back to flat — the namespace becomes unusable if even one
# knob fails to migrate, so the assertion runs over the full
# set rather than a sample.
_PHASE_3_KEYS: tuple[str, ...] = (
    "icmp6.accept_redirects",
    "icmp6.gratuitous_na_count",
    "icmp6.dad_transmits",
    "icmp6.retrans_timer_ms",
    "icmp6.accept_ra_defrtr",
    "icmp6.accept_ra_pinfo",
    "icmp6.accept_ra_min_hop_limit",
    "icmp6.rtr_solicitation_interval_ms",
    "icmp6.rtr_solicitation_max_rt_ms",
    "icmp6.max_rtr_solicitations",
    "icmp6.enhanced_dad",
    "icmp6.regen_advance_s",
    "icmp6.temp_addr_sweep_interval_s",
    "icmp6.idgen_retries",
    "icmp6.accept_dad",
    "icmp6.max_rtr_solicitation_delay_ms",
    "icmp6.use_tempaddr",
    "icmp6.temp_valid_lifetime_s",
    "icmp6.temp_preferred_lifetime_s",
    "icmp6.max_desync_factor_s",
    "icmp6.optimistic_dad",
    "icmp6.use_rfc7217",
)


class TestIcmp6NdSysctlPerInterface(NdTestCase):
    """
    The 'icmp6.<ifname>.<field>' per-interface override
    surface for the 22-knob ND namespace.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test mutations do not
        leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__sysctl__all_22_knobs_registered_interface_scope(self) -> None:
        """
        Ensure every one of the 22 'icmp6.*' knobs migrates as
        interface-scope in a single batch — the namespace is
        unusable if half-migrated, so the registry-meta check
        runs over the full set rather than a sample.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for key in _PHASE_3_KEYS:
            knob = sysctl_module._registry.get(key)
            self.assertIsNotNone(
                knob,
                msg=f"icmp6 knob {key!r} must remain registered.",
            )
            assert knob is not None  # narrow for mypy
            self.assertTrue(
                knob.interface_scope,
                msg=f"icmp6 knob {key!r} must be interface_scope=True after Phase 3.",
            )

    def test__icmp6__sysctl__bare_base_key_write_is_rejected(self) -> None:
        """
        Ensure writing the bare base key
        'icmp6.accept_redirects' (no '<ifname>' segment) is
        rejected after the interface-scope migration —
        operators MUST address a specific interface or the
        '"default"' template. Pins the §4.4 contract for one
        representative knob (the registry's parse rule
        applies uniformly to every interface-scope key).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(KeyError) as ctx:
            sysctl_module.set("icmp6.accept_redirects", 0)
        self.assertIn(
            "icmp6.accept_redirects",
            str(ctx.exception),
            msg="The bare-base-key rejection must surface the offending key.",
        )

    def test__icmp6__sysctl__default_slot_is_template_for_unnamed_iface(self) -> None:
        """
        Ensure writing 'icmp6.default.accept_redirects = 0'
        applies to every interface that has no per-iface
        override — Linux 'net.ipv6.conf.default.<knob>'
        parity. The test-harness handler has no
        '_interface_name' plumbed so it inherits from the
        'default' slot exactly.

        Reference: Linux net.ipv6.conf.default.accept_redirects (template for new ifaces).
        """

        # Operator writes the template — runtime read by the
        # PacketHandler must observe 0 (drop).
        sysctl_module.set("icmp6.default.accept_redirects", 0)
        from pytcp.stack import sysctl_iface

        self.assertEqual(
            sysctl_iface.get_for_iface(
                "icmp6.accept_redirects",
                self._packet_handler._interface_name,
            ),
            0,
            msg=(
                "Setting the 'default' slot must change the runtime read for an "
                "interface that has no per-iface override (the harness handler)."
            ),
        )

    def test__icmp6__sysctl__per_iface_override_does_not_leak_to_default(self) -> None:
        """
        Ensure setting 'icmp6.tap_a.use_tempaddr = 2' affects
        only the 'tap_a' slot — the 'default' template and
        any other named iface continue to observe the
        registered default.

        Reference: Linux net.ipv6.conf.<iface>.use_tempaddr (per-interface scope).
        """

        sysctl_module.set("icmp6.tap_a.use_tempaddr", 2)
        from pytcp.stack import sysctl_iface

        self.assertEqual(
            sysctl_iface.get_for_iface("icmp6.use_tempaddr", "tap_a"),
            2,
            msg="tap_a's slot must observe the per-iface override.",
        )
        self.assertEqual(
            sysctl_iface.get_for_iface("icmp6.use_tempaddr", "tap_b"),
            0,
            msg="tap_b without an override must observe the registered default (0).",
        )
        self.assertEqual(
            sysctl_iface.get_for_iface("icmp6.use_tempaddr", None),
            0,
            msg="The 'default' template must NOT be modified by a per-iface write.",
        )
