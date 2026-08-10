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
Per-interface 'ip4.*' conf-plane sysctl overrides — the two
ip4 knobs Linux exposes per-interface
('net.ipv4.conf.<iface>.accept_source_route',
'net.ipv4.conf.<iface>.bc_forwarding') migrate to the
'ip4.<ifname>.<field>' shape. Phase 4 of the plan at
'docs/refactor/sysctl_per_interface.md'.

pytcp/tests/integration/protocols/ip4/test__ip4__sysctl_per_interface.py

ver 3.0.10
"""

from typing import override
from unittest import TestCase

from pytcp.stack import sysctl as sysctl_module
from pytcp.stack import sysctl_iface


class TestIp4SysctlPerInterface(TestCase):
    """
    The 'ip4.<ifname>.<field>' per-interface override
    surface for the 2-knob ip4 conf-plane subset.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test mutations do not
        leak.
        """

        sysctl_module.reset_to_defaults()

    def test__ip4__sysctl__accept_source_route_is_interface_scope(self) -> None:
        """
        Ensure 'ip4.accept_source_route' migrates to
        interface-scope storage — Linux's
        'net.ipv4.conf.<iface>.accept_source_route' is
        per-interface.

        Reference: Linux net.ipv4.conf.<iface>.accept_source_route (per-interface).
        """

        knob = sysctl_module._registry.get("ip4.accept_source_route")
        self.assertIsNotNone(
            knob,
            msg="'ip4.accept_source_route' must remain registered.",
        )
        assert knob is not None
        self.assertTrue(
            knob.interface_scope,
            msg="'ip4.accept_source_route' must be interface_scope=True after Phase 4.",
        )

    def test__ip4__sysctl__allow_broadcast_is_interface_scope(self) -> None:
        """
        Ensure 'ip4.allow_broadcast' migrates to interface-
        scope storage — Linux's
        'net.ipv4.conf.<iface>.bc_forwarding' is per-interface.

        Reference: Linux net.ipv4.conf.<iface>.bc_forwarding (per-interface broadcast forwarding).
        """

        knob = sysctl_module._registry.get("ip4.allow_broadcast")
        self.assertIsNotNone(
            knob,
            msg="'ip4.allow_broadcast' must remain registered.",
        )
        assert knob is not None
        self.assertTrue(
            knob.interface_scope,
            msg="'ip4.allow_broadcast' must be interface_scope=True after Phase 4.",
        )

    def test__ip4__sysctl__bare_base_key_write_is_rejected(self) -> None:
        """
        Ensure writing the bare base key 'ip4.accept_source_route'
        is rejected — operators MUST address a specific iface
        or the '"default"' template.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(KeyError) as ctx:
            sysctl_module.set("ip4.accept_source_route", True)
        self.assertIn(
            "ip4.accept_source_route",
            str(ctx.exception),
            msg="The bare-base-key rejection must surface the offending key.",
        )

    def test__ip4__sysctl__per_iface_override_scoped(self) -> None:
        """
        Ensure setting 'ip4.tap_a.accept_source_route = True'
        applies only to tap_a — tap_b inherits the default
        (False) and the 'default' template stays at False.

        Reference: Linux net.ipv4.conf.<iface>.accept_source_route (per-interface scope).
        """

        sysctl_module.set("ip4.tap_a.accept_source_route", True)

        self.assertEqual(
            sysctl_iface.get_for_iface("ip4.accept_source_route", "tap_a"),
            True,
            msg="tap_a's slot must observe the override.",
        )
        self.assertEqual(
            sysctl_iface.get_for_iface("ip4.accept_source_route", "tap_b"),
            False,
            msg="tap_b without an override must observe the default (False).",
        )
        self.assertEqual(
            sysctl_iface.get_for_iface("ip4.accept_source_route", None),
            False,
            msg="The 'default' template must NOT be modified by a per-iface write.",
        )

    def test__ip4__sysctl__allow_broadcast_per_iface_override(self) -> None:
        """
        Ensure 'ip4.tap_a.allow_broadcast = 1' is observable
        through 'sysctl_iface.get_for_iface' while tap_b keeps
        the default (0).

        Reference: Linux net.ipv4.conf.<iface>.bc_forwarding (per-interface broadcast).
        """

        sysctl_module.set("ip4.tap_a.allow_broadcast", 1)
        self.assertEqual(
            sysctl_iface.get_for_iface("ip4.allow_broadcast", "tap_a"),
            1,
            msg="tap_a's slot must observe the broadcast override.",
        )
        self.assertEqual(
            sysctl_iface.get_for_iface("ip4.allow_broadcast", "tap_b"),
            0,
            msg="tap_b without an override must observe the default (0).",
        )

    def test__ip4__sysctl__default_slot_template_update(self) -> None:
        """
        Ensure 'ip4.default.accept_source_route = True'
        changes the template that every interface without a
        per-iface override observes.

        Reference: Linux net.ipv4.conf.default.accept_source_route (template).
        """

        sysctl_module.set("ip4.default.accept_source_route", True)
        self.assertEqual(
            sysctl_iface.get_for_iface("ip4.accept_source_route", None),
            True,
            msg="Default-slot write must change the no-iface read.",
        )
        self.assertEqual(
            sysctl_iface.get_for_iface("ip4.accept_source_route", "any_iface"),
            True,
            msg="An iface without its own slot inherits the default template.",
        )
