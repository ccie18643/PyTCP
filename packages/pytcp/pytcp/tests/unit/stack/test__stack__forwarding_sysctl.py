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
This module contains tests for the M1 IPv4 / IPv6 forwarding
policy sysctl knobs — the 'ip4.ip_forward' / 'ip6.all.forwarding'
global masters and the 'ip4.forwarding' / 'ip6.forwarding'
per-interface switches that gate the Phase-2 router forwarding
plane.

pytcp/tests/unit/stack/test__stack__forwarding_sysctl.py

ver 3.0.9
"""

from typing import override
from unittest import TestCase

from pytcp.stack import sysctl as sysctl_module
from pytcp.stack import sysctl_iface


class TestStackForwardingSysctl(TestCase):
    """
    The IPv4 / IPv6 forwarding-policy sysctl knobs.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test mutations do not leak
        into unrelated tests run in the same process.
        """

        sysctl_module.reset_to_defaults()

    def test__ip4__ip_forward__registered_flat_default_off(self) -> None:
        """
        Ensure 'ip4.ip_forward' is registered as a flat (global,
        non-interface) knob defaulting to False, so a stack with no
        configuration keeps exact host behaviour.

        Reference: RFC 1812 §5.2.1 (forward-or-deliver decision).
        Reference: Linux net.ipv4.ip_forward (global master).
        """

        knob = sysctl_module._registry.get("ip4.ip_forward")
        self.assertIsNotNone(
            knob,
            msg="'ip4.ip_forward' must be registered.",
        )
        assert knob is not None
        self.assertFalse(
            knob.interface_scope,
            msg="'ip4.ip_forward' must be a flat (global) knob, not interface-scope.",
        )
        self.assertIs(
            sysctl_module.get("ip4.ip_forward"),
            False,
            msg="'ip4.ip_forward' must default to False (host, not router).",
        )

    def test__ip6__all_forwarding__registered_flat_default_off(self) -> None:
        """
        Ensure 'ip6.all.forwarding' is registered as a flat (global)
        knob defaulting to False.

        Reference: RFC 1812 §5.2.1 (forward-or-deliver decision).
        Reference: Linux net.ipv6.conf.all.forwarding (global master).
        """

        knob = sysctl_module._registry.get("ip6.all.forwarding")
        self.assertIsNotNone(
            knob,
            msg="'ip6.all.forwarding' must be registered.",
        )
        assert knob is not None
        self.assertFalse(
            knob.interface_scope,
            msg="'ip6.all.forwarding' must be a flat (global) knob, not interface-scope.",
        )
        self.assertIs(
            sysctl_module.get("ip6.all.forwarding"),
            False,
            msg="'ip6.all.forwarding' must default to False.",
        )

    def test__ip4__forwarding__registered_interface_scope_default_off(self) -> None:
        """
        Ensure 'ip4.forwarding' is registered as a per-interface
        knob whose 'default' slot is False.

        Reference: RFC 1812 §5.2.1 (forward-or-deliver decision).
        Reference: Linux net.ipv4.conf.<iface>.forwarding (per-interface).
        """

        knob = sysctl_module._registry.get("ip4.forwarding")
        self.assertIsNotNone(
            knob,
            msg="'ip4.forwarding' must be registered.",
        )
        assert knob is not None
        self.assertTrue(
            knob.interface_scope,
            msg="'ip4.forwarding' must be interface-scope.",
        )
        self.assertIs(
            sysctl_iface.get_for_iface("ip4.forwarding", "tap7"),
            False,
            msg="An unconfigured interface must observe the 'default' slot (False).",
        )

    def test__ip6__forwarding__registered_interface_scope_default_off(self) -> None:
        """
        Ensure 'ip6.forwarding' is registered as a per-interface
        knob whose 'default' slot is False.

        Reference: RFC 1812 §5.2.1 (forward-or-deliver decision).
        Reference: Linux net.ipv6.conf.<iface>.forwarding (per-interface).
        """

        knob = sysctl_module._registry.get("ip6.forwarding")
        self.assertIsNotNone(
            knob,
            msg="'ip6.forwarding' must be registered.",
        )
        assert knob is not None
        self.assertTrue(
            knob.interface_scope,
            msg="'ip6.forwarding' must be interface-scope.",
        )
        self.assertIs(
            sysctl_iface.get_for_iface("ip6.forwarding", "tap7"),
            False,
            msg="An unconfigured interface must observe the 'default' slot (False).",
        )

    def test__ip4__ip_forward__rejects_non_bool(self) -> None:
        """
        Ensure the 'ip4.ip_forward' validator rejects a non-bool
        value, keeping the knob's 0/1-switch semantics clean.

        Reference: RFC 1812 §5.2.1 (forward-or-deliver decision).
        """

        with self.assertRaises(ValueError):
            sysctl_module.set("ip4.ip_forward", 1)

    def test__ip4__forwarding__per_iface_override_scoped(self) -> None:
        """
        Ensure 'ip4.tap_a.forwarding = True' lands only in tap_a's
        slot: tap_a observes the override while tap_b keeps the
        default.

        Reference: Linux net.ipv4.conf.<iface>.forwarding (per-interface scope).
        """

        sysctl_module.set("ip4.tap_a.forwarding", True)

        self.assertIs(
            sysctl_iface.get_for_iface("ip4.forwarding", "tap_a"),
            True,
            msg="tap_a's slot must observe the override.",
        )
        self.assertIs(
            sysctl_iface.get_for_iface("ip4.forwarding", "tap_b"),
            False,
            msg="tap_b without an override must observe the default (False).",
        )

    def test__ip6__all_forwarding__flat_key_shadows_iface_split(self) -> None:
        """
        Ensure the flat master key 'ip6.all.forwarding' resolves to
        the global knob and does not collide with the interface-scope
        'ip6.forwarding' knob parsed as ifname 'all'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sysctl_module.set("ip6.all.forwarding", True)

        self.assertIs(
            sysctl_module.get("ip6.all.forwarding"),
            True,
            msg="'ip6.all.forwarding' must resolve to the flat master knob.",
        )
        self.assertIs(
            sysctl_iface.get_for_iface("ip6.forwarding", "all"),
            False,
            msg="Writing the master must not leak into the 'ip6.forwarding' 'all' slot.",
        )
