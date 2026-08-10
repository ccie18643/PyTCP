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
This module contains unit tests for the per-session keep-alive
state container in
'pytcp/protocols/tcp/state/tcp__state__keepalive.py'.

pytcp/tests/unit/protocols/tcp/state/test__tcp__state__keepalive.py

ver 3.0.10
"""

import inspect
from unittest import TestCase

from pytcp.protocols.tcp.state.tcp__state__keepalive import KeepaliveState


class TestKeepaliveState__Defaults(TestCase):
    """
    Per-field default values pinning the post-construction state
    of 'KeepaliveState'.
    """

    def test__keepalive_state__enabled_default_false(self) -> None:
        """
        Ensure 'enabled' defaults to False so a freshly-
        constructed session does not emit keep-alive probes
        without an explicit application opt-in.

        Reference: RFC 9293 §3.8.4 (keep-alive opt-in).
        """

        self.assertFalse(
            KeepaliveState().enabled,
            msg="KeepaliveState.enabled must default to False.",
        )

    def test__keepalive_state__probes_unacked_default_zero(self) -> None:
        """
        Ensure 'probes_unacked' defaults to 0 so a fresh session
        starts the §4.2.3.6 counter from the canonical baseline.

        Reference: RFC 1122 §4.2.3.6 (unanswered-probe counter).
        """

        self.assertEqual(
            KeepaliveState().probes_unacked,
            0,
            msg="KeepaliveState.probes_unacked must default to 0.",
        )

    def test__keepalive_state__overrides_default_none(self) -> None:
        """
        Ensure the three setsockopt overrides default to None so
        the helper accessors fall back to the supplied canonical
        defaults until an explicit setsockopt opt-in.

        Reference: RFC 1122 §4.2.3.6 (per-session tunables).
        """

        state = KeepaliveState()
        self.assertIsNone(
            state.idle_override,
            msg="idle_override must default to None.",
        )
        self.assertIsNone(
            state.interval_override,
            msg="interval_override must default to None.",
        )
        self.assertIsNone(
            state.max_count_override,
            msg="max_count_override must default to None.",
        )

    def test__keepalive_state__active_default_false(self) -> None:
        """
        Ensure 'active' defaults to False so a freshly-
        constructed session does not believe the keep-alive
        timer is registered. The lazy-arm path flips it True.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            KeepaliveState().active,
            msg="KeepaliveState.active must default to False.",
        )


class TestKeepaliveState__Methods(TestCase):
    """
    Method behaviour for KeepaliveState.
    """

    def test__keepalive_state__reset_for_idle_clears_counter_arms(self) -> None:
        """
        Ensure 'reset_for_idle' clears 'probes_unacked' and flips
        'active' True so the next idle-window arm starts from the
        canonical baseline.

        Reference: RFC 1122 §4.2.3.6 (idle-window reset on activity).
        """

        state = KeepaliveState()
        state.probes_unacked = 5
        state.active = False
        state.reset_for_idle()
        self.assertEqual(
            state.probes_unacked,
            0,
            msg="reset_for_idle must clear probes_unacked.",
        )
        self.assertTrue(
            state.active,
            msg="reset_for_idle must flip active True.",
        )

    def test__keepalive_state__idle_timeout_uses_override(self) -> None:
        """
        Ensure 'idle_timeout' returns the per-session override
        when set, ignoring the supplied default. The accessor is
        the single source of truth at the timer-arm site so the
        override takes effect deterministically.

        Reference: RFC 1122 §4.2.3.6 (idle-window override).
        """

        state = KeepaliveState()
        state.idle_override = 12345
        self.assertEqual(
            state.idle_timeout(default=99999),
            12345,
            msg="idle_timeout must return the override when set.",
        )

    def test__keepalive_state__idle_timeout_falls_back_to_default(self) -> None:
        """
        Ensure 'idle_timeout' returns the supplied default when
        no override is set.

        Reference: RFC 1122 §4.2.3.6 (idle-window default).
        """

        self.assertEqual(
            KeepaliveState().idle_timeout(default=99999),
            99999,
            msg="idle_timeout must fall back to the default.",
        )

    def test__keepalive_state__interval_timeout_dispatches(self) -> None:
        """
        Ensure 'interval_timeout' returns the override when set,
        else the supplied default.

        Reference: RFC 1122 §4.2.3.6 (probe interval).
        """

        state = KeepaliveState()
        self.assertEqual(
            state.interval_timeout(default=500),
            500,
            msg="No override must yield the default.",
        )
        state.interval_override = 250
        self.assertEqual(
            state.interval_timeout(default=500),
            250,
            msg="Override must take precedence over the default.",
        )

    def test__keepalive_state__max_probes_dispatches(self) -> None:
        """
        Ensure 'max_probes' returns the override when set, else
        the supplied default.

        Reference: RFC 1122 §4.2.3.6 (probe-count ceiling).
        """

        state = KeepaliveState()
        self.assertEqual(
            state.max_probes(default=9),
            9,
            msg="No override must yield the default.",
        )
        state.max_count_override = 3
        self.assertEqual(
            state.max_probes(default=9),
            3,
            msg="Override must take precedence over the default.",
        )


class TestKeepaliveState__Slotted(TestCase):
    """
    The slotted-dataclass invariant for KeepaliveState.
    """

    def test__tcp_state__keepalive__is_slotted(self) -> None:
        """
        Ensure KeepaliveState is a slotted dataclass so it grows no per-instance
        __dict__ on the TcpSession state object.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            hasattr(KeepaliveState(), "__dict__"),
            msg="KeepaliveState must be declared with slots=True (no per-instance __dict__).",
        )


class TestKeepaliveState__KeywordOnlySignatures(TestCase):
    """
    Keyword-only enforcement on the KeepaliveState mutator signatures.
    """

    def test__tcp_state__keepalive__methods_are_keyword_only(self) -> None:
        """
        Ensure the KeepaliveState mutators reject positional arguments — their
        public parameters are keyword-only, pinning the call contract.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            inspect.signature(KeepaliveState.idle_timeout).parameters["default"].kind,
            inspect.Parameter.KEYWORD_ONLY,
            msg="KeepaliveState.idle_timeout 'default' must be keyword-only.",
        )
        self.assertIs(
            inspect.signature(KeepaliveState.interval_timeout).parameters["default"].kind,
            inspect.Parameter.KEYWORD_ONLY,
            msg="KeepaliveState.interval_timeout 'default' must be keyword-only.",
        )
        self.assertIs(
            inspect.signature(KeepaliveState.max_probes).parameters["default"].kind,
            inspect.Parameter.KEYWORD_ONLY,
            msg="KeepaliveState.max_probes 'default' must be keyword-only.",
        )
