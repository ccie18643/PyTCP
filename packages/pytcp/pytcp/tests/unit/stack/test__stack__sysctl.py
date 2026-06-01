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
This module contains tests for the 'pytcp.stack.sysctl'
runtime-tunable knob registry — Phase 0 of the framework
plan at 'docs/refactor/sysctl_framework.md'.

pytcp/tests/unit/stack/test__stack__sysctl.py

ver 3.0.8
"""

import sys
import types
from unittest import TestCase

from pytcp.stack import sysctl


def _build_carrier_module(name: str, **attrs: object) -> types.ModuleType:
    """
    Build a throwaway module to act as the storage backing for
    test sysctl registrations. Installed into 'sys.modules' so
    'sysctl.set' can resolve it by name.
    """

    module = types.ModuleType(name)
    for attr, value in attrs.items():
        setattr(module, attr, value)
    sys.modules[name] = module
    return module


class _SysctlFixtureBase(TestCase):
    """
    Shared fixture: snapshot the registry's internal state on
    setUp and restore it on tearDown so each test starts and
    ends with a clean slate. The framework allows lazy
    re-registration in production (constants modules call
    'register' at import time, once), but tests need to
    re-register fresh keys per case.
    """

    def setUp(self) -> None:
        """
        Snapshot the registry membership and module-level
        attributes that any test might mutate.
        """

        self._snapshot_registry = dict(sysctl._registry)
        self._snapshot_finalize = list(sysctl._finalize_validators)
        self._carriers: list[str] = []

    def tearDown(self) -> None:
        """
        Restore the registry membership / finalize-validator list
        and remove any throwaway carrier modules.
        """

        sysctl._registry.clear()
        sysctl._registry.update(self._snapshot_registry)
        sysctl._finalize_validators.clear()
        sysctl._finalize_validators.extend(self._snapshot_finalize)
        for name in self._carriers:
            sys.modules.pop(name, None)

    def _register_int(
        self,
        *,
        key: str,
        carrier_name: str,
        attr: str,
        default: int,
        description: str = "",
    ) -> types.ModuleType:
        """
        Convenience helper — install a throwaway carrier module
        with the supplied attribute and register the knob on it.
        """

        module = _build_carrier_module(carrier_name, **{attr: default})
        self._carriers.append(carrier_name)
        sysctl.register(
            key=key,
            module_name=carrier_name,
            attr=attr,
            default=default,
            validator=sysctl.is_positive_int(key),
            description=description,
        )
        return module


class TestSysctlRegisterAndGet(_SysctlFixtureBase):
    """
    The 'register' / 'get' happy-path tests.
    """

    def test__lib__sysctl__register_then_get_returns_default(self) -> None:
        """
        Ensure a freshly-registered knob's 'get' returns the
        registered default value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._register_int(
            key="test.foo.max_age",
            carrier_name="pytcp_test_carrier_foo",
            attr="FOO__MAX_AGE",
            default=42,
        )
        self.assertEqual(
            sysctl.get("test.foo.max_age"),
            42,
            msg="sysctl.get must return the registered default for a freshly-registered key.",
        )

    def test__lib__sysctl__get_unknown_key_raises(self) -> None:
        """
        Ensure 'get' on an unregistered key raises 'KeyError'
        with the offending key in the message — the public
        contract for "no such sysctl."

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(KeyError) as ctx:
            sysctl.get("test.unknown.key")
        self.assertIn(
            "test.unknown.key",
            str(ctx.exception),
            msg="The unknown-key error message must surface the offending key.",
        )


class TestSysctlSet(_SysctlFixtureBase):
    """
    The 'set' write-through and validator tests.
    """

    def test__lib__sysctl__set_updates_module_attribute(self) -> None:
        """
        Ensure 'sysctl.set(key, value)' writes through to the
        backing module attribute. Code reading via qualified
        access (e.g. 'arp__constants.ARP__CACHE__ENTRY_MAX_AGE')
        must observe the new value on the next read — this is
        the entire point of the registry.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        carrier = self._register_int(
            key="test.foo.max_age",
            carrier_name="pytcp_test_carrier_set",
            attr="FOO__MAX_AGE",
            default=10,
        )
        sysctl.set("test.foo.max_age", 99)
        self.assertEqual(
            carrier.FOO__MAX_AGE,
            99,
            msg=(
                "sysctl.set must write the new value to the backing module "
                "attribute; runtime readers using qualified access depend "
                "on this for the override to take effect."
            ),
        )
        self.assertEqual(
            sysctl.get("test.foo.max_age"),
            99,
            msg="sysctl.get after set must return the new value.",
        )

    def test__lib__sysctl__set_unknown_key_raises(self) -> None:
        """
        Ensure 'sysctl.set' on an unregistered key raises
        'KeyError' with the offending key in the message.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(KeyError) as ctx:
            sysctl.set("test.unknown.key", 1)
        self.assertIn(
            "test.unknown.key",
            str(ctx.exception),
            msg="The unknown-key error message must surface the offending key.",
        )

    def test__lib__sysctl__set_validator_rejects_invalid_value(self) -> None:
        """
        Ensure a per-knob validator that rejects the value
        propagates a 'ValueError' carrying both the offending
        key and the offending value. The public contract is
        "the caller can recover the key from the error."

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._register_int(
            key="test.foo.max_age",
            carrier_name="pytcp_test_carrier_invalid",
            attr="FOO__MAX_AGE",
            default=10,
        )
        with self.assertRaises(ValueError) as ctx:
            sysctl.set("test.foo.max_age", -1)
        self.assertIn(
            "test.foo.max_age",
            str(ctx.exception),
            msg="The validator-rejection error must surface the offending key.",
        )

    def test__lib__sysctl__set_validator_failure_does_not_mutate(self) -> None:
        """
        Ensure a 'set' that fails validation leaves the backing
        module attribute unchanged — the validator runs BEFORE
        the write so a rejected value never leaks through.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        carrier = self._register_int(
            key="test.foo.max_age",
            carrier_name="pytcp_test_carrier_atomic",
            attr="FOO__MAX_AGE",
            default=10,
        )
        try:
            sysctl.set("test.foo.max_age", -1)
        except ValueError:
            pass
        self.assertEqual(
            carrier.FOO__MAX_AGE,
            10,
            msg="A rejected sysctl.set must NOT mutate the backing attribute.",
        )


class TestSysctlListAndDescribe(_SysctlFixtureBase):
    """
    The 'list_keys' / 'describe' / 'snapshot' tests.
    """

    def test__lib__sysctl__list_keys_enumerates_registered(self) -> None:
        """
        Ensure 'list_keys' returns every key that has been
        registered, in registration order. Drives the
        'pytcp.stack.sysctl' discovery story — operators use
        this to enumerate available knobs.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._register_int(key="test.alpha", carrier_name="pytcp_test_carrier_alpha", attr="A", default=1)
        self._register_int(key="test.beta", carrier_name="pytcp_test_carrier_beta", attr="B", default=2)

        keys = sysctl.list_keys()
        self.assertIn(
            "test.alpha",
            keys,
            msg="list_keys must include every registered key (alpha missing).",
        )
        self.assertIn(
            "test.beta",
            keys,
            msg="list_keys must include every registered key (beta missing).",
        )

    def test__lib__sysctl__describe_returns_registered_description(self) -> None:
        """
        Ensure 'describe' returns the description string the
        knob was registered with. Drives the operator-facing
        'sysctl --help'-style introspection.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._register_int(
            key="test.foo",
            carrier_name="pytcp_test_carrier_describe",
            attr="FOO",
            default=1,
            description="The foo timeout in seconds.",
        )
        self.assertEqual(
            sysctl.describe("test.foo"),
            "The foo timeout in seconds.",
            msg="describe must return the description string passed to _register.",
        )

    def test__lib__sysctl__snapshot_returns_current_values(self) -> None:
        """
        Ensure 'snapshot' returns a dict mapping every
        registered key to its current live value — useful for
        debug dumps and for restoring state from a snapshot
        produced earlier.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._register_int(key="test.foo", carrier_name="pytcp_test_carrier_snap_foo", attr="FOO", default=1)
        self._register_int(key="test.bar", carrier_name="pytcp_test_carrier_snap_bar", attr="BAR", default=2)
        sysctl.set("test.foo", 11)

        snap = sysctl.snapshot()
        self.assertEqual(
            snap.get("test.foo"),
            11,
            msg="snapshot must reflect the current live value (post-set).",
        )
        self.assertEqual(
            snap.get("test.bar"),
            2,
            msg="snapshot must reflect the unmutated live value where set was not called.",
        )


class TestSysctlReset(_SysctlFixtureBase):
    """
    The 'reset_to_defaults' tests.
    """

    def test__lib__sysctl__reset_restores_defaults(self) -> None:
        """
        Ensure 'reset_to_defaults' restores every knob's
        backing attribute to the value passed at registration
        time. Used by 'stack.stop()' and test teardown to
        prevent per-run mutation from leaking into the next
        run's defaults.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        carrier = self._register_int(
            key="test.foo",
            carrier_name="pytcp_test_carrier_reset",
            attr="FOO",
            default=10,
        )
        sysctl.set("test.foo", 99)
        sysctl.reset_to_defaults()
        self.assertEqual(
            carrier.FOO,
            10,
            msg="reset_to_defaults must restore the registered default on the backing attribute.",
        )
        self.assertEqual(
            sysctl.get("test.foo"),
            10,
            msg="get after reset must return the registered default.",
        )


class TestSysctlOverrideContextManager(_SysctlFixtureBase):
    """
    The 'override' context-manager tests.
    """

    def test__lib__sysctl__override_round_trips(self) -> None:
        """
        Ensure the 'override' context manager mutates on enter
        and restores the prior value on exit — the test-only
        ergonomic equivalent of a save/set/finally/set chain.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        carrier = self._register_int(
            key="test.foo",
            carrier_name="pytcp_test_carrier_override",
            attr="FOO",
            default=10,
        )
        with sysctl.override("test.foo", 99):
            self.assertEqual(
                carrier.FOO,
                99,
                msg="override must mutate on enter to the supplied value.",
            )
        self.assertEqual(
            carrier.FOO,
            10,
            msg="override must restore the prior value on exit.",
        )

    def test__lib__sysctl__override_restores_on_exception(self) -> None:
        """
        Ensure 'override' restores the prior value even when
        the wrapped block raises — the contract operators rely
        on for safe transient overrides.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        carrier = self._register_int(
            key="test.foo",
            carrier_name="pytcp_test_carrier_override_exc",
            attr="FOO",
            default=10,
        )
        with self.assertRaises(RuntimeError):
            with sysctl.override("test.foo", 99):
                raise RuntimeError("transient failure inside override block")
        self.assertEqual(
            carrier.FOO,
            10,
            msg="override must restore on __exit__ even when the wrapped block raises.",
        )


class TestSysctlCrossKnobValidation(_SysctlFixtureBase):
    """
    The cross-knob (finalize-validator) tests.
    """

    def test__lib__sysctl__finalize_validator_runs_after_init(self) -> None:
        """
        Ensure a registered cross-knob constraint runs when
        'finalize_validators' is called and rejects an invalid
        combination — the path 'stack.init()' uses to enforce
        invariants like 'refresh < max'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._register_int(key="test.max", carrier_name="pytcp_test_carrier_finalize_max", attr="MAX", default=100)
        self._register_int(
            key="test.refresh",
            carrier_name="pytcp_test_carrier_finalize_refresh",
            attr="REFRESH",
            default=10,
        )

        def refresh_lt_max() -> None:
            if sysctl.get("test.refresh") >= sysctl.get("test.max"):
                raise ValueError("test.refresh must be strictly less than test.max")

        sysctl.register_finalize_validator(refresh_lt_max)

        sysctl.set("test.refresh", 200)  # individual set passes per-knob check
        with self.assertRaises(ValueError) as ctx:
            sysctl.finalize_validators()
        self.assertIn(
            "test.refresh",
            str(ctx.exception),
            msg="The finalize-validator error must surface the offending key.",
        )

    def test__lib__sysctl__finalize_validators_pass_when_all_consistent(self) -> None:
        """
        Ensure 'finalize_validators' does NOT raise when every
        registered cross-knob constraint passes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._register_int(key="test.max", carrier_name="pytcp_test_carrier_pass_max", attr="MAX", default=100)
        self._register_int(
            key="test.refresh",
            carrier_name="pytcp_test_carrier_pass_refresh",
            attr="REFRESH",
            default=10,
        )

        def refresh_lt_max() -> None:
            if sysctl.get("test.refresh") >= sysctl.get("test.max"):
                raise ValueError("test.refresh must be < test.max")

        sysctl.register_finalize_validator(refresh_lt_max)
        # Both at default → 10 < 100 → passes.
        sysctl.finalize_validators()


class TestSysctlDictLikeAccess(_SysctlFixtureBase):
    """
    The dict-like '__getitem__' / '__setitem__' / '__contains__'
    tests on the public 'pytcp.stack.sysctl.sysctl' singleton.
    """

    def test__lib__sysctl__dict_like_setitem_writes_through(self) -> None:
        """
        Ensure 'sysctl[key] = value' on the public registry
        singleton routes to 'sysctl.set' — the dict-like sugar
        used by 'pytcp.stack.sysctl["arp.cache.max_age"] = 60'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        carrier = self._register_int(
            key="test.foo",
            carrier_name="pytcp_test_carrier_setitem",
            attr="FOO",
            default=10,
        )
        sysctl.sysctl["test.foo"] = 77
        self.assertEqual(
            carrier.FOO,
            77,
            msg="Dict-like setitem must write through to the backing attribute.",
        )

    def test__lib__sysctl__dict_like_getitem_returns_value(self) -> None:
        """
        Ensure 'sysctl[key]' on the registry singleton returns
        the current live value — operator-facing readback.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._register_int(
            key="test.foo",
            carrier_name="pytcp_test_carrier_getitem",
            attr="FOO",
            default=10,
        )
        self.assertEqual(
            sysctl.sysctl["test.foo"],
            10,
            msg="Dict-like getitem must return the current live value.",
        )

    def test__lib__sysctl__dict_like_contains_returns_membership(self) -> None:
        """
        Ensure '"key" in sysctl' reports registered membership
        — supports 'if "arp.cache.max_age" in sysctl' guards
        before set/get.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._register_int(
            key="test.foo",
            carrier_name="pytcp_test_carrier_contains",
            attr="FOO",
            default=10,
        )
        self.assertIn(
            "test.foo",
            sysctl.sysctl,
            msg="Dict-like __contains__ must report registered keys as members.",
        )
        self.assertNotIn(
            "test.unknown",
            sysctl.sysctl,
            msg="Dict-like __contains__ must NOT report unregistered keys.",
        )


class TestSysctlValidatorHelpers(_SysctlFixtureBase):
    """
    The 'is_positive_int' validator-helper tests.
    """

    def test__lib__sysctl__is_positive_int_accepts_positive(self) -> None:
        """
        Ensure 'is_positive_int' accepts (does not raise on)
        any positive integer.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sysctl.is_positive_int("test.foo")(1)
        sysctl.is_positive_int("test.foo")(99999)

    def test__lib__sysctl__is_positive_int_rejects_zero(self) -> None:
        """
        Ensure 'is_positive_int' rejects zero — a zero timeout
        / count is almost always wrong (would make the loop
        spin or no-op).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.is_positive_int("test.foo")(0)

    def test__lib__sysctl__is_positive_int_rejects_negative(self) -> None:
        """
        Ensure 'is_positive_int' rejects negative integers.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.is_positive_int("test.foo")(-5)

    def test__lib__sysctl__is_positive_int_rejects_non_int(self) -> None:
        """
        Ensure 'is_positive_int' rejects non-int types
        (booleans excepted — Python treats bool as int but the
        validator must reject 'True' / 'False' as numerically
        meaningless for a count).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.is_positive_int("test.foo")("5")
        with self.assertRaises(ValueError):
            sysctl.is_positive_int("test.foo")(1.5)
        with self.assertRaises(ValueError):
            sysctl.is_positive_int("test.foo")(True)

    def test__lib__sysctl__is_int_in_range_accepts_in_range(self) -> None:
        """
        Ensure 'is_int_in_range' accepts (does not raise on) the
        inclusive bounds and an interior value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        validator = sysctl.is_int_in_range("test.foo", low=0, high=3)
        validator(0)
        validator(2)
        validator(3)

    def test__lib__sysctl__is_int_in_range_rejects_out_of_range_and_non_int(self) -> None:
        """
        Ensure 'is_int_in_range' rejects values below / above the
        range, booleans, and non-int types.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        validator = sysctl.is_int_in_range("test.foo", low=0, high=3)
        for bad in (-1, 4, True, 1.5, "2"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    validator(bad)
