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
This module contains tests for the interface-scope extension
of 'pytcp.stack.sysctl' — Phase 0 of the per-interface
migration plan at 'docs/refactor/sysctl_per_interface.md'.
Covers the new 'interface_scope=True' '_Knob' shape, the
'<namespace>.<ifname>.<field>' key parsing rule, the
'"default"' slot fallback, and the
'pytcp.stack.sysctl_iface' helper module.

pytcp/tests/unit/stack/test__stack__sysctl_iface.py

ver 3.0.10
"""

import sys
import types
from typing import override
from unittest import TestCase

from pytcp.stack import sysctl, sysctl_iface


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


class _SysctlIfaceFixtureBase(TestCase):
    """
    Shared fixture: snapshot the registry's internal state on
    setUp and restore it on tearDown so each test starts and
    ends with a clean slate.
    """

    @override
    def setUp(self) -> None:
        """
        Snapshot the registry membership and module-level
        attributes that any test might mutate.
        """

        self._snapshot_registry = dict(sysctl._registry)
        self._snapshot_finalize = list(sysctl._finalize_validators)
        self._carriers: list[str] = []

    @override
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

    def _register_iface_int(
        self,
        *,
        key: str,
        carrier_name: str,
        attr: str,
        default: int,
        initial_slots: dict[str, int] | None = None,
        description: str = "",
    ) -> types.ModuleType:
        """
        Install a throwaway carrier module backing an
        interface-scope int knob. Storage is a 'dict[str, int]'
        seeded with '{"default": <default>}' (plus any
        'initial_slots' overlay) and registered with
        'interface_scope=True'.
        """

        storage: dict[str, int] = {"default": default}
        if initial_slots is not None:
            storage.update(initial_slots)
        module = _build_carrier_module(carrier_name, **{attr: storage})
        self._carriers.append(carrier_name)
        sysctl.register(
            key=key,
            module_name=carrier_name,
            attr=attr,
            default=default,
            validator=sysctl.is_positive_int(key),
            description=description,
            interface_scope=True,
        )
        return module

    def _register_flat_int(
        self,
        *,
        key: str,
        carrier_name: str,
        attr: str,
        default: int,
    ) -> types.ModuleType:
        """
        Install a throwaway carrier module backing a flat (non-
        interface-scope) int knob — used to pin coexistence
        with the existing flat-key surface.
        """

        module = _build_carrier_module(carrier_name, **{attr: default})
        self._carriers.append(carrier_name)
        sysctl.register(
            key=key,
            module_name=carrier_name,
            attr=attr,
            default=default,
            validator=sysctl.is_positive_int(key),
        )
        return module


class TestSysctlIfaceRegister(_SysctlIfaceFixtureBase):
    """
    The 'register(interface_scope=True)' shape tests.
    """

    def test__lib__sysctl_iface__register_records_interface_scope_flag(self) -> None:
        """
        Ensure registering an interface-scope knob records the
        'interface_scope=True' flag on the '_Knob' entry so the
        rest of the registry can dispatch on it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._register_iface_int(
            key="test.arp.ignore",
            carrier_name="pytcp_test_iface_carrier_register",
            attr="ARP__IGNORE",
            default=1,
        )
        self.assertTrue(
            sysctl._registry["test.arp.ignore"].interface_scope,
            msg="register(interface_scope=True) must mark the registered _Knob.",
        )

    def test__lib__sysctl_iface__register_default_flag_is_false(self) -> None:
        """
        Ensure 'register(...)' defaults 'interface_scope' to
        'False' so the existing flat-key call sites are
        unchanged.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._register_flat_int(
            key="test.flat.knob",
            carrier_name="pytcp_test_iface_carrier_flat",
            attr="FLAT_KNOB",
            default=42,
        )
        self.assertFalse(
            sysctl._registry["test.flat.knob"].interface_scope,
            msg="register without interface_scope must default the flag to False.",
        )


class TestSysctlIfaceSet(_SysctlIfaceFixtureBase):
    """
    The 'sysctl.set' parsing tests for interface-scope keys.
    """

    def test__lib__sysctl_iface__set_per_iface_slot_writes_dict_entry(self) -> None:
        """
        Ensure 'sysctl.set("ns.ifname.field", value)' writes the
        value into the per-interface dict slot keyed by the
        '<ifname>' segment of the operator-supplied key.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        carrier = self._register_iface_int(
            key="test.arp.ignore",
            carrier_name="pytcp_test_iface_carrier_set_slot",
            attr="ARP__IGNORE",
            default=1,
        )
        sysctl.set("test.arp.tap7.ignore", 2)
        self.assertEqual(
            carrier.ARP__IGNORE.get("tap7"),
            2,
            msg="sysctl.set on a per-iface key must write the value into storage[<ifname>].",
        )
        self.assertEqual(
            carrier.ARP__IGNORE.get("default"),
            1,
            msg="Writing a per-iface slot must NOT clobber the 'default' slot.",
        )

    def test__lib__sysctl_iface__set_default_slot_updates_template(self) -> None:
        """
        Ensure 'sysctl.set("ns.default.field", value)' updates
        the '"default"' slot — the template that newly-attached
        interfaces inherit from.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        carrier = self._register_iface_int(
            key="test.arp.ignore",
            carrier_name="pytcp_test_iface_carrier_set_default",
            attr="ARP__IGNORE",
            default=1,
        )
        sysctl.set("test.arp.default.ignore", 9)
        self.assertEqual(
            carrier.ARP__IGNORE.get("default"),
            9,
            msg="sysctl.set on 'ns.default.field' must update the 'default' slot.",
        )

    def test__lib__sysctl_iface__set_bare_base_key_on_iface_knob_raises(self) -> None:
        """
        Ensure writing the bare base key 'ns.field' (no
        '<ifname>' segment) for an interface-scope knob raises
        with a message that names the offending key — the
        operator MUST address a specific interface or the
        '"default"' slot.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._register_iface_int(
            key="test.arp.ignore",
            carrier_name="pytcp_test_iface_carrier_bare_set",
            attr="ARP__IGNORE",
            default=1,
        )
        with self.assertRaises(KeyError) as ctx:
            sysctl.set("test.arp.ignore", 2)
        self.assertIn(
            "test.arp.ignore",
            str(ctx.exception),
            msg="The bare-base-key rejection must surface the offending key.",
        )

    def test__lib__sysctl_iface__set_unknown_per_iface_key_raises(self) -> None:
        """
        Ensure a per-iface-shaped operator key whose base is not
        registered raises 'KeyError' with the offending key in
        the message — same contract as the flat-key 'unknown
        sysctl' path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(KeyError) as ctx:
            sysctl.set("test.unknown.tap7.field", 1)
        self.assertIn(
            "test.unknown.tap7.field",
            str(ctx.exception),
            msg="The unknown-per-iface-key error must surface the operator-supplied key.",
        )

    def test__lib__sysctl_iface__set_runs_validator_on_per_iface_write(self) -> None:
        """
        Ensure the per-knob validator runs on a per-interface
        write — invalid per-interface values are rejected
        BEFORE the slot mutation lands.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        carrier = self._register_iface_int(
            key="test.arp.ignore",
            carrier_name="pytcp_test_iface_carrier_validator",
            attr="ARP__IGNORE",
            default=1,
        )
        with self.assertRaises(ValueError):
            sysctl.set("test.arp.tap7.ignore", -1)
        self.assertNotIn(
            "tap7",
            carrier.ARP__IGNORE,
            msg="A rejected per-iface set must NOT create the per-iface slot.",
        )

    def test__lib__sysctl_iface__set_writes_iface_slot_for_unknown_iface(self) -> None:
        """
        Ensure writing a per-iface slot for an interface name
        not present in 'stack.interfaces' succeeds — matches
        Linux behaviour where 'sysctl -w
        net.ipv4.conf.fake0.arp_ignore=2' persists the value so
        a later attach picks it up.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        carrier = self._register_iface_int(
            key="test.arp.ignore",
            carrier_name="pytcp_test_iface_carrier_unknown_iface",
            attr="ARP__IGNORE",
            default=1,
        )
        sysctl.set("test.arp.notyetattached.ignore", 2)
        self.assertEqual(
            carrier.ARP__IGNORE.get("notyetattached"),
            2,
            msg="Pre-attach config must succeed (Linux parity).",
        )


class TestSysctlIfaceGet(_SysctlIfaceFixtureBase):
    """
    The 'sysctl.get' parsing tests for interface-scope keys.
    """

    def test__lib__sysctl_iface__get_returns_per_iface_value(self) -> None:
        """
        Ensure 'sysctl.get("ns.ifname.field")' returns the
        per-interface slot's value when it has been set.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._register_iface_int(
            key="test.arp.ignore",
            carrier_name="pytcp_test_iface_carrier_get_slot",
            attr="ARP__IGNORE",
            default=1,
            initial_slots={"tap7": 2},
        )
        self.assertEqual(
            sysctl.get("test.arp.tap7.ignore"),
            2,
            msg="sysctl.get must return the per-iface slot value when set.",
        )

    def test__lib__sysctl_iface__get_falls_back_to_default_slot(self) -> None:
        """
        Ensure 'sysctl.get("ns.ifname.field")' falls back to the
        '"default"' slot when the per-interface slot is absent —
        the runtime resolution chain a newly-attached interface
        observes before any operator override.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._register_iface_int(
            key="test.arp.ignore",
            carrier_name="pytcp_test_iface_carrier_get_fallback",
            attr="ARP__IGNORE",
            default=1,
        )
        self.assertEqual(
            sysctl.get("test.arp.fresh.ignore"),
            1,
            msg="A 'get' for an absent per-iface slot must fall back to 'default'.",
        )

    def test__lib__sysctl_iface__get_default_slot_returns_template(self) -> None:
        """
        Ensure 'sysctl.get("ns.default.field")' returns the
        template value directly — operators can read the
        current template without enumerating slots.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._register_iface_int(
            key="test.arp.ignore",
            carrier_name="pytcp_test_iface_carrier_get_default",
            attr="ARP__IGNORE",
            default=5,
        )
        self.assertEqual(
            sysctl.get("test.arp.default.ignore"),
            5,
            msg="get on the 'default' slot must return the template value.",
        )

    def test__lib__sysctl_iface__get_bare_base_key_on_iface_knob_raises(self) -> None:
        """
        Ensure reading the bare base key 'ns.field' for an
        interface-scope knob raises 'KeyError' — the registry
        has no single value to return; the caller must address
        a specific interface or the '"default"' slot.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._register_iface_int(
            key="test.arp.ignore",
            carrier_name="pytcp_test_iface_carrier_bare_get",
            attr="ARP__IGNORE",
            default=1,
        )
        with self.assertRaises(KeyError) as ctx:
            sysctl.get("test.arp.ignore")
        self.assertIn(
            "test.arp.ignore",
            str(ctx.exception),
            msg="Bare-base-key rejection must surface the offending key.",
        )

    def test__lib__sysctl_iface__flat_key_unaffected_by_iface_parsing(self) -> None:
        """
        Ensure an existing flat key (no '<ifname>' segment) is
        resolved directly without going through the
        interface-scope parsing path — the per-interface
        extension MUST NOT break the flat-key contract.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._register_flat_int(
            key="test.flat.knob",
            carrier_name="pytcp_test_iface_carrier_coexist",
            attr="FLAT_KNOB",
            default=42,
        )
        self.assertEqual(
            sysctl.get("test.flat.knob"),
            42,
            msg="Flat-key 'get' must work unchanged after the iface extension.",
        )
        sysctl.set("test.flat.knob", 99)
        self.assertEqual(
            sysctl.get("test.flat.knob"),
            99,
            msg="Flat-key 'set' must work unchanged after the iface extension.",
        )


class TestSysctlIfaceReset(_SysctlIfaceFixtureBase):
    """
    The 'reset_to_defaults' behavior for interface-scope knobs.
    """

    def test__lib__sysctl_iface__reset_clears_per_iface_slots(self) -> None:
        """
        Ensure 'reset_to_defaults' replaces the per-interface
        dict with a fresh '{"default": <registered>}' — clobbers
        every per-iface slot AND restores the template. This is
        the contract test fixtures rely on for cross-test
        isolation.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        carrier = self._register_iface_int(
            key="test.arp.ignore",
            carrier_name="pytcp_test_iface_carrier_reset",
            attr="ARP__IGNORE",
            default=1,
            initial_slots={"tap7": 2, "tap8": 3},
        )
        sysctl.set("test.arp.default.ignore", 9)
        sysctl.reset_to_defaults()
        self.assertEqual(
            carrier.ARP__IGNORE,
            {"default": 1},
            msg="reset_to_defaults must restore an interface-scope knob to {'default': <registered>}.",
        )


class TestSysctlIfaceHelper(_SysctlIfaceFixtureBase):
    """
    The 'pytcp.stack.sysctl_iface' helper module surface.
    """

    def test__lib__sysctl_iface__get_for_iface_returns_per_iface_value(self) -> None:
        """
        Ensure 'sysctl_iface.get_for_iface(base, ifname)'
        returns the per-interface slot value when set — the
        runtime read path for per-interface consumers.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._register_iface_int(
            key="test.arp.ignore",
            carrier_name="pytcp_test_iface_carrier_helper_get",
            attr="ARP__IGNORE",
            default=1,
            initial_slots={"tap7": 2},
        )
        self.assertEqual(
            sysctl_iface.get_for_iface("test.arp.ignore", "tap7"),
            2,
            msg="get_for_iface must return the per-iface slot value when set.",
        )

    def test__lib__sysctl_iface__get_for_iface_falls_back_to_default(self) -> None:
        """
        Ensure 'sysctl_iface.get_for_iface(base, ifname)' falls
        back to the '"default"' slot when the per-interface
        slot is absent.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._register_iface_int(
            key="test.arp.ignore",
            carrier_name="pytcp_test_iface_carrier_helper_fallback",
            attr="ARP__IGNORE",
            default=7,
        )
        self.assertEqual(
            sysctl_iface.get_for_iface("test.arp.ignore", "fresh"),
            7,
            msg="get_for_iface must fall back to 'default' when the per-iface slot is absent.",
        )

    def test__lib__sysctl_iface__get_for_iface_none_resolves_to_default(self) -> None:
        """
        Ensure 'sysctl_iface.get_for_iface(base, None)'
        resolves to the '"default"' slot directly. The runtime
        passes 'None' when no interface name is in scope (test
        harnesses that skip 'interface_name=' on the
        'PacketHandler' ctor).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._register_iface_int(
            key="test.arp.ignore",
            carrier_name="pytcp_test_iface_carrier_helper_none",
            attr="ARP__IGNORE",
            default=4,
            initial_slots={"tap7": 99},
        )
        self.assertEqual(
            sysctl_iface.get_for_iface("test.arp.ignore", None),
            4,
            msg="get_for_iface(base, None) must resolve directly to the 'default' slot.",
        )

    def test__lib__sysctl_iface__get_for_iface_on_flat_key_raises(self) -> None:
        """
        Ensure 'sysctl_iface.get_for_iface' rejects a flat
        (non-interface-scope) key — calling the helper with a
        flat key is a programmer bug; surface it loudly.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._register_flat_int(
            key="test.flat.knob",
            carrier_name="pytcp_test_iface_carrier_helper_flat",
            attr="FLAT_KNOB",
            default=42,
        )
        with self.assertRaises(KeyError) as ctx:
            sysctl_iface.get_for_iface("test.flat.knob", "tap7")
        self.assertIn(
            "test.flat.knob",
            str(ctx.exception),
            msg="get_for_iface on a flat key must surface the offending key.",
        )

    def test__lib__sysctl_iface__get_for_iface_unknown_base_raises(self) -> None:
        """
        Ensure 'sysctl_iface.get_for_iface' raises 'KeyError'
        with the offending base key when the base is not
        registered at all.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(KeyError) as ctx:
            sysctl_iface.get_for_iface("test.absent.knob", "tap7")
        self.assertIn(
            "test.absent.knob",
            str(ctx.exception),
            msg="get_for_iface on an unknown base must surface the offending key.",
        )

    def test__lib__sysctl_iface__set_for_iface_writes_per_iface_slot(self) -> None:
        """
        Ensure 'sysctl_iface.set_for_iface(base, ifname, value)'
        writes the value to the per-interface slot AND runs the
        registered validator — the programmatic write path that
        pairs with 'get_for_iface'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        carrier = self._register_iface_int(
            key="test.arp.ignore",
            carrier_name="pytcp_test_iface_carrier_helper_set",
            attr="ARP__IGNORE",
            default=1,
        )
        sysctl_iface.set_for_iface("test.arp.ignore", "tap7", 2)
        self.assertEqual(
            carrier.ARP__IGNORE.get("tap7"),
            2,
            msg="set_for_iface must write into storage[<ifname>].",
        )

    def test__lib__sysctl_iface__set_for_iface_runs_validator(self) -> None:
        """
        Ensure 'sysctl_iface.set_for_iface' runs the registered
        validator and rejects invalid values, leaving the slot
        unmutated.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        carrier = self._register_iface_int(
            key="test.arp.ignore",
            carrier_name="pytcp_test_iface_carrier_helper_validate",
            attr="ARP__IGNORE",
            default=1,
        )
        with self.assertRaises(ValueError):
            sysctl_iface.set_for_iface("test.arp.ignore", "tap7", -1)
        self.assertNotIn(
            "tap7",
            carrier.ARP__IGNORE,
            msg="A rejected set_for_iface must NOT create the per-iface slot.",
        )

    def test__lib__sysctl_iface__set_for_iface_on_flat_key_raises(self) -> None:
        """
        Ensure 'sysctl_iface.set_for_iface' rejects a flat key
        — symmetric with 'get_for_iface', flat keys belong on
        the 'sysctl.set' API.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._register_flat_int(
            key="test.flat.knob",
            carrier_name="pytcp_test_iface_carrier_helper_flat_set",
            attr="FLAT_KNOB",
            default=42,
        )
        with self.assertRaises(KeyError) as ctx:
            sysctl_iface.set_for_iface("test.flat.knob", "tap7", 1)
        self.assertIn(
            "test.flat.knob",
            str(ctx.exception),
            msg="set_for_iface on a flat key must surface the offending key.",
        )


class TestSysctlIfaceOverride(_SysctlIfaceFixtureBase):
    """
    The 'override' context manager behavior on interface-scope
    keys — pinned so test fixtures can use the existing context
    manager to scope a per-iface override.
    """

    def test__lib__sysctl_iface__override_round_trips_per_iface_slot(self) -> None:
        """
        Ensure 'sysctl.override("ns.ifname.field", value)'
        mutates on enter and restores the prior observable value
        on exit — works on per-iface keys exactly like flat
        keys.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._register_iface_int(
            key="test.arp.ignore",
            carrier_name="pytcp_test_iface_carrier_override",
            attr="ARP__IGNORE",
            default=1,
            initial_slots={"tap7": 5},
        )
        with sysctl.override("test.arp.tap7.ignore", 9):
            self.assertEqual(
                sysctl.get("test.arp.tap7.ignore"),
                9,
                msg="override must mutate the per-iface slot on enter.",
            )
        self.assertEqual(
            sysctl.get("test.arp.tap7.ignore"),
            5,
            msg="override must restore the prior per-iface slot value on exit.",
        )


class TestSysctlIfaceListIntegration(_SysctlIfaceFixtureBase):
    """
    Integration of interface-scope knobs with the existing
    'list_keys' / 'snapshot' surface.
    """

    def test__lib__sysctl_iface__list_keys_includes_iface_base(self) -> None:
        """
        Ensure interface-scope knobs appear in 'list_keys()'
        under their base key form (e.g. 'arp.ignore', not
        'arp.<iface>.ignore') so the operator-facing discovery
        surface stays bounded.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._register_iface_int(
            key="test.arp.ignore",
            carrier_name="pytcp_test_iface_carrier_list",
            attr="ARP__IGNORE",
            default=1,
            initial_slots={"tap7": 2, "tap8": 3},
        )
        keys = sysctl.list_keys()
        self.assertIn(
            "test.arp.ignore",
            keys,
            msg="list_keys must enumerate the interface-scope knob under its base key form.",
        )

    def test__lib__sysctl_iface__snapshot_returns_storage_dict(self) -> None:
        """
        Ensure 'sysctl.snapshot()' for an interface-scope knob
        returns the per-interface storage dict directly. This
        preserves the 'every registered key in the snapshot'
        contract for debug dumps; operators inspecting the
        snapshot see the full per-slot map.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._register_iface_int(
            key="test.arp.ignore",
            carrier_name="pytcp_test_iface_carrier_snapshot",
            attr="ARP__IGNORE",
            default=1,
            initial_slots={"tap7": 2},
        )
        snap = sysctl.snapshot()
        self.assertEqual(
            snap.get("test.arp.ignore"),
            {"default": 1, "tap7": 2},
            msg="snapshot must surface the per-iface storage dict for an interface-scope knob.",
        )


class TestSysctlIfaceDescribe(_SysctlIfaceFixtureBase):
    """
    Interface-scope knob 'describe' key-form tolerance tests.
    """

    def test__lib__sysctl_iface__describe_accepts_base_and_slot_forms(self) -> None:
        """
        Ensure 'describe' returns the knob's registered description
        whether the knob is addressed by its base key, the 'default'
        template slot, or a per-interface slot. The description is
        knob-level metadata shared by every slot, so all three forms
        resolve to the same string.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._register_iface_int(
            key="test.arp.accept",
            carrier_name="pytcp_test_iface_carrier_describe",
            attr="ARP__ACCEPT",
            default=0,
            description="Accept gratuitous replies on this interface.",
        )
        expected = "Accept gratuitous replies on this interface."
        for key in (
            "test.arp.accept",
            "test.arp.default.accept",
            "test.arp.tap7.accept",
        ):
            with self.subTest(key=key):
                self.assertEqual(
                    sysctl.describe(key),
                    expected,
                    msg=f"describe({key!r}) must return the knob-level description.",
                )

    def test__lib__sysctl_iface__describe_rejects_unknown_key(self) -> None:
        """
        Ensure 'describe' raises 'KeyError' for a key that maps to no
        registered knob, including a slot-qualified form whose base is
        unregistered.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(KeyError, msg="describe must reject an unknown key."):
            sysctl.describe("test.nope.tap7.accept")
