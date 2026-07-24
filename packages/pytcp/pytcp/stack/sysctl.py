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
This module contains the runtime-tunable sysctl knob registry
— PyTCP's equivalent of the Linux net.* sysctl namespace.
Policy constants in protocol packages register themselves at
import time; operators read and write live values through
'pytcp.stack.sysctl["<dotted.key>"]' or via 'stack.init()'
kwargs at boot.

Design + classification rules: docs/refactor/sysctl_framework.md
Workflow for adding a knob: .claude/skills/sysctl_knob/SKILL.md

pytcp/stack/sysctl.py

ver 3.0.8
"""

import sys
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Generator, Iterator


@dataclass(slots=True)
class _Knob:
    """
    Single registry entry. Tracks the dotted-name canonical
    key, the backing module + attribute that holds the live
    value, the registration-time default (for restore), and an
    optional per-knob validator.

    'interface_scope' marks per-interface knobs whose backing
    attribute is a 'dict[str, T]' keyed by interface name with
    a mandatory '"default"' slot. Operator-side reads / writes
    use the expanded key 'ns.<ifname>.field' (see the parser
    in 'set' / 'get'); the bare base key is rejected. Plan:
    docs/refactor/sysctl_per_interface.md.
    """

    key: str
    module_name: str
    attr: str
    default: Any
    validator: Callable[[Any], None] | None
    description: str
    interface_scope: bool = False


_registry: dict[str, _Knob] = {}
_finalize_validators: list[Callable[[], None]] = []


def register(
    *,
    key: str,
    module_name: str,
    attr: str,
    default: Any,
    validator: Callable[[Any], None] | None = None,
    description: str = "",
    interface_scope: bool = False,
) -> None:
    """
    Register a runtime-tunable knob. Called from inside a
    protocol package's '*__constants.py' module at import
    time, once per knob. The 'module_name' is the calling
    module's '__name__'; the registry resolves it via
    'sys.modules' on each access so the binding survives
    re-imports.

    Pass 'interface_scope=True' for per-interface knobs whose
    backing attribute is a 'dict[str, T]' keyed by interface
    name. Plan: docs/refactor/sysctl_per_interface.md.
    """

    _registry[key] = _Knob(
        key=key,
        module_name=module_name,
        attr=attr,
        default=default,
        validator=validator,
        description=description,
        interface_scope=interface_scope,
    )


def register_finalize_validator(callback: Callable[[], None], /) -> None:
    """
    Register a cross-knob constraint callback. The callback is
    invoked from 'finalize_validators()' (called at the end of
    'stack.init()' and on every individual 'set()'). It must
    raise 'ValueError' on rejection — the registry re-raises
    the first failure verbatim.
    """

    _finalize_validators.append(callback)


def _resolve(key: str) -> _Knob:
    """
    Look up the registry entry for a key, raising 'KeyError'
    with a self-explanatory message on miss. Strict base-key
    lookup — does NOT expand interface-scope operator keys;
    use '_resolve_with_iface' for that.
    """

    knob = _registry.get(key)
    if knob is None:
        raise KeyError(f"unknown sysctl: {key!r}")
    return knob


def _split_iface_key(key: str) -> tuple[str, str] | None:
    """
    Split an interface-scope operator key '<ns...>.<ifname>.<field>'
    into '(base '<ns...>.<field>', ifname)' when its base maps to a
    registered interface-scope knob; otherwise 'None'. The '<ifname>'
    segment always sits just before the field — Linux's per-iface
    sysctls put the device name immediately before the leaf field name
    (e.g. 'net.ipv4.conf.<iface>.arp_ignore').
    """

    parts = key.split(".")
    if len(parts) < 3:
        return None
    base = ".".join(parts[:-2] + parts[-1:])
    candidate = _registry.get(base)
    if candidate is not None and candidate.interface_scope:
        return base, parts[-2]
    return None


def _resolve_with_iface(key: str) -> tuple[_Knob, str | None]:
    """
    Resolve a sysctl key against the registry, splitting
    interface-scope operator keys ('<ns>.<ifname>.<field>')
    into the base key '<ns>.<field>' plus '<ifname>'. Returns
    '(knob, None)' for flat keys and '(knob, ifname)' for
    interface-scope keys.

    Raises 'KeyError' on unknown keys AND on a bare base-key
    access ('<ns>.<field>' with no '<ifname>' segment) against
    an interface-scope knob — the operator MUST address a
    specific interface or the '"default"' template slot.
    """

    knob = _registry.get(key)
    if knob is not None:
        if knob.interface_scope:
            raise KeyError(
                f"sysctl {key!r} is interface-scope; specify "
                f"'<namespace>.<ifname>.<field>' or "
                f"'<namespace>.default.<field>'",
            )
        return knob, None

    split = _split_iface_key(key)
    if split is not None:
        base, ifname = split
        return _registry[base], ifname

    raise KeyError(f"unknown sysctl: {key!r}")


def _resolve_knob(key: str) -> _Knob:
    """
    Resolve a key to its knob for knob-level metadata access (e.g.
    'describe'), tolerant of how the knob is addressed: a flat key, an
    interface-scope base key '<ns>.<field>', or an interface-scope
    operator key '<ns>.<ifname>.<field>' all resolve to the same knob.
    Raises 'KeyError' when no knob matches.
    """

    knob = _registry.get(key)
    if knob is not None:
        return knob
    split = _split_iface_key(key)
    if split is not None:
        return _registry[split[0]]
    raise KeyError(f"unknown sysctl: {key!r}")


def get(key: str) -> Any:
    """
    Return the live value of the named sysctl by reading the
    backing module attribute through 'getattr'. Raises
    'KeyError' with the offending key in the message when no
    such knob is registered.

    For interface-scope knobs the operator-supplied key takes
    the form '<ns>.<ifname>.<field>' and the value resolves
    through the chain ifname-slot → '"default"' slot.
    """

    knob, ifname = _resolve_with_iface(key)
    if ifname is None:
        return getattr(sys.modules[knob.module_name], knob.attr)
    storage: dict[str, Any] = getattr(sys.modules[knob.module_name], knob.attr)
    if ifname in storage:
        return storage[ifname]
    return storage["default"]


def set(key: str, value: Any) -> None:
    """
    Set the live value of the named sysctl. Runs the per-knob
    validator (if any) before the write so a rejected value
    never leaks through to the backing attribute. Raises
    'KeyError' on unknown keys, 'ValueError' on validator
    rejection (with both the offending key and the value in
    the message).

    For interface-scope knobs the operator-supplied key takes
    the form '<ns>.<ifname>.<field>' and the write lands in
    'storage[<ifname>]'; pre-attach configuration is allowed
    (Linux parity — the slot persists until an interface with
    that name attaches).
    """

    knob, ifname = _resolve_with_iface(key)
    if knob.validator is not None:
        knob.validator(value)
    if ifname is None:
        setattr(sys.modules[knob.module_name], knob.attr, value)
        return
    storage: dict[str, Any] = getattr(sys.modules[knob.module_name], knob.attr)
    storage[ifname] = value


def list_keys() -> list[str]:
    """
    Return the list of registered keys in registration order.
    Drives operator-facing discovery ('sysctl --list'-style).
    """

    return list(_registry.keys())


def describe(key: str) -> str:
    """
    Return the human-readable description string registered
    with the knob. Empty string when no description was given.

    Tolerant of interface-scope addressing — a flat key, an
    interface-scope base key '<ns>.<field>', or a slot-qualified
    '<ns>.<ifname>.<field>' operator key all resolve to the same
    knob-level description.
    """

    return _resolve_knob(key).description


def snapshot() -> dict[str, Any]:
    """
    Return a snapshot of every registered key's current live
    value. Used for debug dumps and as a save-point for
    'reset_to_defaults'-style restoration.

    For interface-scope knobs the snapshot surfaces the full
    per-interface storage dict (every slot — '"default"' plus
    each per-iface override) so a debug dump captures the
    complete state. Flat knobs surface the scalar live value
    as today.
    """

    result: dict[str, Any] = {}
    for key, knob in _registry.items():
        if knob.interface_scope:
            result[key] = getattr(sys.modules[knob.module_name], knob.attr)
        else:
            result[key] = get(key)
    return result


def reset_to_defaults() -> None:
    """
    Restore every registered knob's backing attribute to the
    value passed at registration time. Used by 'stack.stop()'
    and test teardown to guarantee per-run mutation does not
    leak across runs.

    For interface-scope knobs the storage dict is replaced
    with a fresh '{"default": <registered>}' — every per-iface
    slot is cleared AND the template is restored.
    """

    for knob in _registry.values():
        if knob.interface_scope:
            setattr(sys.modules[knob.module_name], knob.attr, {"default": knob.default})
        else:
            setattr(sys.modules[knob.module_name], knob.attr, knob.default)


def finalize_validators() -> None:
    """
    Run every registered cross-knob constraint. Called at the
    end of 'stack.init()' after all kwargs have been applied,
    and on every individual 'set()' so runtime mutation that
    breaks a cross-knob constraint also fails fast. Each
    constraint is a callable that raises 'ValueError' on
    rejection — the registry re-raises the first failure
    verbatim.
    """

    for validator in _finalize_validators:
        validator()


@contextmanager
def override(key: str, value: Any) -> Generator[None, None, None]:
    """
    Context manager that mutates a sysctl on enter and
    restores the prior value on exit. Restoration runs even
    when the wrapped block raises.
    """

    prior = get(key)
    set(key, value)
    try:
        yield
    finally:
        set(key, prior)


class _SysctlRegistry:
    """
    Dict-like facade over the registry, exposed as the
    'pytcp.stack.sysctl.sysctl' singleton. Forwards subscript
    access to the module-level 'get' / 'set' functions.
    """

    def __getitem__(self, key: str) -> Any:
        """
        Return the live value of the named sysctl.
        """

        return get(key)

    def __setitem__(self, key: str, value: Any) -> None:
        """
        Set the live value of the named sysctl.
        """

        set(key, value)

    def __contains__(self, key: object) -> bool:
        """
        Test whether the registry contains the named sysctl.
        """

        return isinstance(key, str) and key in _registry

    def __iter__(self) -> Iterator[str]:
        """
        Iterate over the registered keys in registration order.
        """

        return iter(_registry)

    def __len__(self) -> int:
        """
        Return the number of registered keys.
        """

        return len(_registry)


sysctl = _SysctlRegistry()


def is_positive_int(name: str) -> Callable[[Any], None]:
    """
    Build a validator that requires a positive (> 0) integer.
    The 'name' is closed over so the rejection message
    surfaces the offending key.
    """

    def validator(value: Any) -> None:
        """
        Raise 'ValueError' unless 'value' is a positive int.
        """

        # 'isinstance(True, int)' is True in Python so booleans
        # would otherwise pass — reject them explicitly.
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"sysctl {name!r} must be a positive int; got {value!r}")

    return validator


def is_non_negative_int(name: str) -> Callable[[Any], None]:
    """
    Build a validator that requires a non-negative (≥ 0) integer
    — accepts 0, rejects negatives, floats, and booleans.
    Surfaces 'name' in the rejection message.
    """

    def validator(value: Any) -> None:
        """
        Raise 'ValueError' unless 'value' is a non-negative int.
        """

        # 'isinstance(True, int)' is True in Python so booleans
        # would otherwise pass — reject them explicitly.
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"sysctl {name!r} must be a non-negative int; got {value!r}")

    return validator


def is_float_in_range(name: str, *, low: float, high: float) -> Callable[[Any], None]:
    """
    Build a validator that requires a real-number value in the
    inclusive range '[low, high]'. Accepts 'int' transparently
    (Python's '0' is interchangeable with '0.0' in arithmetic
    contexts), rejects booleans and non-numeric types. Surfaces
    'name' in the rejection message.
    """

    def validator(value: Any) -> None:
        """
        Raise 'ValueError' unless 'value' is a numeric value in
        '[low, high]'.
        """

        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(
                f"sysctl {name!r} must be a number in [{low}, {high}]; " f"got {type(value).__name__}({value!r})",
            )
        if not low <= value <= high:
            raise ValueError(
                f"sysctl {name!r} must be in [{low}, {high}]; got {value!r}",
            )

    return validator


def is_int_in_range(name: str, *, low: int, high: int) -> Callable[[Any], None]:
    """
    Build a validator that requires an integer in the inclusive
    range '[low, high]'. Rejects booleans and non-int types.
    Surfaces 'name' in the rejection message.
    """

    def validator(value: Any) -> None:
        """
        Raise 'ValueError' unless 'value' is an int in '[low, high]'.
        """

        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(
                f"sysctl {name!r} must be an int in [{low}, {high}]; got {type(value).__name__}({value!r})",
            )
        if not low <= value <= high:
            raise ValueError(
                f"sysctl {name!r} must be in [{low}, {high}]; got {value!r}",
            )

    return validator
