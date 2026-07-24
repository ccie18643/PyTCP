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
This module contains the interface-scope helper surface that
runtime consumers use to read and write per-interface sysctl
knobs. Pairs with 'pytcp.stack.sysctl' (the operator-facing
dict-like surface) — consumers call
'sysctl_iface.get_for_iface(base, ifname)' from inside a
packet handler whose '_interface_name' is in scope.

Plan: docs/refactor/sysctl_per_interface.md.

pytcp/stack/sysctl_iface.py

ver 3.0.8
"""

import sys
from typing import Any

from pytcp.stack.sysctl import _registry


def _resolve_iface_knob(base_key: str) -> Any:
    """
    Look up an interface-scope knob by its registered base key
    (e.g. 'arp.ignore', not 'arp.<ifname>.ignore'). Raises
    'KeyError' on unknown bases AND on flat (non-interface-
    scope) keys — calling the iface helpers with a flat key
    is a programmer bug and surfaces loudly.
    """

    knob = _registry.get(base_key)
    if knob is None:
        raise KeyError(f"unknown sysctl: {base_key!r}")
    if not knob.interface_scope:
        raise KeyError(
            f"sysctl {base_key!r} is not interface-scope; " f"use 'pytcp.stack.sysctl.get'/'set' for flat keys",
        )
    return knob


def get_for_iface(base_key: str, ifname: str | None, /) -> Any:
    """
    Return the per-interface live value for an interface-scope
    sysctl. Resolution chain: 'storage[<ifname>]' if present,
    else 'storage["default"]'. The runtime read path that
    packet-handler / cache / SLAAC consumers call in their hot
    loops — each consumer has its own '_interface_name' in
    scope.

    Pass 'None' when no interface is in scope (test harnesses
    that skip 'interface_name=' on the 'PacketHandler' ctor);
    the read falls back to the '"default"' template slot
    directly.

    Raises 'KeyError' on unknown bases AND on flat keys (see
    '_resolve_iface_knob' for the contract).
    """

    knob = _resolve_iface_knob(base_key)
    storage: dict[str, Any] = getattr(sys.modules[knob.module_name], knob.attr)
    if ifname is not None and ifname in storage:
        return storage[ifname]
    return storage["default"]


def set_for_iface(base_key: str, ifname: str, value: Any, /) -> None:
    """
    Write the per-interface slot for an interface-scope sysctl.
    Runs the registered per-knob validator before the write —
    invalid per-interface values never leak through. The
    programmatic counterpart to 'get_for_iface'; the dict-like
    operator surface ('sysctl["ns.<ifname>.field"] = value')
    routes here through 'sysctl.set'.

    Raises 'KeyError' on unknown bases AND on flat keys,
    'ValueError' on validator rejection.
    """

    knob = _resolve_iface_knob(base_key)
    if knob.validator is not None:
        knob.validator(value)
    storage: dict[str, Any] = getattr(sys.modules[knob.module_name], knob.attr)
    storage[ifname] = value
