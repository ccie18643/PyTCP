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
This module contains the lock-guarded registry of stack network
interfaces, keyed by ifindex.

pytcp/runtime/interface_table.py

ver 3.0.10
"""

import threading
from collections.abc import Iterator, Mapping
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Guarded to break a genuine import cycle: 'pytcp.stack' imports
    # this module at top to declare the module-level 'interfaces'
    # registry, this module would import 'packet_handler' for the
    # handler type, and 'packet_handler' imports 'pytcp.stack' at top
    # ('from pytcp import stack'). The handlers are stored opaquely —
    # the table never calls into the class — so the type is needed for
    # annotations only and the runtime import is unnecessary.
    from pytcp.runtime.packet_handler import PacketHandlerL2, PacketHandlerL3


class InterfaceTable:
    """
    The stack-wide registry of network interfaces keyed by ifindex.

    Each value is a 'PacketHandler' — the handler instance IS the
    per-interface object (it owns the MTU, MAC, addresses, fragment
    tables, IP-id generators, neighbor caches and rings for one
    interface). Linux keys interfaces (and their per-ifindex ARP / ND
    caches, addresses, MTU) by ifindex; this registry mirrors that.

    A lock-guarded, dict-compatible replacement for the former bare
    'dict[int, PacketHandler]'. The daemon mutates the registry at
    runtime ('add_interface' / 'remove_interface' = RTNETLINK
    'RTM_NEWLINK' / 'RTM_DELLINK') while the RX / TX / timer threads
    read it; compound access (and free-threaded / no-GIL builds) need
    the explicit lock. 'add' allocates the next ifindex and stores the
    handler under the lock so two concurrent adds cannot collide on the
    same index.

    Iteration accessors ('values' / 'keys' / 'items' / '__iter__')
    return detached snapshots taken under the lock, so a reader can
    iterate the interface set while another thread mutates it without
    risking 'RuntimeError: dictionary changed size during iteration'.
    """

    def __init__(self, *, first_ifindex: int = 1) -> None:
        """
        Initialize an empty registry, its guarding lock, and the base
        ifindex the first 'add' allocates.
        """

        self._lock = threading.Lock()
        self._first_ifindex = first_ifindex
        self._interfaces: dict[int, "PacketHandlerL2 | PacketHandlerL3"] = {}

    def add(self, handler: "PacketHandlerL2 | PacketHandlerL3", /) -> int:
        """
        Allocate the next ifindex, register 'handler' under it, stamp
        the allocated ifindex onto the handler, and return it.

        The first add into an empty table takes 'first_ifindex';
        thereafter the index is 'max(existing) + 1' — freed indexes are
        never reused, matching the monotonic allocation Linux uses for
        netdev ifindexes. Allocation and store happen under the lock so
        concurrent adds receive distinct indexes.
        """

        with self._lock:
            ifindex = self._first_ifindex if not self._interfaces else max(self._interfaces) + 1
            handler.set_ifindex(ifindex)
            self._interfaces[ifindex] = handler
            return ifindex

    def get(
        self,
        ifindex: int,
        default: "PacketHandlerL2 | PacketHandlerL3 | None" = None,
    ) -> "PacketHandlerL2 | PacketHandlerL3 | None":
        """
        Return the interface registered under 'ifindex', or 'default'.
        """

        with self._lock:
            return self._interfaces.get(ifindex, default)

    def pop(
        self,
        ifindex: int,
        default: "PacketHandlerL2 | PacketHandlerL3 | None" = None,
    ) -> "PacketHandlerL2 | PacketHandlerL3 | None":
        """
        Remove and return the interface under 'ifindex', or 'default'.
        """

        with self._lock:
            return self._interfaces.pop(ifindex, default)

    def __getitem__(self, ifindex: int) -> "PacketHandlerL2 | PacketHandlerL3":
        """
        Return the interface registered under 'ifindex' (or raise).
        """

        with self._lock:
            return self._interfaces[ifindex]

    def __setitem__(self, ifindex: int, handler: "PacketHandlerL2 | PacketHandlerL3") -> None:
        """
        Register 'handler' under 'ifindex', replacing any prior entry.
        """

        with self._lock:
            self._interfaces[ifindex] = handler

    def __delitem__(self, ifindex: int) -> None:
        """
        Remove the interface registered under 'ifindex' (or raise).
        """

        with self._lock:
            del self._interfaces[ifindex]

    def __contains__(self, ifindex: int) -> bool:
        """
        Return whether an interface is registered under 'ifindex'.
        """

        with self._lock:
            return ifindex in self._interfaces

    def __len__(self) -> int:
        """
        Return the number of registered interfaces.
        """

        with self._lock:
            return len(self._interfaces)

    def __iter__(self) -> Iterator[int]:
        """
        Return an iterator over a snapshot of the registered ifindexes.
        """

        with self._lock:
            return iter(list(self._interfaces))

    def keys(self) -> list[int]:
        """
        Return a snapshot list of the registered ifindexes.
        """

        with self._lock:
            return list(self._interfaces.keys())

    def values(self) -> list["PacketHandlerL2 | PacketHandlerL3"]:
        """
        Return a snapshot list of the registered interfaces.
        """

        with self._lock:
            return list(self._interfaces.values())

    def items(self) -> list[tuple[int, "PacketHandlerL2 | PacketHandlerL3"]]:
        """
        Return a snapshot list of the registered (ifindex, interface)
        pairs.
        """

        with self._lock:
            return list(self._interfaces.items())

    def clear(self) -> None:
        """
        Remove every registered interface.
        """

        with self._lock:
            self._interfaces.clear()

    def update(self, other: "Mapping[int, PacketHandlerL2 | PacketHandlerL3]") -> None:
        """
        Bulk-install the mappings from 'other' into the registry.
        """

        with self._lock:
            self._interfaces.update(other)
