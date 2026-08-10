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
This module contains the base class for all of the subsystems used by the stack.

pytcp/runtime/subsystem.py

ver 3.0.10
"""

import threading
from abc import ABC, abstractmethod

from pytcp.lib.logger import log, set_log_interface

SUBSYSTEM_SLEEP_TIME__SEC = 0.1


class Subsystem(ABC):
    """
    Base class for stack-internal background-thread runtime
    components. Each subclass implements '_subsystem_loop()'
    which the base wraps in a 'while not stop_event' loop
    running on a dedicated worker thread spawned by 'start()'
    and joined by 'stop()'. Used by 'TxRing', 'RxRing',
    'Timer', and 'NeighborCache' (the IPv4 'ArpCache' and
    IPv6 'NdCache' parents) — every long-lived kernel-side
    runtime that needs an independent thread of execution.

    This is a runtime / kernel-side primitive, NOT a Phase-3
    public API surface. Userspace consumers MUST NOT
    subclass it — see CLAUDE.md "no userspace reach-through
    to stack internals". The home in 'pytcp/runtime/' is
    structurally enforcing that boundary.

    Initialisation contract — subclasses must set
    'self._subsystem_name' BEFORE calling 'super().__init__()'
    because the base init logs an 'Initializing <name>' line
    on the 'stack' channel.
    """

    _subsystem_name: str
    _event__stop_subsystem: threading.Event
    _thread: threading.Thread | None
    # Interface name this subsystem belongs to, bound onto the worker
    # thread's log context so every message it emits is interface-tagged.
    # None for stack-wide subsystems (the timer) whose work is not tied to
    # one interface.
    _log_interface: str | None = None

    def __init__(self, *, info: str | None = None) -> None:
        """
        Initialize the subsystem.
        """

        __debug__ and log(
            "stack",
            (f"Initializing {self._subsystem_name}" + (f" [{info}]" if info else "")),
        )

        self._event__stop_subsystem = threading.Event()
        self._thread = None

    def set_log_interface(self, interface_name: str | None, /) -> None:
        """
        Bind this subsystem's worker-thread log context to 'interface_name'
        so every message it emits is interface-tagged. Called by the
        stack lifecycle at construction time before 'start()'; the value
        is read once by the worker thread in '_thread__subsystem'.
        """

        self._log_interface = interface_name

    def start(self) -> None:
        """
        Start the subsystem.
        """

        __debug__ and log("stack", f"Starting {self._subsystem_name}")

        # Double-start guard. If a worker thread is already
        # running and 'start()' is called again, the previous
        # thread would be orphaned (its '_event__stop_subsystem'
        # reset + lost reference). Fail loudly instead.
        assert self._thread is None or not self._thread.is_alive(), (
            f"{self._subsystem_name}.start() called while a worker is still running; " f"call stop() before restart."
        )

        self._event__stop_subsystem.clear()
        # Daemon worker: 'stop()' joins it with a bounded 2.0 s timeout
        # for a graceful exit, but a subclass blocked in a syscall (a
        # DHCPv4 client mid-recv, a ring blocked on the TAP fd) can miss
        # that window and be left dangling. A daemon thread is then
        # abandoned at interpreter exit instead of wedging the process —
        # the safety net behind the bounded join in 'stop()'.
        self._thread = threading.Thread(target=self._thread__subsystem, daemon=True)
        self._thread.start()
        self._start()

    def stop(self) -> None:
        """
        Stop the subsystem.
        """

        __debug__ and log("stack", f"Stopping {self._subsystem_name}")

        self._event__stop_subsystem.set()
        if self._thread is not None:
            # Bound the join so a misbehaving subclass with a
            # blocking '_subsystem_loop' cannot wedge stack
            # teardown. The canonical loop cadence is
            # 'SUBSYSTEM_SLEEP_TIME__SEC' (0.1 s) so a few
            # iterations' worth is generous in normal operation.
            # NOTE: the joined thread reference is intentionally
            # retained on 'self._thread' so consumers can poll
            # 'is_alive()' after stop(); restart via 'start()'
            # is gated by the double-start assert above on the
            # 'is_alive()' check rather than on identity.
            self._thread.join(timeout=2.0)
            if self._thread.is_alive():
                __debug__ and log(
                    "stack",
                    f"<WARN>{self._subsystem_name} worker did not exit within 2.0 s; " f"leaving thread dangling</>",
                )
        self._stop()

    def _start(self) -> None:
        """
        Perform additional actions after starting the subsystem.
        """

    def _stop(self) -> None:
        """
        Perform additional actions after stopping the subsystem.
        """

    def _thread__subsystem(self) -> None:
        """
        Run the subsystem loop until the stop event is set.
        """

        # Tag every message this worker thread emits with its interface so
        # a multi-homed trace is readable per NIC.
        set_log_interface(self._log_interface)

        __debug__ and log("stack", f"Started {self._subsystem_name}")

        while not self._event__stop_subsystem.is_set():
            self._subsystem_loop()

        __debug__ and log("stack", f"Stopped {self._subsystem_name}")

    @abstractmethod
    def _subsystem_loop(self) -> None:
        """
        Execute the subsystem operations in a loop.
        """

        raise NotImplementedError
