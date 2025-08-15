#!/usr/bin/env python3

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
The base class for all of the subsystems used by the stack.

pytcp/lib/subsystem.py

ver 3.0.3
"""


import threading
from abc import ABC, abstractmethod

from pytcp.lib.logger import log

SUBSYSTEM_SLEEP_TIME__SEC = 0.1


class Subsystem(ABC):
    """
    Base class for the 'user space' services and clients.
    """

    _subsystem_name: str
    _event__stop_subsystem: threading.Event

    def __init__(self, *, info: str | None = None) -> None:
        """
        Initialize the subsystem.
        """

        __debug__ and log(
            "stack",
            (
                f"Initializing {self._subsystem_name}"
                + (f" [{info}]" if info else "")
            ),
        )

        self._event__stop_subsystem = threading.Event()

    def start(self) -> None:
        """
        Start the subsystem.
        """

        __debug__ and log("stack", f"Starting {self._subsystem_name}")

        self._event__stop_subsystem.clear()
        threading.Thread(target=self._thread__subsystem).start()
        self._start()

    def stop(self) -> None:
        """
        Stop the subsystem.
        """

        __debug__ and log("stack", f"Stopping {self._subsystem_name}")

        self._event__stop_subsystem.set()
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
        Thread responsible for executing the subsystem operations.
        """

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
