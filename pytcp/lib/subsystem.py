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
The base class for all of the subsystems used by stack.

pytcp/lib/subsystem.py

ver 3.0.3
"""


from __future__ import annotations

from pytcp.lib.logger import log
from abc import ABC, abstractmethod
import threading


class Subsystem(ABC):
    """
    Base class for 'user space' services like clients and servers.
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
                f"Initializing {self._subsystem_name}" f" [{info}]"
                if info
                else ""
            ),
        )

        self._event__stop_subsystem = threading.Event()

    def start(self) -> None:
        """
        Start the subsystem.
        """

        __debug__ and log("stack", f"Starting {self._subsystem_name}")

        self._event__stop_subsystem.clear()

        self._start()

    def stop(self) -> None:
        """
        Stop the subsystem.
        """

        __debug__ and log("stack", f"Stopping {self._subsystem_name}")

        self._event__stop_subsystem.set()

        self._stop()

    @abstractmethod
    def _start(self) -> None:
        """
        Start the subsystem componenets.
        """

        raise NotImplementedError

    def _stop(self) -> None:
        """
        Stop the subsystem components.
        """
