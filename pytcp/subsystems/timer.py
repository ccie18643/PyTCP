#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################

# pylint: disable = expression-not-assigned
# pylint: disable = too-many-instance-attributes
# pylint: disable = too-many-arguments

"""
Module contains class supporting timer that can be used by other stack components.

pytcp/subsystems/timer.py

ver 2.7
"""


from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

from pytcp.lib.logger import log


class TimerTask:
    """
    Timer task support class.
    """

    def __init__(
        self,
        method: Callable,
        args: list[Any],
        kwargs: dict[str, Any],
        delay: int,
        delay_exp: bool,
        repeat_count: int,
        stop_condition: Callable | None,
    ) -> None:
        """
        Class constructor, repeat_count = -1 means infinite, delay_exp means
        to raise delay time exponentially after each method execution.
        """
        self._method: Callable = method
        self._args: list[Any] = args
        self._kwargs: dict[str, Any] = kwargs
        self._delay: int = delay
        self._delay_exp: bool = delay_exp
        self._repeat_count: int = repeat_count
        self._stop_condition: Callable | None = stop_condition
        self._remaining_delay: int = delay
        self._delay_exp_factor: int = 0

    @property
    def remaining_delay(self) -> int:
        """
        Getter for the '_remaining_delay' attribute.
        """
        return self._remaining_delay

    def tick(self) -> None:
        """
        Tick input from timer.
        """

        self._remaining_delay -= 1

        if self._stop_condition and self._stop_condition():
            self._remaining_delay = 0
            return

        if self._remaining_delay:
            return

        self._method(*self._args, **self._kwargs)

        if self._repeat_count:
            self._remaining_delay = (
                self._delay * (1 << self._delay_exp_factor)
                if self._delay_exp
                else self._delay
            )
            self._delay_exp_factor += 1
            if self._repeat_count > 0:
                self._repeat_count -= 1


class Timer:
    """
    Support for stack timer.
    """

    def __init__(self) -> None:
        """
        Class constructor.
        """
        self._tasks: list[TimerTask] = []
        self._timers: dict[str, int] = {}
        self._run_thread: bool = False

    def start(self) -> None:
        """
        Start timer thread.
        """
        __debug__ and log("stack", "Starting timer thread")
        self._run_thread = True
        threading.Thread(target=self.__thread_timer).start()
        time.sleep(0.1)

    def stop(self) -> None:
        """
        Stop timer thread.
        """
        __debug__ and log("stack", "Stopping timer thread")
        self._run_thread = False
        time.sleep(0.1)

    def __thread_timer(self) -> None:
        """
        Thread responsible for executing register methods on every timer tick.
        """

        __debug__ and log("stack", "Started timer thread")

        while self._run_thread:
            time.sleep(0.001)

            # Tck register timers
            for name in self._timers:
                self._timers[name] -= 1

            # Cleanup expired timers
            self._timers = {_: __ for _, __ in self._timers.items() if __}

            # Tick register methods
            for task in self._tasks:
                task.tick()

            # Cleanup expired methods
            self._tasks = [_ for _ in self._tasks if _.remaining_delay]

        __debug__ and log("stack", "Stopped timer thread")

    def register_method(
        self,
        method: Callable,
        args: list[Any] | None = None,
        kwargs: dict[str, Any] | None = None,
        delay: int = 1,
        delay_exp: bool = False,
        repeat_count: int = -1,
        stop_condition: Callable | None = None,
    ) -> None:
        """
        Register method to be executed by timer.
        """
        self._tasks.append(
            TimerTask(
                method,
                [] if args is None else args,
                {} if kwargs is None else kwargs,
                delay,
                delay_exp,
                repeat_count,
                stop_condition,
            )
        )

    def register_timer(self, name: str, timeout: int) -> None:
        """
        Register delay timer.
        """
        self._timers[name] = timeout

    def is_expired(self, name: str) -> bool:
        """
        Check if timer expired.
        """
        __debug__ and log("timer", f"<r>Active timers: {self._timers}</>")
        return not self._timers.get(name, None)
