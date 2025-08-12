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
Module contains class supporting timer that can be used by other stack components.

pytcp/stack/timer.py

ver 3.0.2
"""


from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

from pytcp.lib.logger import log
from pytcp.lib.subsystem import Subsystem


class TimerTask:
    """
    Timer task support class.
    """

    _method: Callable[[Any], None]
    _args: list[Any]
    _kwargs: dict[str, Any]
    _delay: int
    _delay_exp: bool
    _repeat_count: int
    _stop_condition: Callable[[], bool] | None
    _remaining_delay: int
    _delay_exp_factor: int

    def __init__(
        self,
        *,
        method: Callable[[Any], None],
        args: list[Any],
        kwargs: dict[str, Any],
        delay: int,
        delay_exp: bool,
        repeat_count: int,
        stop_condition: Callable[[], bool] | None,
    ) -> None:
        """
        Class constructor, repeat_count = -1 means infinite, delay_exp means
        to raise delay time exponentially after each method execution.
        """

        self._method = method
        self._args = args
        self._kwargs = kwargs
        self._delay = delay
        self._delay_exp = delay_exp
        self._repeat_count = repeat_count
        self._stop_condition = stop_condition
        self._remaining_delay = delay
        self._delay_exp_factor = 0

    @property
    def remaining_delay(self) -> int:
        """
        Geter for the '_remaining_delay' attribute.
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


class Timer(Subsystem):
    """
    Support for stack timer.
    """

    _subsystem_name = "Timer"

    _tasks: list[TimerTask]
    _timers: dict[str, int]

    _event__stop_subsystem: threading.Event

    def __init__(self) -> None:
        """
        Class constructor.
        """

        super().__init__()

        self._tasks = []
        self._timers = {}

    def _subsystem_loop(self) -> None:
        """
        Execute registered methods on every timer tick.
        """

        self._event__stop_subsystem.wait(0.001)

        # Adjust registered timers
        for name in self._timers:
            self._timers[name] -= 1

        # Cleanup expired timers
        self._timers = {_: __ for _, __ in self._timers.items() if __}

        # Tick registered methods
        for task in self._tasks:
            task.tick()

        # Cleanup expired methods
        self._tasks = [_ for _ in self._tasks if _.remaining_delay]

    def register_method(
        self,
        *,
        method: Callable[[Any], None],
        args: list[Any] | None = None,
        kwargs: dict[str, Any] | None = None,
        delay: int = 1,
        delay_exp: bool = False,
        repeat_count: int = -1,
        stop_condition: Callable[[], bool] | None = None,
    ) -> None:
        """
        Register method to be executed by timer.
        """

        self._tasks.append(
            TimerTask(
                method=method,
                args=[] if args is None else args,
                kwargs={} if kwargs is None else kwargs,
                delay=delay,
                delay_exp=delay_exp,
                repeat_count=repeat_count,
                stop_condition=stop_condition,
            )
        )

    def register_timer(self, *, name: str, timeout: int) -> None:
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
