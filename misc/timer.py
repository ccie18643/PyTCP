#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-2021  Sebastian Majewski                             #
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


#
# misc/timer.py - module contains class supporting timer that can be used by other stack components
#


import threading
import time
from typing import Callable, Optional

import loguru

import misc.stack as stack


class TimerTask:
    """Timer task support class"""

    def __init__(self, method: Callable, args: list, kwargs: dict, delay: int, delay_exp: bool, repeat_count: int, stop_condition: Optional[Callable]) -> None:
        """Class constructor, repeat_count = -1 means infinite, delay_exp means to raise delay time exponentially after each method execution"""

        self.method = method
        self.args = args
        self.kwargs = kwargs
        self.delay = delay
        self.delay_exp = delay_exp
        self.repeat_count = repeat_count
        self.stop_condition = stop_condition

        self.remaining_delay = delay
        self.delay_exp_factor = 0

    def tick(self):
        """Tick input from timer"""

        self.remaining_delay -= 1

        if self.stop_condition and self.stop_condition():
            self.remaining_delay = 0
            return

        if self.remaining_delay:
            return

        self.method(*self.args, **self.kwargs)

        if self.repeat_count:
            self.remaining_delay = self.delay * (1 << self.delay_exp_factor) if self.delay_exp else self.delay
            self.delay_exp_factor += 1
            if self.repeat_count > 0:
                self.repeat_count -= 1


class Timer:
    """Support for stack timer"""

    def __init__(self) -> None:
        """Class constructor"""

        stack.timer = self

        if __debug__:
            self._logger = loguru.logger.bind(object_name="timer.")

        self.run_timer = True

        self.tasks: list[TimerTask] = []
        self.timers: dict[str, int] = {}

        threading.Thread(target=self.__thread_timer).start()
        if __debug__:
            self._logger.debug("Started timer")

    def __thread_timer(self) -> None:
        """Thread responsible for executing registered methods on every timer tick"""

        while self.run_timer:
            time.sleep(0.001)

            # Tck registered timers
            for name in self.timers:
                self.timers[name] -= 1

            # Cleanup expired timers
            self.timers = {_: __ for _, __ in self.timers.items() if __}

            # Tick registered methods
            for task in self.tasks:
                task.tick()

            # Cleanup expired methods
            self.tasks = [_ for _ in self.tasks if _.remaining_delay]

    def register_method(
        self,
        method: Callable,
        args: list = None,
        kwargs: dict = None,
        delay: int = 1,
        delay_exp: bool = False,
        repeat_count: int = -1,
        stop_condition: Optional[Callable] = None,
    ) -> None:
        """Register method to be executed by timer"""

        self.tasks.append(TimerTask(method, [] if args is None else args, {} if kwargs is None else kwargs, delay, delay_exp, repeat_count, stop_condition))

    def register_timer(self, name: str, timeout: int) -> None:
        """Register delay timer"""

        self.timers[name] = timeout

    def is_expired(self, name: str) -> bool:
        """Check if timer expired"""

        if __debug__:
            self._logger.opt(ansi=True).trace(f"<red>Active timers: {self.timers}</>")

        return not self.timers.get(name, None)
