#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020  Sebastian Majewski                                  #
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

##############################################################################################
#                                                                                            #
#  This program is a work in progress and it changes on daily basis due to new features      #
#  being implemented, changes being made to already implemented features, bug fixes, etc.    #
#  Therefore if the current version is not working as expected try to clone it again the     #
#  next day or shoot me an email describing the problem. Any input is appreciated. Also      #
#  keep in mind that some features may be implemented only partially (as needed for stack    #
#  operation) or they may be implemented in sub-optimal or not 100% RFC compliant way (due   #
#  to lack of time) or last but not least they may contain bug(s) that i didn't notice yet.  #
#                                                                                            #
##############################################################################################


#
# timer.py - module contains class supporting timer that can be used by other stack components
#


import threading
import time

import loguru

import stack


class TimerTask:
    """ Timer task support class """

    def __init__(self, method, args, kwargs, delay, delay_exp, repeat_count, stop_condition):
        """ Class constructor, repeat_count = -1 means infinite, delay_exp means to raise delay time exponentialy after each method execution """

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
        """ Tick input from timer """

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
    """ Support for stack timer """

    def __init__(self):
        """ Class constructor """

        stack.timer = self

        self.logger = loguru.logger.bind(object_name="timer.")

        self.run_timer = True

        self.tasks = []
        self.timers = {}

        threading.Thread(target=self.__thread_timer).start()
        self.logger.debug("Started timer")

    def __thread_timer(self):
        """ Thread responsible for executing registered methods on every timer tick """

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

    def register_method(self, method, args=None, kwargs=None, delay=1, delay_exp=False, repeat_count=-1, stop_condition=None):
        """ Register method to be executed by timer """

        self.tasks.append(TimerTask(method, [] if args is None else args, {} if kwargs is None else kwargs, delay, delay_exp, repeat_count, stop_condition))

    def register_timer(self, name, timeout):
        """ Register delay timer """

        self.timers[name] = timeout

    def timer_expired(self, name):
        """ Check if timer expired """

        self.logger.opt(ansi=True).trace(f"<red>Active timers: {self.timers}</>")

        return not self.timers.get(name, None)
