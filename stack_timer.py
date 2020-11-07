#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
stack_tmer.py - module contains class supporting timer that can be used by other stack components

"""

import loguru
import time
import threading


class StackTimerTask:
    """ Timer task support class """

    def __init__(self, method, args, kwargs, delay, repeat):
        """ Class constructor """

        self.method = method
        self.args = args
        self.kwargs = kwargs
        self.delay = delay
        self.repeat = repeat

        self.remaining_delay = delay

    def tick(self):
        """ Tick input from timer """

        self.remaining_delay -= 1

        if self.remaining_delay:
            return

        self.method(*self.args, **self.kwargs)

        if self.repeat:
            self.remaining_delay = self.delay
            if self.repeat > 0:
                self.repeat -= 1


class StackTimer:
    """ Support for stack timer """

    def __init__(self):
        """ Class constructor """

        self.logger = loguru.logger.bind(object_name="stack_timer.")

        self.run_stack_timer = True

        self.tasks = []
        self.timers = {}

        threading.Thread(target=self.__thread_timer).start()
        self.logger.debug("Started stack timer")

    def __thread_timer(self):
        """ Thread responsible for executing registered methods on every timer tick """

        while self.run_stack_timer:
            time.sleep(0.001)

            # Tck registered timers
            for name in self.timers:
                self.timers[name] -= 1

            # Tick registered methods
            for task in self.tasks:
                task.tick()

            # Cleanup expired timers
            self.timers = {_: __ for _, __ in self.timers.items() if __}

            # Cleanup expired methods
            self.tasks = [_ for _ in self.tasks if _.remaining_delay]

    def register_method(self, method, args=[], kwargs={}, delay=1, repeat=-1):
        """ Register method to be executed by timer """

        self.tasks.append(StackTimerTask(method, args, kwargs, delay, repeat))

    def register_timer(self, name, timeout):
        """ Register delay timer """

        self.timers[name] = timeout

    def timer_expired(self, name):
        """ Check if timer expired """

        self.logger.opt(ansi=True).trace(f"<red>Active timers: {self.timers}</>")

        return not self.timers.get(name, None) 
