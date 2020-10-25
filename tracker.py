#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
tracker.py - generate serial number information for new packets

"""


import time


class Tracker:
    """ Object used for tracking packets """

    serial_rx = 0
    serial_tx = 0

    def __init__(self, prefix, echo_tracker=None):
        """ Class constructor """

        self.echo_tracker = echo_tracker

        assert prefix in {"RX", "TX"}

        if prefix == "RX":
            self.timestamp = time.time()
            self.serial = f"RX{Tracker.serial_rx:0>4x}".upper()
            Tracker.serial_rx += 1
            if Tracker.serial_rx > 0xFFFF:
                Tracker.serial_rx = 0

        if prefix == "TX":
            self.timestamp = time.time()
            self.serial = f"TX{Tracker.serial_tx:0>4x}".upper()
            Tracker.serial_tx += 1
            if Tracker.serial_tx > 0xFFFF:
                Tracker.serial_tx = 0

    def __str__(self):
        """ Return serial number string """

        if self.echo_tracker:
            return self.serial + " " + str(self.echo_tracker)

        return self.serial

    @property
    def latency(self):
        """ Latency between echo tracker timestamp and current time """

        if self.echo_tracker:
            return f" {(time.time() - self.echo_tracker.timestamp) * 1000:.3f}ms"

        return ""
