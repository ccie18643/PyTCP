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
# tracker.py - generate serial number information for new packets
#


import time


class Tracker:
    """Object used for tracking packets"""

    serial_rx = 0
    serial_tx = 0

    def __init__(self, prefix, echo_tracker=None):
        """Class constructor"""

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
        """Return serial number string"""

        if self.echo_tracker:
            return self.serial + " " + str(self.echo_tracker)

        return self.serial

    @property
    def latency(self):
        """Latency between echo tracker timestamp and current time"""

        if self.echo_tracker:
            return f" {(time.time() - self.echo_tracker.timestamp) * 1000:.3f}ms"

        return ""
