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
# rx_ring.py - module contains class supporting RX operations
#


import os
import threading

import loguru


class RxRing:
    """ Support for receiving packets from the network """

    def __init__(self, tap):
        """ Initialize access to tap interface and the inbound queue """

        self.tap = tap
        self.rx_ring = []
        self.logger = loguru.logger.bind(object_name="rx_ring.")
        self.packet_enqueued = threading.Semaphore(0)

        threading.Thread(target=self.__thread_receive).start()
        self.logger.debug("Started RX ring")

    def __thread_receive(self):
        """ Thread responsible for receiving and enqueuing incoming packets """

        while True:
            self.rx_ring.append(os.read(self.tap, 2048))
            self.packet_enqueued.release()

    def dequeue(self):
        """ Dequeue inboutd packet from RX ring """

        self.packet_enqueued.acquire()
        return self.rx_ring.pop(0)
