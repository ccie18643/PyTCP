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
# service/tcp_generic.py - 'user space' TCP generic service class
#


from __future__ import annotations  # Required by Python ver < 3.10

import threading
from typing import TYPE_CHECKING

import lib.socket as socket
from misc.ip_helper import ip_version

if TYPE_CHECKING:
    from lib.socket import Socket


class ServiceTcp:
    """TCP service support class"""

    def __init__(self, name: str, local_ip_address: str, local_port: int) -> None:
        """Class constructor"""

        self.local_ip_address = local_ip_address
        self.local_port = local_port
        self.name = name

        threading.Thread(target=self.__thread_service).start()

    def __thread_service(self) -> None:
        """Service initialization"""

        version = ip_version(self.local_ip_address)
        if version == 6:
            s = socket.socket(family=socket.AF_INET6, type=socket.SOCK_STREAM)
        elif version == 4:
            s = socket.socket(family=socket.AF_INET4, type=socket.SOCK_STREAM)
        else:
            print(f"Service TCP {self.name}: Invalid local IP address - {self.local_ip_address}")
            return

        try:
            s.bind((self.local_ip_address, self.local_port))
            print(f"Service TCP {self.name}: Socket created, bound to {self.local_ip_address}, port {self.local_port}")
        except OSError as error:
            print(f"Service TCP {self.name}: bind() call failed - {error}")
            return

        s.listen()
        print(f"Service TCP {self.name}: Socket set to listening mode")

        while True:
            cs, _ = s.accept()
            print(f"Service TCP {self.name}: Inbound connection received from {cs.remote_ip_address}, port {cs.remote_port}")
            threading.Thread(target=self.__thread_connection, args=(cs,)).start()

    def __thread_connection(self, cs: Socket) -> None:
        """Inbound connection handler"""

        self.service(cs)

    def service(self, cs: Socket) -> None:
        """Service method"""

        print(f"Service TCP {self.name}: No service method defined, closing connection")
        cs.close()
