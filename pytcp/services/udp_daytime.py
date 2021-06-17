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
# services/udp_daytime.py - 'user space' service UDP Daytime (RFC 867)
#


from __future__ import annotations  # Required by Python ver < 3.10

from datetime import datetime
from typing import TYPE_CHECKING

from lib.logger import log
from services.udp_generic import ServiceUdp

if TYPE_CHECKING:
    from lib.socket import Socket


class ServiceUdpDaytime(ServiceUdp):
    """UDP Echo service support class"""

    def __init__(self, local_ip_address: str, local_port: int = 13):
        """Class constructor"""

        super().__init__("Echo", local_ip_address, local_port)

    def service(self, s: Socket) -> None:
        """Inbound connection handler"""

        while True:
            _, remote_address = s.recvfrom()
            message = bytes(str(datetime.now()), "utf-8")
            s.sendto(message, remote_address)
            if __debug__:
                log("service", f"Service UDP Daytime: Sent {len(message)} bytes to {remote_address[0]}, port {remote_address[1]}")
