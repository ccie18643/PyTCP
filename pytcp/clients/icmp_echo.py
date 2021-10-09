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
# clients/icmp_echo.py - 'user space' client for ICMPv4/v6 echo
#


from __future__ import annotations

import random
import threading
import time
from datetime import datetime

import misc.stack as stack
from lib.ip4_address import Ip4Address
from lib.ip6_address import Ip6Address
from lib.logger import log
from misc.ip_helper import str_to_ip


class ClientIcmpEcho:
    """ICMPv4/v6 Echo client support class"""

    def __init__(self, local_ip_address: str, remote_ip_address: str, message_count: int = -1) -> None:
        """Class constructor"""

        self.local_ip_address = str_to_ip(local_ip_address)
        self.remote_ip_address = str_to_ip(remote_ip_address)
        self.message_count = message_count

        threading.Thread(target=self.__thread_client).start()

    def __thread_client(self) -> None:

        assert self.local_ip_address is not None
        assert self.remote_ip_address is not None

        flow_id = random.randint(0, 65535)

        message_count = self.message_count
        message_seq = 0
        while message_count:
            message = bytes(str(datetime.now()) + "\n", "utf-8")

            if self.local_ip_address.version == 4:
                assert isinstance(self.local_ip_address, Ip4Address)
                assert isinstance(self.remote_ip_address, Ip4Address)
                stack.packet_handler.send_icmp4_packet(
                    local_ip_address=self.local_ip_address,
                    remote_ip_address=self.remote_ip_address,
                    type=8,
                    code=0,
                    ec_id=flow_id,
                    ec_seq=message_seq,
                    ec_data=message,
                )

            if self.local_ip_address.version == 6:
                assert isinstance(self.local_ip_address, Ip6Address)
                assert isinstance(self.remote_ip_address, Ip6Address)
                stack.packet_handler.send_icmp6_packet(
                    local_ip_address=self.local_ip_address,
                    remote_ip_address=self.remote_ip_address,
                    type=128,
                    code=0,
                    ec_id=flow_id,
                    ec_seq=message_seq,
                    ec_data=message,
                )

            if __debug__:
                log("client", f"Client ICMP Echo: Sent ICMP Echo ({flow_id}/{message_seq}) to {self.remote_ip_address} - {str(message)}")
            time.sleep(1)
            message_seq += 1
            message_count = min(message_count, message_count - 1)
