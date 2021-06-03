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
# client/icmp_echo.py - 'user space' client for ICMPv4/v6 echo
#


import random
import threading
import time
from datetime import datetime

import misc.stack as stack
from misc.ip_helper import ip_pick_version


class ClientIcmpEcho:
    """ICMPv4/v6 Echo client support class"""

    def __init__(self, local_ip_address: str, remote_ip_address: str, message_count: int = -1) -> None:
        """Class constructor"""

        self.local_ip_address = ip_pick_version(local_ip_address)
        self.remote_ip_address = ip_pick_version(remote_ip_address)
        self.message_count = message_count

        threading.Thread(target=self.__thread_client).start()

    def __thread_client(self) -> None:

        flow_id = random.randint(0, 65535)

        message_count = self.message_count
        message_seq = 0
        while message_count:
            message = bytes(str(datetime.now()) + "\n", "utf-8")

            if self.local_ip_address.version == 4:
                stack.packet_handler._phtx_icmp4(  # type: ignore
                    ip4_src=self.local_ip_address,
                    ip4_dst=self.remote_ip_address,
                    icmp4_type=8,
                    icmp4_code=0,
                    icmp4_ec_id=flow_id,
                    icmp4_ec_seq=message_seq,
                    icmp4_ec_data=message,
                )

            if self.local_ip_address.version == 6:
                stack.packet_handler._phtx_icmp6(  # type: ignore
                    ip6_src=self.local_ip_address,
                    ip6_dst=self.remote_ip_address,
                    icmp6_type=128,
                    icmp6_code=0,
                    icmp6_ec_id=flow_id,
                    icmp6_ec_seq=message_seq,
                    icmp6_ec_data=message,
                )

            print(f"Client ICMP Echo: Sent ICMP Echo ({flow_id}/{message_seq}) to {self.remote_ip_address} - {str(message)}")
            time.sleep(1)
            message_seq += 1
            message_count = min(message_count, message_count - 1)
