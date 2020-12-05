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
# client_icmp_echo.py - 'user space' client for ICMPv4/v6 echo
#


import random
import threading
import time
from datetime import datetime

import stack
from ip_helper import ip_pick_version


class ClientIcmpEcho:
    """ ICMPv4/v6 Echo client support class """

    def __init__(self, local_ip_address, remote_ip_address, message_count=None):
        """ Class constructor """

        local_ip_address = ip_pick_version(local_ip_address)
        remote_ip_address = ip_pick_version(remote_ip_address)

        threading.Thread(target=self.__thread_client, args=(local_ip_address, remote_ip_address, message_count)).start()

    @staticmethod
    def __thread_client(local_ip_address, remote_ip_address, message_count):

        flow_id = random.randint(0, 65535)

        message_seq = 0
        while message_count is None or message_seq < message_count:
            message = bytes(str(datetime.now()) + "\n", "utf-8")

            if local_ip_address.version == 4:
                stack.packet_handler.phtx_icmp4(
                    ip4_src=local_ip_address,
                    ip4_dst=remote_ip_address,
                    icmp4_type=8,
                    icmp4_code=0,
                    icmp4_ec_id=flow_id,
                    icmp4_ec_seq=message_seq,
                    icmp4_ec_raw_data=message,
                )

            if local_ip_address.version == 6:
                stack.packet_handler.phtx_icmp6(
                    ip6_src=local_ip_address,
                    ip6_dst=remote_ip_address,
                    icmp6_type=128,
                    icmp6_code=0,
                    icmp6_ec_id=flow_id,
                    icmp6_ec_seq=message_seq,
                    icmp6_ec_raw_data=message,
                )

            print(f"Client ICMP Echo: Sent ICMP Echo ({flow_id}/{message_seq}) to {remote_ip_address} - {message}")
            time.sleep(1)
            message_seq += 1
