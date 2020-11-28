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


#
# udp_metadata.py - module contains storage class for incoming UDP packet's metadata
#


class UdpMetadata:
    """ Store UDP metadata """

    def __init__(self, local_ip_address, local_port, remote_ip_address, remote_port, raw_data, tracker):
        self.local_ip_address = local_ip_address
        self.local_port = local_port
        self.remote_ip_address = remote_ip_address
        self.remote_port = remote_port
        self.raw_data = raw_data
        self.tracker = tracker

    @property
    def udp_session_id(self):
        """ Session ID """

        return f"UDP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}"

    @property
    def socket_id_patterns(self):
        """ Socket ID patterns that match this packet """

        if self.remote_ip_address.version == 6:
            return [
                f"UDP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}",
                f"UDP/{self.local_ip_address}/{self.local_port}/*/*",
                f"UDP/::/{self.local_port}/*/{self.remote_port}",
                f"UDP/*/{self.local_port}/*/{self.remote_port}",
                f"UDP/::/{self.local_port}/*/*",
                f"UDP/*/{self.local_port}/*/*",
            ]

        if self.remote_ip_address.version == 4:
            return [
                f"UDP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}",
                f"UDP/{self.local_ip_address}/{self.local_port}/*/*",
                f"UDP/0.0.0.0/{self.local_port}/*/{self.remote_port}",
                f"UDP/*/{self.local_port}/*/{self.remote_port}",
                f"UDP/0.0.0.0/{self.local_port}/*/*",
                f"UDP/*/{self.local_port}/*/*",
            ]
