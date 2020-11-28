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
# tcp_metadata.py - module contains storage class for incoming TCP packet's metadata
#


class TcpMetadata:
    """ Store TCP metadata """

    def __init__(
        self,
        local_ip_address,
        local_port,
        remote_ip_address,
        remote_port,
        flag_syn,
        flag_ack,
        flag_fin,
        flag_rst,
        seq,
        ack,
        win,
        wscale,
        mss,
        raw_data,
        tracker,
    ):
        self.local_ip_address = local_ip_address
        self.local_port = local_port
        self.remote_ip_address = remote_ip_address
        self.remote_port = remote_port
        self.flag_syn = flag_syn
        self.flag_ack = flag_ack
        self.flag_fin = flag_fin
        self.flag_rst = flag_rst
        self.seq = seq
        self.ack = ack
        self.win = win
        self.wscale = wscale
        self.mss = mss
        self.raw_data = raw_data
        self.tracker = tracker

    @property
    def tcp_session_id(self):
        """ Session ID """

        return f"TCP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}"

    @property
    def tcp_session_listening_patterns(self):
        """ Session ID patterns that match listening socket """

        if self.remote_ip_address.version == 6:
            return [
                f"TCP/{self.local_ip_address}/{self.local_port}/*/*",
                f"TCP/::/{self.local_port}/*/*",
                f"TCP/*/{self.local_port}/*/*",
            ]

        if self.remote_ip_address.version == 4:
            return [
                f"TCP/{self.local_ip_address}/{self.local_port}/*/*",
                f"TCP/0.0.0.0/{self.local_port}/*/*",
                f"TCP/*/{self.local_port}/*/*",
            ]
