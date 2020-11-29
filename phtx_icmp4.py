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
# phtx_icmp4.py - packet handler for outbound ICMPv4 packets
#


import ps_icmp4
import stack


def phtx_icmp4(
    self,
    ip4_src,
    ip4_dst,
    icmp4_type,
    icmp4_code=0,
    icmp4_ec_id=None,
    icmp4_ec_seq=None,
    icmp4_ec_raw_data=None,
    icmp4_un_raw_data=None,
    echo_tracker=None,
):
    """ Handle outbound ICMPv4 packets """

    # Check if IPv4 protocol support is enabled, if not then silently drop the packet
    if not stack.ip4_support:
        return

    icmp4_packet_tx = ps_icmp4.Icmp4Packet(
        icmp4_type=icmp4_type,
        icmp4_code=icmp4_code,
        icmp4_ec_id=icmp4_ec_id,
        icmp4_ec_seq=icmp4_ec_seq,
        icmp4_ec_raw_data=icmp4_ec_raw_data,
        icmp4_un_raw_data=icmp4_un_raw_data,
        echo_tracker=echo_tracker,
    )

    self.logger.opt(ansi=True).info(f"<magenta>{icmp4_packet_tx.tracker}</magenta> - {icmp4_packet_tx}")
    self.phtx_ip4(ip4_src=ip4_src, ip4_dst=ip4_dst, child_packet=icmp4_packet_tx)
