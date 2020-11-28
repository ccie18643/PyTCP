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
# phtx_icmpv4.py - packet handler for outbound ICMPv4 packets
#


import ps_icmpv4
import stack


def phtx_icmpv4(
    self,
    ipv4_src,
    ipv4_dst,
    icmpv4_type,
    icmpv4_code=0,
    icmpv4_ec_id=None,
    icmpv4_ec_seq=None,
    icmpv4_ec_raw_data=None,
    icmpv4_un_raw_data=None,
    icmpv4_ipv4_packet_rx=None,
    echo_tracker=None,
):
    """ Handle outbound ICMPv4 packets """

    # Check if IPv4 protocol support is enabled, if not then silently drop the packet
    if not stack.ipv4_support:
        return

    icmpv4_packet_tx = ps_icmpv4.ICMPv4Packet(
        icmpv4_type=icmpv4_type,
        icmpv4_code=icmpv4_code,
        icmpv4_ec_id=icmpv4_ec_id,
        icmpv4_ec_seq=icmpv4_ec_seq,
        icmpv4_ec_raw_data=icmpv4_ec_raw_data,
        icmpv4_un_raw_data=icmpv4_un_raw_data,
        echo_tracker=echo_tracker,
    )

    self.logger.opt(ansi=True).info(f"<magenta>{icmpv4_packet_tx.tracker}</magenta> - {icmpv4_packet_tx}")
    self.phtx_ipv4(ipv4_src=ipv4_src, ipv4_dst=ipv4_dst, child_packet=icmpv4_packet_tx)
