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
# phtx_icmpv6.py - packet handler for outbound ICMPv6 packets
#


import ps_icmpv6
import stack


def phtx_icmpv6(
    self,
    ipv6_src,
    ipv6_dst,
    icmpv6_type,
    icmpv6_code=0,
    ipv6_hop=64,
    icmpv6_un_raw_data=None,
    icmpv6_ec_id=None,
    icmpv6_ec_seq=None,
    icmpv6_ec_raw_data=None,
    icmpv6_ns_target_address=None,
    icmpv6_na_flag_r=False,
    icmpv6_na_flag_s=False,
    icmpv6_na_flag_o=False,
    icmpv6_na_target_address=None,
    icmpv6_nd_options=[],
    icmpv6_mlr2_multicast_address_record=[],
    icmpv6_ipv6_packet_rx=None,
    echo_tracker=None,
):
    """ Handle outbound ICMPv6 packets """

    # Check if IPv6 protocol support is enabled, if not then silently drop the packet
    if not stack.ipv6_support:
        return

    icmpv6_packet_tx = ps_icmpv6.ICMPv6Packet(
        icmpv6_type=icmpv6_type,
        icmpv6_code=icmpv6_code,
        icmpv6_un_raw_data=icmpv6_un_raw_data,
        icmpv6_ec_id=icmpv6_ec_id,
        icmpv6_ec_seq=icmpv6_ec_seq,
        icmpv6_ec_raw_data=icmpv6_ec_raw_data,
        icmpv6_ns_target_address=icmpv6_ns_target_address,
        icmpv6_na_flag_r=icmpv6_na_flag_r,
        icmpv6_na_flag_s=icmpv6_na_flag_s,
        icmpv6_na_flag_o=icmpv6_na_flag_o,
        icmpv6_na_target_address=icmpv6_na_target_address,
        icmpv6_nd_options=icmpv6_nd_options,
        icmpv6_mlr2_multicast_address_record=icmpv6_mlr2_multicast_address_record,
        echo_tracker=echo_tracker,
    )

    self.logger.opt(ansi=True).info(f"<magenta>{icmpv6_packet_tx.tracker}</magenta> - {icmpv6_packet_tx}")
    self.phtx_ipv6(ipv6_src=ipv6_src, ipv6_dst=ipv6_dst, ipv6_hop=ipv6_hop, child_packet=icmpv6_packet_tx)
