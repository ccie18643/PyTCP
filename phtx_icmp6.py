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
# phtx_icmp6.py - packet handler for outbound ICMPv6 packets
#


import config
import fpa_icmp6


def _phtx_icmp6(
    self,
    ip6_src,
    ip6_dst,
    icmp6_type,
    icmp6_code=0,
    ip6_hop=64,
    icmp6_un_data=None,
    icmp6_ec_id=None,
    icmp6_ec_seq=None,
    icmp6_ec_data=None,
    icmp6_ns_target_address=None,
    icmp6_na_flag_r=False,
    icmp6_na_flag_s=False,
    icmp6_na_flag_o=False,
    icmp6_na_target_address=None,
    icmp6_nd_options=None,
    icmp6_mlr2_multicast_address_record=None,
    echo_tracker=None,
):
    """Handle outbound ICMPv6 packets"""

    # Check if IPv6 protocol support is enabled, if not then silently drop the packet
    if not config.ip6_support:
        return

    icmp6_packet_tx = fpa_icmp6.Icmp6Packet(
        type=icmp6_type,
        code=icmp6_code,
        un_data=icmp6_un_data,
        ec_id=icmp6_ec_id,
        ec_seq=icmp6_ec_seq,
        ec_data=icmp6_ec_data,
        ns_target_address=icmp6_ns_target_address,
        na_flag_r=icmp6_na_flag_r,
        na_flag_s=icmp6_na_flag_s,
        na_flag_o=icmp6_na_flag_o,
        na_target_address=icmp6_na_target_address,
        nd_options=[] if icmp6_nd_options is None else icmp6_nd_options,
        mlr2_multicast_address_record=[] if icmp6_mlr2_multicast_address_record is None else icmp6_mlr2_multicast_address_record,
        echo_tracker=echo_tracker,
    )

    if __debug__:
        self._logger.opt(ansi=True).info(f"<magenta>{icmp6_packet_tx.tracker}</magenta> - {icmp6_packet_tx}")
    self._phtx_ip6(ip6_src=ip6_src, ip6_dst=ip6_dst, ip6_hop=ip6_hop, child_packet=icmp6_packet_tx)
