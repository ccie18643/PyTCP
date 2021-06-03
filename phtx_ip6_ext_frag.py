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
# phtx_ip6_ext_frag.py - packet handler for outbound IPv6 fragment extension header
#


import config
import fpa_ip6
import fpa_ip6_ext_frag


def _phtx_ip6_ext_frag(self, ip6_packet_tx):
    """Handle outbound IPv6 fagment extension header"""

    # Check if IPv6 protocol support is enabled, if not then silently drop the packet
    if not config.ip6_support:
        return

    data = bytearray(ip6_packet_tx.dlen)
    ip6_packet_tx._child_packet.assemble_packet(data, 0, ip6_packet_tx.pshdr_sum)
    data_mtu = (config.mtu - fpa_ip6.IP6_HEADER_LEN - fpa_ip6_ext_frag.IP6_EXT_FRAG_LEN) & 0b1111111111111000
    data_frags = [data[_ : data_mtu + _] for _ in range(0, len(data), data_mtu)]
    offset = 0
    self.ip6_id += 1
    for data_frag in data_frags:
        ip6_ext_frag_tx = fpa_ip6_ext_frag.Ip6ExtFrag(
            next=ip6_packet_tx.next, offset=offset, flag_mf=data_frag is not data_frags[-1], id=self.ip6_id, data=data_frag
        )
        if __debug__:
            self._logger.debug(f"{ip6_ext_frag_tx.tracker} - {ip6_ext_frag_tx}")
        self._phtx_ip6(ip6_src=ip6_packet_tx.src, ip6_dst=ip6_packet_tx.dst, child_packet=ip6_ext_frag_tx)
        offset += len(data_frag)
