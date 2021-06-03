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
# ip6_ext_frag/phtx.py - packet handler for outbound IPv6 fragment extension header
#


import config
import ip6.fpa
import ip6.ps
import ip6_ext_frag.fpa
import ip6_ext_frag.ps


def _phtx_ip6_ext_frag(self, ip6_packet_tx: ip6.fpa.Assembler) -> None:
    """Handle outbound IPv6 fagment extension header"""

    # Check if IPv6 protocol support is enabled, if not then silently drop the packet
    if not config.ip6_support:
        return

    data = bytearray(ip6_packet_tx.dlen)
    ip6_packet_tx._carried_packet.assemble(data, 0, ip6_packet_tx.pshdr_sum)
    data_mtu = (config.mtu - ip6.ps.HEADER_LEN - ip6_ext_frag.ps.HEADER_LEN) & 0b1111111111111000
    data_frags = [data[_ : data_mtu + _] for _ in range(0, len(data), data_mtu)]
    offset = 0
    self.ip6_id += 1
    for data_frag in data_frags:
        ip6_ext_frag_tx = ip6_ext_frag.fpa.Assembler(
            next=ip6_packet_tx.next, offset=offset, flag_mf=data_frag is not data_frags[-1], id=self.ip6_id, data=data_frag
        )
        if __debug__:
            self._logger.debug(f"{ip6_ext_frag_tx.tracker} - {ip6_ext_frag_tx}")
        self._phtx_ip6(ip6_src=ip6_packet_tx.src, ip6_dst=ip6_packet_tx.dst, carried_packet=ip6_ext_frag_tx)
        offset += len(data_frag)
