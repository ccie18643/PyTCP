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
# phrx_icmpv4.py - packet handler for inbound ICMPv4 packets
#


import ps_icmpv4


def phrx_icmpv4(self, ipv4_packet_rx, icmpv4_packet_rx):
    """ Handle inbound ICMPv4 packets """

    self.logger.opt(ansi=True).info(f"<green>{icmpv4_packet_rx.tracker}</green> - {icmpv4_packet_rx}")

    # Validate ICMPv4 packet checksum
    if not icmpv4_packet_rx.validate_cksum():
        self.logger.debug(f"{icmpv4_packet_rx.tracker} - ICMPv4 packet has invalid checksum, droping")
        return

    # Respond to ICMPv4 Echo Request packet
    if icmpv4_packet_rx.icmpv4_type == ps_icmpv4.ICMPV4_ECHOREQUEST and icmpv4_packet_rx.icmpv4_code == 0:
        self.logger.debug(f"Received ICMPv4 Echo Request packet from {ipv4_packet_rx.ipv4_src}, sending reply")

        self.phtx_icmpv4(
            ipv4_src=ipv4_packet_rx.ipv4_dst,
            ipv4_dst=ipv4_packet_rx.ipv4_src,
            icmpv4_type=ps_icmpv4.ICMPV4_ECHOREPLY,
            icmpv4_ec_id=icmpv4_packet_rx.icmpv4_ec_id,
            icmpv4_ec_seq=icmpv4_packet_rx.icmpv4_ec_seq,
            icmpv4_ec_raw_data=icmpv4_packet_rx.icmpv4_ec_raw_data,
            echo_tracker=icmpv4_packet_rx.tracker,
        )
        return
