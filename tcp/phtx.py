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
# tcp/phtx.py - packet handler for outbound TCP packets
#


import config
import tcp.fpa
from misc.ipv4_address import IPv4Address
from misc.ipv6_address import IPv6Address

PACKET_LOSS = False


def _phtx_tcp(
    self,
    ip_src,
    ip_dst,
    tcp_sport,
    tcp_dport,
    tcp_seq=0,
    tcp_ack=0,
    tcp_flag_ns=False,
    tcp_flag_crw=False,
    tcp_flag_ece=False,
    tcp_flag_urg=False,
    tcp_flag_ack=False,
    tcp_flag_psh=False,
    tcp_flag_rst=False,
    tcp_flag_syn=False,
    tcp_flag_fin=False,
    tcp_mss=None,
    tcp_win=0,
    tcp_urp=0,
    tcp_data=b"",
    echo_tracker=None,
):
    """ Handle outbound TCP packets """

    assert type(ip_src) in {IPv4Address, IPv6Address}
    assert type(ip_dst) in {IPv4Address, IPv6Address}
    assert 0 < tcp_sport < 65536
    assert 0 < tcp_dport < 65536

    # Check if IPv4 protocol support is enabled, if not then silently drop the IPv4 packet
    if not config.ip4_support and ip_dst.version == 4:
        return

    # Check if IPv6 protocol support is enabled, if not then silently drop the IPv6 packet
    if not config.ip6_support and ip_dst.version == 6:
        return

    tcp_options = []

    if tcp_mss:
        tcp_options.append(tcp.fpa.OptMss(tcp_mss))
        tcp_options.append(tcp.fpa.OptNop())
        tcp_options.append(tcp.fpa.OptWscale(0))

    tcp_packet_tx = tcp.fpa.Assembler(
        sport=tcp_sport,
        dport=tcp_dport,
        seq=tcp_seq,
        ack=tcp_ack,
        flag_ns=tcp_flag_ns,
        flag_crw=tcp_flag_crw,
        flag_ece=tcp_flag_ece,
        flag_urg=tcp_flag_urg,
        flag_ack=tcp_flag_ack,
        flag_psh=tcp_flag_psh,
        flag_rst=tcp_flag_rst,
        flag_syn=tcp_flag_syn,
        flag_fin=tcp_flag_fin,
        win=tcp_win,
        urp=tcp_urp,
        options=tcp_options,
        data=tcp_data,
        echo_tracker=echo_tracker,
    )

    if __debug__:
        self._logger.opt(ansi=True).info(f"<magenta>{tcp_packet_tx.tracker}</magenta> - {tcp_packet_tx}")

    # Check if packet should be dropped due to random packet loss enabled (for TCP retansmission testing)
    if PACKET_LOSS:
        from random import randint

        if randint(0, 99) == 7:
            if __debug__:
                self._logger.critical("SIMULATED LOST TX DATA PACKET")
            return

    if ip_src.version == 6 and ip_dst.version == 6:
        self._phtx_ip6(ip6_src=ip_src, ip6_dst=ip_dst, carried_packet=tcp_packet_tx)

    if ip_src.version == 4 and ip_dst.version == 4:
        self._phtx_ip4(ip4_src=ip_src, ip4_dst=ip_dst, carried_packet=tcp_packet_tx)
