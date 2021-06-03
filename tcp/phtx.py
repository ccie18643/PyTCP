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
# tcp/phtx.py - packet handler for outbound TCP packets
#


from typing import Optional, Union

import config
import tcp.fpa
from misc.ipv4_address import IPv4Address
from misc.ipv6_address import IPv6Address
from misc.tracker import Tracker

PACKET_LOSS = False


def _phtx_tcp(
    self,
    ip_src: Union[IPv6Address, IPv4Address],
    ip_dst: Union[IPv6Address, IPv4Address],
    tcp_sport: int,
    tcp_dport: int,
    tcp_seq: int = 0,
    tcp_ack: int = 0,
    tcp_flag_ns: bool = False,
    tcp_flag_crw: bool = False,
    tcp_flag_ece: bool = False,
    tcp_flag_urg: bool = False,
    tcp_flag_ack: bool = False,
    tcp_flag_psh: bool = False,
    tcp_flag_rst: bool = False,
    tcp_flag_syn: bool = False,
    tcp_flag_fin: bool = False,
    tcp_mss: Optional[int] = None,
    tcp_win: int = 0,
    tcp_urp: int = 0,
    tcp_data: bytes = b"",
    echo_tracker: Optional[Tracker] = None,
) -> None:
    """Handle outbound TCP packets"""

    assert 0 < tcp_sport < 65536
    assert 0 < tcp_dport < 65536

    # Check if IPv4 protocol support is enabled, if not then silently drop the IPv4 packet
    if not config.ip4_support and ip_dst.version == 4:
        return

    # Check if IPv6 protocol support is enabled, if not then silently drop the IPv6 packet
    if not config.ip6_support and ip_dst.version == 6:
        return

    tcp_options: list[Union[tcp.fpa.OptMss, tcp.fpa.OptNop, tcp.fpa.OptWscale]] = []

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
