################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


"""
This package contains one click command per capture scenario;
COMMANDS is the registry the top-level group adds them from.

tools/capture/scenarios/__init__.py

ver 3.0.9
"""

import click
from tools.capture.scenarios import (
    arp_acd,
    boot,
    ip4_dhcp,
    ip4_icmp_echo,
    ip4_icmp_frag_rx,
    ip4_tcp_monkeys,
    ip4_udp_monkeys,
    ip6_icmp_echo,
    ip6_tcp_monkeys,
    ip6_udp_monkeys,
)

COMMANDS: list[click.Command] = [
    boot.command,
    arp_acd.command,
    ip4_icmp_echo.command,
    ip6_icmp_echo.command,
    ip4_tcp_monkeys.command,
    ip6_tcp_monkeys.command,
    ip4_udp_monkeys.command,
    ip6_udp_monkeys.command,
    ip4_icmp_frag_rx.command,
    ip4_dhcp.command,
]
