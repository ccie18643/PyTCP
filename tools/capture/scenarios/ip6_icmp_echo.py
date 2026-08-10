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
This module contains the 'ip6-icmp-echo' scenario: a host pings
the stack over IPv6 (ICMPv6 ND resolution + Echo).

tools/capture/scenarios/ip6_icmp_echo.py

ver 3.0.10
"""

import time
from typing import Any

import click
from tools.capture.lib import Harness, common_options, make_config


@click.command(name="ip6-icmp-echo", help="Host pings the stack over IPv6 (ND resolution + ICMPv6 Echo).")
@common_options
@click.option("--count", type=int, default=3, show_default=True, help="Echo Requests to send.")
def command(*, count: int, **kwargs: Any) -> None:
    """
    Capture ICMPv6 ND resolution followed by an Echo exchange.
    """

    cfg = make_config(**kwargs)
    with Harness(cfg) as harness:
        harness.add_host_v6()
        harness.start_stack(ip4="off", ip6="static")
        harness.wait_for(f"Successfully claimed IPv6 address {cfg.ip6_addr}", cfg.claim_timeout)
        time.sleep(1)
        harness.ping(cfg.ip6_addr, ipv6=True, count=count)
        time.sleep(1)
        harness.stop_all()
        harness.print_client_output(f"host ping6 ({cfg.peer6} -> {cfg.ip6_addr})")
        # Neighbor Discovery plus the Echo exchange with the host peer.
        harness.wire(f"icmpv6 or ipv6.addr == {cfg.ip6_addr}")
