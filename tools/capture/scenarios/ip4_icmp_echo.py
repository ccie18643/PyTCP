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
This module contains the 'ip4-icmp-echo' scenario: a host pings
the stack over IPv4 (ARP resolution + ICMP Echo).

tools/capture/scenarios/ip4_icmp_echo.py

ver 3.0.8
"""

import time
from typing import Any

import click
from tools.capture.lib import Harness, common_options, make_config


@click.command(name="ip4-icmp-echo", help="Host pings the stack over IPv4 (ARP resolution + ICMP Echo).")
@common_options
@click.option("--count", type=int, default=3, show_default=True, help="Echo Requests to send.")
def command(*, count: int, **kwargs: Any) -> None:
    """
    Capture ARP resolution followed by an ICMP Echo exchange.
    """

    cfg = make_config(**kwargs)
    with Harness(cfg) as harness:
        peer = harness.detect_peer4()
        harness.start_stack(ip4="static", ip6="off")
        harness.wait_for(f"Successfully claimed IPv4 address {cfg.ip4_addr}", cfg.claim_timeout)
        time.sleep(1)
        harness.ping(cfg.ip4_addr, ipv6=False, count=count)
        time.sleep(1)
        harness.stop_all()
        harness.print_client_output(f"host ping ({peer} -> {cfg.ip4_addr})")
        harness.wire(r" (ARP,|IP .*ICMPv4)")
