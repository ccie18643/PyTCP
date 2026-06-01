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

ver 3.0.8
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
        harness.start_capture("ip6 or arp")
        harness.start_example(
            "examples.stack",
            "--stack-interface",
            cfg.iface,
            "--stack-ip6-address",
            cfg.ip6,
            "--stack-no-ip4",
        )
        harness.wait_for(f"Successfully claimed IPv6 address {cfg.ip6_addr}", cfg.claim_timeout)
        time.sleep(1)
        harness.ping(cfg.ip6_addr, ipv6=True, count=count)
        time.sleep(1)
        harness.stop_example()
        harness.print_client_output(f"host ping6 ({cfg.peer6} -> {cfg.ip6_addr})")
        harness.wire(
            "-Y",
            f"ipv6.addr=={cfg.ip6_addr} || icmpv6",
            "-T",
            "fields",
            "-e",
            "frame.time_relative",
            "-e",
            "_ws.col.Protocol",
            "-e",
            "ipv6.src",
            "-e",
            "ipv6.dst",
            "-e",
            "_ws.col.Info",
        )
