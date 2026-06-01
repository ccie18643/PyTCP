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
This module contains the 'ip6-udp-monkeys' scenario: the ASCII
monkeys echoed over IPv6 UDP.

tools/capture/scenarios/ip6_udp_monkeys.py

ver 3.0.8
"""

import time
from typing import Any

import click

from tools.capture.lib import SERVICE_LOG_RE, Harness, common_options, make_config


@click.command(name="ip6-udp-monkeys", help="UDP echo over IPv6 (ASCII monkeys).")
@common_options
@click.option(
    "--payload",
    type=click.Choice(["malpi", "malpa", "malpka"]),
    default="malpi",
    show_default=True,
    help="Which ASCII-art monkey the service echoes.",
)
def command(*, payload: str, **kwargs: Any) -> None:
    """
    Capture the IPv6 UDP monkeys echo exchange.
    """

    cfg = make_config(**kwargs)
    with Harness(cfg) as harness:
        harness.add_host_v6()
        harness.start_capture("ip6 or arp")
        harness.start_example(
            "examples.service__udp_echo",
            "--local-port",
            str(cfg.port),
            "--stack-interface",
            cfg.iface,
            "--stack-ip6-address",
            cfg.ip6,
            "--stack-no-ip4",
        )
        harness.wait_for(f"Socket created, bound to {cfg.ip6_addr}, port {cfg.port}", cfg.bind_timeout)
        time.sleep(1)
        harness.drive_monkeys(cfg.ip6_addr, ipv6=True, udp=True, payload=payload, graceful=True)
        time.sleep(2)
        harness.stop_example()
        harness.print_client_output("client output (echoed monkeys)")
        harness.log_highlights(SERVICE_LOG_RE, 20)
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
