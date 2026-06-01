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
This module contains the 'ip4-tcp-monkeys' scenario: the ASCII
monkeys echoed over IPv4 TCP with a graceful service-side close.

tools/capture/scenarios/ip4_tcp_monkeys.py

ver 3.0.8
"""

import time
from typing import Any

import click

from tools.capture.lib import SERVICE_LOG_RE, Harness, common_options, make_config


@click.command(name="ip4-tcp-monkeys", help="TCP echo over IPv4 (ASCII monkeys); graceful close by default.")
@common_options
@click.option(
    "--payload",
    type=click.Choice(["malpi", "malpa", "malpka"]),
    default="malpi",
    show_default=True,
    help="Which ASCII-art monkey the service echoes.",
)
@click.option(
    "--graceful/--no-graceful",
    default=True,
    show_default=True,
    help="Graceful service FIN (separate quit) vs. the idle-timeout RST variant.",
)
def command(*, payload: str, graceful: bool, **kwargs: Any) -> None:
    """
    Capture the IPv4 TCP monkeys echo and connection teardown.
    """

    cfg = make_config(**kwargs)
    with Harness(cfg) as harness:
        harness.start_capture(f"arp or host {cfg.ip4_addr}")
        harness.start_example(
            "examples.service__tcp_echo",
            "--local-port",
            str(cfg.port),
            "--stack-interface",
            cfg.iface,
            "--stack-ip4-address",
            cfg.ip4,
            "--stack-ip4-gateway",
            cfg.gw4,
            "--stack-no-ip6",
        )
        harness.wait_for(f"Socket created, bound to {cfg.ip4_addr}, port {cfg.port}", cfg.bind_timeout)
        harness.wait_for("Socket set to listening mode", 10)
        time.sleep(1)
        harness.drive_monkeys(cfg.ip4_addr, ipv6=False, udp=False, payload=payload, graceful=graceful)
        time.sleep(2)
        harness.stop_example()
        harness.print_client_output("client output (banner + echoed monkeys)")
        harness.log_highlights(SERVICE_LOG_RE, 20)
        harness.wire(
            "-Y",
            f"arp || ip.addr=={cfg.ip4_addr}",
            "-T",
            "fields",
            "-e",
            "frame.time_relative",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "arp.src.proto_ipv4",
            "-e",
            "arp.dst.proto_ipv4",
            "-e",
            "ip.id",
            "-e",
            "ip.flags.mf",
            "-e",
            "ip.frag_offset",
            "-e",
            "tcp.flags.str",
            "-e",
            "_ws.col.Info",
        )
