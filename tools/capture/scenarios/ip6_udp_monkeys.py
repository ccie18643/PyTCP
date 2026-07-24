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

ver 3.0.9
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
        harness.start_stack(ip4="off", ip6="static")
        harness.wait_for(f"Successfully claimed IPv6 address {cfg.ip6_addr}", cfg.claim_timeout)
        harness.start_service(
            "examples.udp_echo_server__async",
            "--host",
            cfg.ip6_addr,
            "--port",
            str(cfg.port),
        )
        harness.wait_for(f"async UDP echo server on {cfg.ip6_addr}:{cfg.port}", cfg.bind_timeout)
        time.sleep(2)
        harness.drive_monkeys(cfg.ip6_addr, ipv6=True, udp=True, payload=payload, graceful=True)
        time.sleep(2)
        harness.stop_all()
        harness.print_client_output("client output (echoed monkeys)")
        harness.log_highlights(SERVICE_LOG_RE, 20)
        harness.wire(f"icmpv6 or ipv6.addr == {cfg.ip6_addr}")
