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
This module contains the 'ip4-icmp-frag-rx' scenario: the host
sends an oversized ping; the stack reassembles the inbound IPv4
fragments and replies (itself fragmenting the reply).

tools/capture/scenarios/ip4_icmp_frag_rx.py

ver 3.0.8
"""

import time
from typing import Any

import click

from tools.capture.lib import Harness, common_options, make_config


@click.command(name="ip4-icmp-frag-rx", help="Oversized ping: inbound IPv4 reassembly + fragmented reply.")
@common_options
@click.option("--count", type=int, default=2, show_default=True, help="Echo Requests to send.")
@click.option("--size", type=int, default=4000, show_default=True, help="ICMP payload size (bytes).")
def command(*, count: int, size: int, **kwargs: Any) -> None:
    """
    Capture inbound IPv4 fragment reassembly and reply fragmenting.
    """

    cfg = make_config(**kwargs)
    with Harness(cfg) as harness:
        # Capture by host, not BPF 'icmp': a transport/proto BPF
        # filter only matches the FIRST IPv4 fragment, so the
        # later fragments of a fragmented Echo would be invisible
        # and inbound reassembly could not be shown.
        harness.start_capture(f"arp or host {cfg.ip4_addr}")
        harness.start_example(
            "examples.stack",
            "--stack-interface",
            cfg.iface,
            "--stack-ip4-address",
            cfg.ip4,
            "--stack-ip4-gateway",
            cfg.gw4,
            "--stack-no-ip6",
        )
        harness.wait_for(f"Successfully claimed IPv4 address {cfg.ip4_addr}", cfg.claim_timeout)
        time.sleep(1)
        harness.ping(cfg.ip4_addr, ipv6=False, count=count, size=size)
        time.sleep(1)
        harness.stop_example()
        harness.print_client_output(f"host ping -s {size} (-> {cfg.ip4_addr})")
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
            "_ws.col.Info",
        )
