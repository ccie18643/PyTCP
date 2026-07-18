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
This module contains the 'boot' scenario: full stack startup —
IPv6 LLA/SLAAC DAD, MLDv2, RS/RA, and RFC 5227 IPv4 ACD.

tools/capture/scenarios/boot.py

ver 3.0.8
"""

import time
from typing import Any

import click
from tools.capture.lib import Harness, common_options, make_config


@click.command(name="boot", help="Full startup: IPv6 LLA/SLAAC DAD, MLDv2, RS/RA, IPv4 ACD.")
@common_options
def command(**kwargs: Any) -> None:
    """
    Capture the stack's full autoconfiguration on startup.
    """

    cfg = make_config(**kwargs)
    with Harness(cfg) as harness:
        harness.start_stack(ip4="static", ip6="auto")
        harness.wait_for(f"Successfully claimed IPv4 address {cfg.ip4_addr}", cfg.claim_timeout)
        time.sleep(2)
        harness.stop_all()
        harness.log_highlights(
            r"ICMPv6 ND DAD - (Starting|No duplicate)|Successfully claimed|"
            r"Sent out ICMPv6 ND Router Solicitation|Sent out ARP Announcement|"
            r"Multicast Listener Report .HBH",
            16,
        )
        # The stack's own boot frames: only the 'Out' direction, so the
        # capture shows what the stack itself emits during startup.
        harness.wire("icmpv6 or igmp or arp")
