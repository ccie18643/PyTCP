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
This module contains the 'arp-acd' scenario: RFC 5227 Address
Conflict Detection — three ARP Probes then two Announcements.

tools/capture/scenarios/arp_acd.py

ver 3.0.8
"""

import time
from typing import Any

import click
from tools.capture.lib import Harness, common_options, make_config


@click.command(name="arp-acd", help="RFC 5227 ARP Probe / Announcement (Address Conflict Detection).")
@common_options
def command(**kwargs: Any) -> None:
    """
    Capture the RFC 5227 ARP Probe / Announcement sequence.
    """

    cfg = make_config(**kwargs)
    with Harness(cfg) as harness:
        harness.start_stack(ip4="static", ip6="off")
        harness.wait_for(f"Successfully claimed IPv4 address {cfg.ip4_addr}", cfg.claim_timeout)
        time.sleep(1)
        harness.stop_all()
        harness.log_highlights(
            r"Sent out ARP Probe|Sent out ARP Announcement|Successfully claimed IPv4",
            10,
        )
        # The stack's own ACD frames: outbound ARP Probes + Announcement.
        harness.wire("arp")
