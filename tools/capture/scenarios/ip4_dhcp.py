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
This module contains the 'ip4-dhcp' scenario: the DHCPv4 client
lease (DISCOVER / OFFER / REQUEST / ACK). Requires a reachable
DHCPv4 server on the bridge.

tools/capture/scenarios/ip4_dhcp.py

ver 3.0.8
"""

import time
from typing import Any

import click
from tools.capture.lib import Harness, common_options, make_config


@click.command(name="ip4-dhcp", help="DHCPv4 client lease (needs a DHCPv4 server on the bridge).")
@common_options
def command(**kwargs: Any) -> None:
    """
    Capture the DHCPv4 client lease acquisition.
    """

    cfg = make_config(**kwargs)
    with Harness(cfg) as harness:
        # No static IPv4 ⇒ the daemon runs the DHCPv4 client (ip4_dhcp
        # defaults on when no static IPv4 is configured).
        harness.start_stack(ip4="auto", ip6="off")
        # The DHCPv4 client logs 'Lease acquired' on BOUND; the
        # ARP-ACD path additionally logs 'Successfully claimed
        # IPv4 address' once the leased host is announced. Accept
        # either as the readiness signal.
        harness.wait_for(
            r"Lease acquired|Successfully claimed IPv4 address",
            cfg.claim_timeout,
        )
        time.sleep(1)
        harness.stop_all()
        harness.log_highlights(
            r"Found cached lease|DHCP|Initial desync|Successfully claimed IPv4|Sent out ARP Announcement",
            20,
        )
        # DHCPv4 is UDP 67/68; keep those plus ARP (the post-lease ACD).
        harness.wire("bootp or dhcp or arp")
