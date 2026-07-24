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
This module contains the interface dataclass for the ICMPv4 / ICMPv6
RX path -> TCP FSM dispatch communication. Naming follows the
existing 'UdpMetadata' / 'RawMetadata' convention
('pytcp/runtime/socket/udp__metadata.py', 'pytcp/runtime/socket/raw__metadata.py'):
the dataclass that flows from the packet handler to the upper-layer
consumer is suffixed 'Metadata'. Here the consumer is the TCP FSM,
so the file lives next to the FSM under 'pytcp/protocols/tcp/'.

pytcp/protocols/tcp/tcp__icmp_metadata.py

ver 3.0.8
"""

from dataclasses import dataclass
from enum import IntEnum


class IcmpCategory(IntEnum):
    """
    The ICMP-event category recognized by the TCP FSM dispatch.
    Maps 1-to-1 onto the four legacy 'TcpSession.on_*' hooks.
    """

    DEST_UNREACHABLE = 1
    TIME_EXCEEDED = 2
    PARAM_PROBLEM = 3
    PMTU = 4


@dataclass(frozen=True, kw_only=True, slots=True)
class IcmpMetadata:
    """
    The TCP FSM metadata taken from the received ICMP error.
    """

    category: IcmpCategory
    icmp_type: int
    icmp_code: int
    ip_version: int
    pointer: int | None = None
    next_hop_mtu: int | None = None
