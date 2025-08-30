#!/usr/bin/env python3

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
This module contains the ARP packet assembler class.

net_proto/protocols/arp/arp__assembler.py

ver 3.0.4
"""


from net_addr import Ip4Address, MacAddress
from net_proto.lib.proto_assembler import ProtoAssembler
from net_proto.lib.tracker import Tracker
from net_proto.protocols.arp.arp__base import Arp
from net_proto.protocols.arp.arp__enums import ArpOperation
from net_proto.protocols.arp.arp__header import ArpHeader


class ArpAssembler(Arp, ProtoAssembler):
    """
    The ARP packet assembler.
    """

    def __init__(
        self,
        *,
        arp__oper: ArpOperation = ArpOperation.REQUEST,
        arp__sha: MacAddress = MacAddress(),
        arp__spa: Ip4Address = Ip4Address(),
        arp__tha: MacAddress = MacAddress(),
        arp__tpa: Ip4Address = Ip4Address(),
        echo_tracker: Tracker | None = None,
    ) -> None:
        """
        Initialize the ARP packet assembler.
        """

        self._tracker = Tracker(prefix="TX", echo_tracker=echo_tracker)

        self._header = ArpHeader(
            oper=arp__oper,
            sha=arp__sha,
            spa=arp__spa,
            tha=arp__tha,
            tpa=arp__tpa,
        )
