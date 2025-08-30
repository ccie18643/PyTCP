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
This module contains the Ethernet 802.3 packet assembler class.

net_proto/protocols/ethernet_802_3/ethernet_802_3__assembler.py

ver 3.0.4
"""


from net_addr import MacAddress
from net_proto.lib.proto_assembler import ProtoAssembler
from net_proto.protocols.ethernet_802_3.ethernet_802_3__base import (
    Ethernet8023,
    Ethernet8023Payload,
)
from net_proto.protocols.ethernet_802_3.ethernet_802_3__header import (
    Ethernet8023Header,
)
from net_proto.protocols.raw.raw__assembler import RawAssembler


class Ethernet8023Assembler(Ethernet8023[Ethernet8023Payload], ProtoAssembler):
    """
    The Ethernet 802.3 packet assembler.
    """

    _payload: Ethernet8023Payload

    def __init__(
        self,
        *,
        ethernet_802_3__src: MacAddress = MacAddress(),
        ethernet_802_3__dst: MacAddress = MacAddress(),
        ethernet_802_3__payload: Ethernet8023Payload = RawAssembler(),
    ) -> None:
        """
        Initialize the Ethernet 802.3 packet assembler.
        """

        self._tracker = ethernet_802_3__payload.tracker

        self._payload = ethernet_802_3__payload

        self._header = Ethernet8023Header(
            dst=ethernet_802_3__dst,
            src=ethernet_802_3__src,
            dlen=len(self._payload),
        )

    @property
    def payload(self) -> Ethernet8023Payload:
        """
        Get the Ethernet 802.3 packet '_payload' attribute.
        """

        return self._payload
