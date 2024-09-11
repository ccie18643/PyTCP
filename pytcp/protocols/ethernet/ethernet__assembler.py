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
This module contains the Ethernet II packet assembler class.

pytcp/protocols/ethernet/ethernet__assembler.py

ver 3.0.2
"""


from __future__ import annotations

from typing import TYPE_CHECKING

from net_addr import MacAddress
from pytcp.lib.proto_assembler import ProtoAssembler
from pytcp.protocols.ethernet.ethernet__base import Ethernet
from pytcp.protocols.ethernet.ethernet__header import (
    EthernetHeader,
    EthernetType,
)
from pytcp.protocols.raw.raw__assembler import RawAssembler

if TYPE_CHECKING:
    from pytcp.protocols.ethernet.ethernet__base import EthernetPayload


class EthernetAssembler(Ethernet, ProtoAssembler):
    """
    The Ethernet packet assembler.
    """

    _payload: EthernetPayload

    def __init__(
        self,
        *,
        ethernet__src: MacAddress = MacAddress(),
        ethernet__dst: MacAddress = MacAddress(),
        ethernet__payload: EthernetPayload = RawAssembler(),
    ) -> None:
        """
        Initialize the Ethernet packet assembler.
        """

        self._tracker = ethernet__payload.tracker

        self._payload = ethernet__payload

        self._header = EthernetHeader(
            dst=ethernet__dst,
            src=ethernet__src,
            type=EthernetType.from_proto(self._payload),
        )

    @property
    def payload(self) -> EthernetPayload:
        """
        Get the Ethernet packet '_payload' attribute.
        """

        return self._payload
