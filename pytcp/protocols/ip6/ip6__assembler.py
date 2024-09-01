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
This module contains the IPv6 packet assembler.

pytcp/protocols/ip6/ip6__assembler.py

ver 3.0.2
"""


from __future__ import annotations

from typing import TYPE_CHECKING

from pytcp import config
from pytcp.lib.ip6_address import Ip6Address
from pytcp.lib.proto_assembler import ProtoAssembler
from pytcp.protocols.ip6.ip6__base import Ip6
from pytcp.protocols.ip6.ip6__header import Ip6Header, Ip6Next
from pytcp.protocols.raw.raw__assembler import RawAssembler

if TYPE_CHECKING:
    from pytcp.lib.tracker import Tracker

    from .ip6__base import Ip6Payload


class Ip6Assembler(Ip6, ProtoAssembler):
    """
    The IPv6 packet assembler.
    """

    _payload: Ip6Payload

    def __init__(
        self,
        *,
        ip6__src: Ip6Address = Ip6Address(),
        ip6__dst: Ip6Address = Ip6Address(),
        ip6__hop: int = config.IP6__DEFAULT_HOP_LIMIT,
        ip6__dscp: int = 0,
        ip6__ecn: int = 0,
        ip6__flow: int = 0,
        ip6__payload: Ip6Payload = RawAssembler(),
    ) -> None:
        """
        Initialize the IPv6 packet assembler.
        """

        self._tracker: Tracker = ip6__payload.tracker

        self._payload = ip6__payload

        self._header = Ip6Header(
            dscp=ip6__dscp,
            ecn=ip6__ecn,
            flow=ip6__flow,
            dlen=len(self._payload),
            next=Ip6Next.from_proto(self._payload),
            hop=ip6__hop,
            src=ip6__src,
            dst=ip6__dst,
        )

    @property
    def header(self) -> Ip6Header:
        """
        Get the IPv6 packet 'header' attribute.
        """

        return self._header

    @property
    def payload(self) -> Ip6Payload:
        """
        Get the IPv6 packet 'payload' attribute.
        """

        return self._payload
